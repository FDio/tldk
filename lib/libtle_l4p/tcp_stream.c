/*
 * Copyright (c) 2016  Intel Corporation.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <string.h>
#include <rte_malloc.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_tcp.h>

#include "tcp_stream.h"
#include "tcp_timer.h"
#include "stream_table.h"
#include "misc.h"
#include "tcp_ofo.h"


static void
unuse_stream(struct tle_tcp_stream *s)
{
	s->s.type = TLE_VNUM;
	rte_atomic32_set(&s->rx.use, INT32_MIN);
	rte_atomic32_set(&s->tx.use, INT32_MIN);
}

static void
fini_stream(struct tle_tcp_stream *s)
{
	if (s != NULL) {
		rte_free(s->rx.q);
		tcp_ofo_free(s->rx.ofo);
		rte_free(s->tx.q);
		rte_free(s->tx.drb.r);
	}
}

static void
tcp_fini_streams(struct tle_ctx *ctx)
{
	uint32_t i;
	struct tcp_streams *ts;

	ts = CTX_TCP_STREAMS(ctx);
	if (ts != NULL) {
		stbl_fini(&ts->st);
		for (i = 0; i != ctx->prm.max_streams; i++)
			fini_stream(&ts->s[i]);

		/* free the timer wheel */
		tle_timer_free(ts->tmr);
		rte_free(ts->tsq);
	}

	rte_free(ts);
	ctx->streams.buf = NULL;
	STAILQ_INIT(&ctx->streams.free);
}

static struct rte_ring *
alloc_ring(uint32_t n, uint32_t flags, int32_t socket)
{
	struct rte_ring *r;
	size_t sz;
	char name[RTE_RING_NAMESIZE];

	n = rte_align32pow2(n);
	sz = sizeof(*r) + n * sizeof(r->ring[0]);

	r = rte_zmalloc_socket(NULL, sz, RTE_CACHE_LINE_SIZE, socket);
	if (r == NULL) {
		TCP_LOG(ERR, "%s: allocation of %zu bytes on socket %d "
			"failed with error code: %d\n",
			__func__, sz, socket, rte_errno);
		return NULL;
	}

	snprintf(name, sizeof(name), "%p@%zu", r, sz);
	rte_ring_init(r, name, n, flags);
	return r;
}

static int
init_stream(struct tle_ctx *ctx, struct tle_tcp_stream *s)
{
	size_t bsz, rsz, sz;
	uint32_t i, k, n, nb;
	struct tle_drb *drb;
	char name[RTE_RING_NAMESIZE];

	/* init RX part. */

	n = RTE_MAX(ctx->prm.max_stream_rbufs, 1U);
	s->rx.q = alloc_ring(n, RING_F_SP_ENQ, ctx->prm.socket_id);
	if (s->rx.q == NULL)
		return -ENOMEM;

	s->rx.ofo = tcp_ofo_alloc(n, ctx->prm.socket_id);
	if (s->rx.ofo == NULL)
		return -ENOMEM;

	/* init TX part. */

	n = RTE_MAX(ctx->prm.max_stream_sbufs, 1U);
	s->tx.q = alloc_ring(n, RING_F_SC_DEQ, ctx->prm.socket_id);
	if (s->tx.q == NULL)
		return -ENOMEM;

	nb = drb_nb_elem(ctx);
	k = calc_stream_drb_num(ctx, nb);
	n = rte_align32pow2(k);

	/* size of the drbs ring */
	rsz = sizeof(*s->tx.drb.r) + n * sizeof(s->tx.drb.r->ring[0]);
	rsz = RTE_ALIGN_CEIL(rsz, RTE_CACHE_LINE_SIZE);

	/* size of the drb. */
	bsz = tle_drb_calc_size(nb);

	/* total stream drbs size. */
	sz = rsz + bsz * k;

	s->tx.drb.r = rte_zmalloc_socket(NULL, sz, RTE_CACHE_LINE_SIZE,
		ctx->prm.socket_id);
	if (s->tx.drb.r == NULL) {
		TCP_LOG(ERR, "%s(%p): allocation of %zu bytes on socket %d "
			"failed with error code: %d\n",
			__func__, s, sz, ctx->prm.socket_id, rte_errno);
		return -ENOMEM;
	}

	snprintf(name, sizeof(name), "%p@%zu", s, sz);
	rte_ring_init(s->tx.drb.r, name, n, 0);

	for (i = 0; i != k; i++) {
		drb = (struct tle_drb *)((uintptr_t)s->tx.drb.r +
			rsz + bsz * i);
		drb->udata = s;
		drb->size = nb;
		rte_ring_enqueue(s->tx.drb.r, drb);
	}

	s->tx.drb.nb_elem = nb;
	s->tx.drb.nb_max = k;

	/* mark stream as avaialble to use. */

	s->s.ctx = ctx;
	unuse_stream(s);
	STAILQ_INSERT_TAIL(&ctx->streams.free, &s->s, link);

	return 0;
}

static void
tcp_free_drbs(struct tle_stream *s, struct tle_drb *drb[], uint32_t nb_drb)
{
	struct tle_tcp_stream *us;

	us = (struct tle_tcp_stream *)s;
	rte_ring_enqueue_burst(us->tx.drb.r, (void **)drb, nb_drb);
}

static struct tle_timer_wheel *
alloc_timers(uint32_t num, int32_t socket)
{
	struct tle_timer_wheel_args twprm;

	twprm.tick_size = TCP_RTO_GRANULARITY;
	twprm.max_timer = num;
	twprm.socket_id = socket;
	return tle_timer_create(&twprm, tcp_get_tms());
}

static int
tcp_init_streams(struct tle_ctx *ctx)
{
	size_t sz;
	uint32_t i;
	int32_t rc;
	struct tcp_streams *ts;

	sz = sizeof(*ts) + sizeof(ts->s[0]) * ctx->prm.max_streams;
	ts = rte_zmalloc_socket(NULL, sz, RTE_CACHE_LINE_SIZE,
		ctx->prm.socket_id);
	if (ts == NULL) {
		TCP_LOG(ERR, "allocation of %zu bytes on socket %d "
			"for %u tcp_streams failed\n",
			sz, ctx->prm.socket_id, ctx->prm.max_streams);
		return -ENOMEM;
        }

	ctx->streams.buf = ts;
	STAILQ_INIT(&ctx->streams.free);

	ts->tmr = alloc_timers(ctx->prm.max_streams, ctx->prm.socket_id);
	if (ts->tmr == NULL) {
		TCP_LOG(ERR, "alloc_timers(ctx=%p) failed with error=%d\n",
			ctx, rte_errno);
		rc = -ENOMEM;
	} else {
		ts->tsq = alloc_ring(ctx->prm.max_streams,
			RING_F_SC_DEQ, ctx->prm.socket_id);
		if (ts->tsq == NULL)
			rc = -ENOMEM;
		else
			rc = stbl_init(&ts->st, ctx->prm.max_streams,
				ctx->prm.socket_id);
	}

	for (i = 0; rc == 0 && i != ctx->prm.max_streams; i++)
		rc = init_stream(ctx, &ts->s[i]);

	if (rc != 0) {
		TCP_LOG(ERR, "initalisation of %u-th stream failed", i);
		tcp_fini_streams(ctx);
	}

	return rc;
}

static void __attribute__((constructor))
tcp_stream_setup(void)
{ 
	static const struct stream_ops tcp_ops = { 
		.init_streams = tcp_init_streams,
		.fini_streams = tcp_fini_streams,
		.free_drbs = tcp_free_drbs,
	};

	tle_stream_ops[TLE_PROTO_TCP] = tcp_ops;
}

/*
 * Helper routine, check that input event and callback are mutually exclusive.
 */
static int
check_cbev(const struct tle_event *ev, const struct tle_stream_cb *cb)
{
	if (ev != NULL && cb->func != NULL)
		return -EINVAL;
	return 0;
}

static int
check_stream_prm(const struct tle_ctx *ctx,
	const struct tle_tcp_stream_param *prm)
{
	if ((prm->addr.local.ss_family != AF_INET &&
			prm->addr.local.ss_family != AF_INET6) ||
			prm->addr.local.ss_family != prm->addr.remote.ss_family)
		return -EINVAL;

	/* callback and event notifications mechanisms are mutually exclusive */
	if (check_cbev(prm->cfg.recv_ev, &prm->cfg.recv_cb) != 0 ||
			check_cbev(prm->cfg.recv_ev, &prm->cfg.recv_cb) != 0 ||
			check_cbev(prm->cfg.err_ev, &prm->cfg.err_cb) != 0)
		return -EINVAL;

	/* check does context support desired address family. */
	if ((prm->addr.local.ss_family == AF_INET &&
			ctx->prm.lookup4 == NULL) ||
			(prm->addr.local.ss_family == AF_INET6 &&
			ctx->prm.lookup6 == NULL))
		return -EINVAL;

	return 0;
}

struct tle_stream *
tle_tcp_stream_open(struct tle_ctx *ctx,
	const struct tle_tcp_stream_param *prm)
{
	struct tle_tcp_stream *s;
	int32_t rc;

	if (ctx == NULL || prm == NULL || check_stream_prm(ctx, prm) != 0) {
		rte_errno = EINVAL;
		return NULL;
	}

	s = (struct tle_tcp_stream *)get_stream(ctx);
	if (s == NULL)	{
		rte_errno = ENFILE;
		return NULL;

	/* some TX still pending for that stream. */
	} else if (TCP_STREAM_TX_PENDING(s)) {
		put_stream(ctx, &s->s, 0);
		rte_errno = EAGAIN;
		return NULL;
	}

	/* setup L4 ports and L3 addresses fields. */
	rc = stream_fill_ctx(ctx, &s->s,
		(const struct sockaddr *)&prm->addr.local,
		(const struct sockaddr *)&prm->addr.remote);

	if (rc != 0) {
		put_stream(ctx, &s->s, 1);
		rte_errno = rc;
		return NULL;
	}

	/* setup stream notification menchanism */
	s->rx.ev = prm->cfg.recv_ev;
	s->rx.cb = prm->cfg.recv_cb;
	s->tx.ev = prm->cfg.send_ev;
	s->tx.cb = prm->cfg.send_cb;
	s->err.ev = prm->cfg.err_ev;
	s->err.cb = prm->cfg.err_cb;

	/* store other params */
	s->tcb.snd.nb_retm = (prm->cfg.nb_retries != 0) ? prm->cfg.nb_retries :
		TLE_TCP_DEFAULT_RETRIES;

	tcp_stream_up(s);
	return &s->s;
}

/* empty ring queue and free queued mbufs */
static void
empty_queue(struct rte_ring *r)
{
	uint32_t i, n;
	struct rte_mbuf *mb[MAX_PKT_BURST];

	do {
		n = rte_ring_dequeue_burst(r, (void **)mb, RTE_DIM(mb));
		for (i = 0; i != n; i++)
			rte_pktmbuf_free(mb[i]);
	} while (n != 0);
}


/* empty stream's receive queue */
static void
empty_rq(struct tle_tcp_stream *s)
{
	empty_queue(s->rx.q);
	tcp_ofo_reset(s->rx.ofo);	
}


/* empty stream's listen queue */
static void
empty_lq(struct tle_tcp_stream *s, struct stbl *st)
{
	uint32_t i, n;
	struct rte_mbuf *mb;
	union pkt_info pi;
	union seg_info si;
	struct stbl_entry *se[MAX_PKT_BURST];

	do {
		n = rte_ring_dequeue_burst(s->rx.q, (void **)se, RTE_DIM(se));
		for (i = 0; i != n; i++) {
			mb = stbl_get_pkt(se[i]);
			get_pkt_info(mb, &pi, &si);
			stbl_del_pkt_lock(st, se[i], &pi);
			rte_pktmbuf_free(mb);
		}
	} while (n != 0);
}

/*
 * Helper function, used by close API.
 */
static inline void
tcp_stream_term(struct tle_ctx *ctx, struct stbl *st, struct tle_tcp_stream *s)
{
	static const struct tle_stream_cb zcb;

	/* mark stream as unavaialbe for RX/TX. */
	tcp_stream_down(s);

	/* reset TCB */
	memset(&s->tcb, 0, sizeof(s->tcb));

	/* reset cached destination */
	memset(&s->tx.dst, 0, sizeof(s->tx.dst));

	s->rx.ev = NULL;
	s->tx.ev = NULL;
	s->err.ev = NULL;

	s->rx.cb = zcb;
	s->tx.cb = zcb;
	s->err.cb = zcb;

	if (s->ste == NULL) {
		/* free stream's destination port */
		stream_clear_ctx(ctx, &s->s);
		empty_lq(s, st);
	} else {
		/* remove entry from RX streams table */
		stbl_del_stream_lock(st, s->ste, s);
		s->ste = NULL;
		empty_rq(s);
	}

	/* empty TX queue */
	empty_queue(s->tx.q);

	s->ste = NULL;
}

uint32_t
tle_tcp_stream_close_bulk(struct tle_evq *rxq, struct tle_evq *txq,
	struct tle_evq *erq, struct tle_stream *ts[], uint32_t num)
{
	int32_t rc;
	uint32_t i, j;
	uint32_t ie, ir, it;
	struct stbl *st;
	struct tle_ctx *ctx;
	struct tle_tcp_stream *s;
	struct tle_event *rv[num];
	struct tle_event *tv[num];
	struct tle_event *ev[num];

	rc = 0;
	ir = 0, it = 0, ie = 0;

	for (i = 0; i != num; i++) {

		s = TCP_STREAM(ts[i]);
		if (ts[i] == NULL || s->s.type >= TLE_VNUM) {
			rc = EINVAL;
			break;
		}

		rv[ir] = s->rx.ev;
		ir += (s->rx.ev != NULL);
		tv[it] = s->tx.ev;
		it += (s->tx.ev != NULL);
		ev[ie] = s->err.ev;
		ie += (s->err.ev != NULL);
	}

	tle_evq_idle(rxq, rv, ir);
	tle_evq_idle(txq, tv, it);
	tle_evq_idle(erq, ev, ie);

	for (j = 0; j != i; j++) {
		s = TCP_STREAM(ts[j]);
		ctx = s->s.ctx;
		st = CTX_TCP_STLB(ctx); 
		tcp_stream_term(ctx, st, s);
		put_stream(ctx, &s->s, TCP_STREAM_TX_FINISHED(s));
	}

	if (rc != 0)
		rte_errno = rc;
	return i;
}

int
tle_tcp_stream_close(struct tle_stream *ts)
{
	struct tle_ctx *ctx;
	struct tle_tcp_stream *s;
	struct stbl *st;

	s = TCP_STREAM(ts);
	if (ts == NULL || s->s.type >= TLE_VNUM)
		return -EINVAL;

	ctx = s->s.ctx;
	st = CTX_TCP_STLB(ctx); 

	/* reset stream events if any. */
	if (s->rx.ev != NULL)
		tle_event_idle(s->rx.ev);
	if (s->tx.ev != NULL)
		tle_event_idle(s->tx.ev);
	if (s->err.ev != NULL)
		tle_event_idle(s->err.ev);

	tcp_stream_term(ctx, st, s);

	/*
	 * mark the stream as free again.
	 * if there still are pkts queued for TX,
	 * then put this stream to the tail of free list.
	 */
	put_stream(ctx, &s->s, TCP_STREAM_TX_FINISHED(s));
	return 0;
}

int
tle_tcp_stream_get_addr(const struct tle_stream *ts,
	struct tle_tcp_stream_addr *addr)
{
	struct sockaddr_in *lin4, *rin4;
	struct sockaddr_in6 *lin6, *rin6;
	struct tle_tcp_stream *s;

	s = TCP_STREAM(ts);
	if (addr == NULL || ts == NULL || s->s.type >= TLE_VNUM)
		return -EINVAL;

	if (s->s.type == TLE_V4) {

		lin4 = (struct sockaddr_in *)&addr->local;
		rin4 = (struct sockaddr_in *)&addr->remote;

		addr->local.ss_family = AF_INET;
		addr->remote.ss_family = AF_INET;

		lin4->sin_port = s->s.port.dst;
		rin4->sin_port = s->s.port.src;
		lin4->sin_addr.s_addr = s->s.ipv4.addr.dst;
		rin4->sin_addr.s_addr = s->s.ipv4.addr.src;

	} else if (s->s.type == TLE_V6) {

		lin6 = (struct sockaddr_in6 *)&addr->local;
		rin6 = (struct sockaddr_in6 *)&addr->remote;

		addr->local.ss_family = AF_INET6;
		addr->remote.ss_family = AF_INET6;

		lin6->sin6_port = s->s.port.dst;
		rin6->sin6_port = s->s.port.src;
		memcpy(&lin6->sin6_addr, &s->s.ipv6.addr.dst,
			sizeof(lin6->sin6_addr));
		memcpy(&rin6->sin6_addr, &s->s.ipv6.addr.src,
			sizeof(rin6->sin6_addr));
	}

	return 0;
}

int
tle_tcp_stream_listen(struct tle_stream *ts)
{
	struct tle_tcp_stream *s;
	int32_t rc;

	s = TCP_STREAM(ts);
	if (ts == NULL || s->s.type >= TLE_VNUM)
		return -EINVAL;

	/* mark stream as not closable. */
	if (rwl_try_acquire(&s->rx.use) > 0) {
		rc = rte_atomic16_cmpset(&s->tcb.state, TCP_ST_CLOSED,
				TCP_ST_LISTEN);
		rc = (rc == 0) ? -EDEADLK : 0;
	} else
		rc = -EINVAL;

	rwl_release(&s->rx.use);
	return rc;
}

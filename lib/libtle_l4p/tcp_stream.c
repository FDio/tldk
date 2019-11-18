/*
 * Copyright (c) 2016-2017  Intel Corporation.
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

#include <netinet/tcp.h>

#include "tcp_stream.h"
#include "tcp_timer.h"
#include "stream_table.h"
#include "misc.h"
#include "tcp_ctl.h"
#include "tcp_ofo.h"
#include "tcp_txq.h"
#include "tcp_rxtx.h"

static void
unuse_stream(struct tle_tcp_stream *s)
{
	s->s.type = TLE_VNUM;
	rte_atomic32_set(&s->use, INT32_MIN);
}

static void
fini_stream(struct tle_tcp_stream *s)
{
	rte_free(s);
}

static void
tcp_fini_streams(struct tle_ctx *ctx)
{
	struct tcp_streams *ts;
	struct tle_stream *s;

	ts = CTX_TCP_STREAMS(ctx);
	if (ts != NULL) {
		stbl_fini(&ts->st);

		/* TODO: free those in use? may be not necessary, as we assume
		 * all streams have been closed and are free.
		 */
		while (ctx->streams.nb_free--) {
			s = STAILQ_FIRST(&ctx->streams.free);
			STAILQ_FIRST(&ctx->streams.free) = STAILQ_NEXT(s, link);
			fini_stream(TCP_STREAM(s));
		}

		/* free the timer wheel */
		tle_timer_free(ts->tmr);
		rte_free(ts->tsq);

		STAILQ_INIT(&ts->dr.fe);
		STAILQ_INIT(&ts->dr.be);
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
	sz =  rte_ring_get_memsize(n);

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

/* stream memory layout:
 * [tle_tcp_stream] [rx.q] [rx.ofo] [tx.q] [tx.drb.r]
 */
static int
add_stream(struct tle_ctx *ctx)
{
	size_t sz_s, sz_rxq, sz_ofo, sz_txq, sz_drb_r, sz;
	/* for rx.q */
	uint32_t n_rxq;
	/* for rx.ofo */
	struct ofo *ofo;
	struct rte_mbuf **obj;
	uint32_t ndb, nobj;
	size_t dsz, osz;
	/* for tx.q */
	uint32_t n_txq;
	/* for tx.drb.r */
	size_t bsz, rsz;
	struct tle_drb *drb;
	uint32_t k, nb, n_drb;

	uint32_t f, i;
	char name[RTE_RING_NAMESIZE];
	struct tle_tcp_stream *s;

	// stream
	sz_s = RTE_ALIGN_CEIL(sizeof(*s), RTE_CACHE_LINE_SIZE);

	// rx.q
	n_rxq = RTE_MAX(ctx->prm.max_stream_rbufs, 1U);
	n_rxq = rte_align32pow2(n_rxq);
	sz_rxq = rte_ring_get_memsize(n_rxq);
	sz_rxq = RTE_ALIGN_CEIL(sz_rxq, RTE_CACHE_LINE_SIZE);

	// rx.ofo
	calc_ofo_elems(n_rxq, &nobj, &ndb);
	osz = sizeof(*ofo) + sizeof(ofo->db[0]) * ndb;
	dsz = sizeof(ofo->db[0].obj[0]) * nobj * ndb;
	sz_ofo = osz + dsz;
	sz_ofo = RTE_ALIGN_CEIL(sz_ofo, RTE_CACHE_LINE_SIZE);

	// tx.q
	n_txq = RTE_MAX(ctx->prm.max_stream_sbufs, 1U);
	n_txq = rte_align32pow2(n_txq);
	sz_txq = rte_ring_get_memsize(n_txq);
	sz_txq = RTE_ALIGN_CEIL(sz_txq, RTE_CACHE_LINE_SIZE);

	// tx.drb.r
	nb = drb_nb_elem(ctx);
	k = calc_stream_drb_num(ctx, nb);
	n_drb = rte_align32pow2(k);
	rsz = rte_ring_get_memsize(n_drb); /* size of the drbs ring */
	rsz = RTE_ALIGN_CEIL(rsz, RTE_CACHE_LINE_SIZE);
	bsz = tle_drb_calc_size(nb); /* size of the drb. */
	sz_drb_r = rsz + bsz * k; /* total stream drbs size. */
	sz_drb_r = RTE_ALIGN_CEIL(sz_drb_r, RTE_CACHE_LINE_SIZE);

	sz = sz_s + sz_rxq + sz_ofo + sz_txq + sz_drb_r;
	s = rte_zmalloc_socket(NULL, sz, RTE_CACHE_LINE_SIZE,
				ctx->prm.socket_id);
	if (s == NULL) {
		TCP_LOG(ERR, "%s: allocation of %zu bytes on socket %d "
			"failed with error code: %d\n",
			__func__, sz, ctx->prm.socket_id, rte_errno);
		return -ENOMEM;
	}

	s->rx.q = (struct rte_ring *)((uintptr_t)s + sz_s);
	s->rx.ofo = (struct ofo *)((uintptr_t)s->rx.q + sz_rxq);
	ofo = s->rx.ofo;
	s->tx.q = (struct rte_ring *)((uintptr_t)s->rx.ofo + sz_ofo);
	s->tx.drb.r = (struct rte_ring *)((uintptr_t)s->tx.q + sz_txq);

	// ring flags
	f = ((ctx->prm.flags & TLE_CTX_FLAG_ST) == 0) ? 0 :
		(RING_F_SP_ENQ |  RING_F_SC_DEQ);

	/* init RX part. */
	snprintf(name, sizeof(name), "%p@%zu", s->rx.q, sz_rxq);
	rte_ring_init(s->rx.q, name, n_rxq, f);

	obj = (struct rte_mbuf **)&ofo->db[ndb];
	for (i = 0; i != ndb; i++) {
		ofo->db[i].nb_max = nobj;
		ofo->db[i].obj = obj + i * nobj;
	}
	ofo->nb_max = ndb;

	/* init TX part. */
	snprintf(name, sizeof(name), "%p@%zu", s->tx.q, sz_txq);
	rte_ring_init(s->tx.q, name, n_txq, f);

	snprintf(name, sizeof(name), "%p@%zu", s->tx.drb.r, sz_drb_r);
	rte_ring_init(s->tx.drb.r, name, n_drb, f);
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
	_rte_ring_enqueue_burst(us->tx.drb.r, (void **)drb, nb_drb);
}

static struct tle_timer_wheel *
alloc_timers(uint32_t num, uint32_t mshift, int32_t socket)
{
	struct tle_timer_wheel_args twprm;

	twprm.tick_size = TCP_RTO_GRANULARITY;
	twprm.max_timer = num;
	twprm.socket_id = socket;
	return tle_timer_create(&twprm, tcp_get_tms(mshift));
}

static int
tcp_init_streams(struct tle_ctx *ctx)
{
	size_t sz;
	uint32_t f, i;
	int32_t rc;
	struct tcp_streams *ts;

	f = ((ctx->prm.flags & TLE_CTX_FLAG_ST) == 0) ? 0 :
		(RING_F_SP_ENQ |  RING_F_SC_DEQ);

	sz = sizeof(*ts);
	ts = rte_zmalloc_socket(NULL, sz, RTE_CACHE_LINE_SIZE,
		ctx->prm.socket_id);
	if (ts == NULL) {
		TCP_LOG(ERR, "allocation of %zu bytes on socket %d "
			"for %u tcp_streams failed\n",
			sz, ctx->prm.socket_id, ctx->prm.max_streams);
		return -ENOMEM;
	}

	rte_spinlock_init(&ts->dr.lock);
	STAILQ_INIT(&ts->dr.fe);
	STAILQ_INIT(&ts->dr.be);

	ctx->streams.buf = ts;
	STAILQ_INIT(&ctx->streams.free);

	ts->tmr = alloc_timers(ctx->prm.max_streams, ctx->cycles_ms_shift,
		ctx->prm.socket_id);
	if (ts->tmr == NULL) {
		TCP_LOG(ERR, "alloc_timers(ctx=%p) failed with error=%d\n",
			ctx, rte_errno);
		rc = -ENOMEM;
	} else {
		ts->tsq = alloc_ring(ctx->prm.max_streams,
			f | RING_F_SC_DEQ, ctx->prm.socket_id);
		if (ts->tsq == NULL)
			rc = -ENOMEM;
		else
			rc = stbl_init(&ts->st, (ctx->prm.flags & TLE_CTX_FLAG_ST) == 0);
	}

	for (i = 0; rc == 0 && i != ctx->prm.min_streams; i++)
		rc = add_stream(ctx);

	if (rc != 0) {
		TCP_LOG(ERR, "initalisation of %u-th stream failed", i);
		tcp_fini_streams(ctx);
	}

	return rc;
}

/*
 * Note this function is not thread-safe, and we did not lock here as we
 * have the assumption that this ctx is dedicated to one thread.
 */
static uint32_t
tcp_more_streams(struct tle_ctx *ctx)
{
	uint32_t i, nb;
	uint32_t nb_max = ctx->prm.max_streams - 1;
	uint32_t nb_cur = ctx->streams.nb_cur;

	nb = RTE_MIN(ctx->prm.delta_streams, nb_max - nb_cur);
	for (i = 0; i < nb; i++)
		if (add_stream(ctx) != 0)
			break;
	return i;
}

static void __attribute__((constructor(101)))
tcp_stream_setup(void)
{
	static const struct stream_ops tcp_ops = {
		.init_streams = tcp_init_streams,
		.more_streams = tcp_more_streams,
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
		rte_errno = EAGAIN;
		return NULL;
	}

	s->s.option.raw = prm->option;

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
	s->flags = ctx->prm.flags;
	s->tcb.err = 0;
	s->tcb.snd.nb_retm = (prm->cfg.nb_retries != 0) ? prm->cfg.nb_retries :
		TLE_TCP_DEFAULT_RETRIES;
	s->tcb.snd.cwnd = (ctx->prm.icw == 0) ? TCP_INITIAL_CWND_MAX :
				ctx->prm.icw;
	s->tcb.snd.rto_tw = (ctx->prm.timewait == TLE_TCP_TIMEWAIT_DEFAULT) ?
				TCP_RTO_2MSL : ctx->prm.timewait;
	s->tcb.snd.rto_fw = TLE_TCP_FINWAIT_TIMEOUT;

	tcp_stream_up(s);
	return &s->s;
}

/*
 * Helper functions, used by close API.
 */
static inline int
stream_close(struct tle_ctx *ctx, struct tle_tcp_stream *s)
{
	uint16_t uop;
	static const struct tle_stream_cb zcb;

	/* Put uop operation into this wlock; or it may cause this stream
	 * to be put into death ring twice, for example:
	 * 1) FE sets OP_CLOSE;
	 * 2) BE stream_term sets state as TCP_ST_CLOSED, and put in queue;
	 * 3) FE down the stream, and calls stream_term again.
	 */
	tcp_stream_down(s);

	/* check was close() already invoked */
	uop = s->tcb.uop;
	if ((uop & TCP_OP_CLOSE) != 0)
		return -EDEADLK;

	/* record that close() was already invoked */
	if (rte_atomic16_cmpset(&s->tcb.uop, uop, uop | TCP_OP_CLOSE) == 0)
		return -EDEADLK;

	/* reset events/callbacks */
	s->tx.ev = NULL;
	s->rx.ev = NULL;
	s->err.ev = NULL;

	s->rx.cb = zcb;
	s->tx.cb = zcb;
	s->err.cb = zcb;

	switch (s->tcb.state) {
	case TCP_ST_LISTEN:
		/* close the stream straightway */
		tcp_stream_reset(ctx, s);
		return 0;
	case TCP_ST_CLOSED:
		/* it could be put into this state if a RST packet is
		 * received, but this stream could be still in tsq trying
		 * to send something.
		 */
		/* fallthrough */
	case TCP_ST_SYN_SENT:
		/* timer on and could be in tsq (SYN retrans) */
		stream_term(s);
		/* fallthrough */
	case TCP_ST_FIN_WAIT_1:
		/* fallthrough */
	case TCP_ST_CLOSING:
		/* fallthrough */
	case TCP_ST_TIME_WAIT:
		/* fallthrough */
	case TCP_ST_LAST_ACK:
		tcp_stream_up(s);
		return 0;
	case TCP_ST_ESTABLISHED:
		/* fallthrough */
	case TCP_ST_CLOSE_WAIT:
		if (s->tcb.state == TCP_ST_ESTABLISHED) {
			s->tcb.state = TCP_ST_FIN_WAIT_1;
			TCP_DEC_STATS_ATOMIC(TCP_MIB_CURRESTAB);
		} else
			s->tcb.state = TCP_ST_LAST_ACK;

		if (!rte_ring_empty(s->rx.q)) {
			TCP_INC_STATS(TCP_MIB_ESTABRESETS);
			s->tcb.uop |= TCP_OP_RESET;
			stream_term(s);
		}
		break;
	case TCP_ST_FIN_WAIT_2:
		/* Can reach this state if shutdown was called, but the timer
		 * shall be set after this close.
		 */
		break;
	default:
		rte_panic("Invalid state when close: %d\n", s->tcb.state);
	}

	tcp_stream_up(s);
	txs_enqueue(ctx, s);
	return 0;
}

uint32_t
tle_tcp_stream_close_bulk(struct tle_stream *ts[], uint32_t num)
{
	int32_t rc;
	uint32_t i;
	struct tle_ctx *ctx;
	struct tle_tcp_stream *s;

	rc = 0;

	for (i = 0; i != num; i++) {

		s = TCP_STREAM(ts[i]);
		if (ts[i] == NULL || s->s.type >= TLE_VNUM) {
			rc = EINVAL;
			break;
		}

		ctx = s->s.ctx;
		rc = stream_close(ctx, s);
		if (rc != 0)
			break;
	}

	if (rc != 0)
		rte_errno = -rc;
	return i;
}

int
tle_tcp_stream_close(struct tle_stream *ts)
{
	struct tle_ctx *ctx;
	struct tle_tcp_stream *s;

	s = TCP_STREAM(ts);
	if (ts == NULL || s->s.type >= TLE_VNUM)
		return -EINVAL;

	ctx = s->s.ctx;
	return stream_close(ctx, s);
}

int
tle_tcp_stream_shutdown(struct tle_stream *ts, int how)
{
	int ret;
	bool wakeup;
	uint32_t state;
	struct tle_tcp_stream *s;

	s = TCP_STREAM(ts);
	if (ts == NULL || s->s.type >= TLE_VNUM)
		return -EINVAL;

	/* Refer to linux/net/ipv4/tcp.c:tcp_shutdown() */
	if (how == SHUT_RD)
		return 0;

	tcp_stream_down(s);

	state = s->tcb.state;

	switch (state) {
	case TCP_ST_LISTEN:
		/* fallthrough */
	case TCP_ST_SYN_SENT:
		s->tcb.state = TCP_ST_CLOSED;
		wakeup = true;
		ret = 0;
		break;
	case TCP_ST_ESTABLISHED:
		/* fallthrough */
	case TCP_ST_CLOSE_WAIT:
		if (state == TCP_ST_ESTABLISHED) {
			TCP_DEC_STATS_ATOMIC(TCP_MIB_CURRESTAB);
			s->tcb.state = TCP_ST_FIN_WAIT_1;
		} else
			s->tcb.state = TCP_ST_LAST_ACK;
		txs_enqueue(ts->ctx, s);
		wakeup = true;
		ret = 0;
		break;
	default:
		wakeup = false;
		rte_errno = ENOTCONN;
		ret = -1;
	}

	if (wakeup) {
		/* Notify other threads which may wait on the event */
		if (s->tx.ev)
			tle_event_raise(s->tx.ev);
		if (how == SHUT_RDWR && s->err.ev)
			tle_event_raise(s->err.ev);
	}

	tcp_stream_up(s);
	return ret;
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

	/* app may listen for multiple times to change backlog,
	 * we will just return success for such cases.
	 */
	if (s->tcb.state == TCP_ST_LISTEN)
		return 0;

	/* mark stream as not closable. */
	if (tcp_stream_try_acquire(s) > 0) {
		rc = rte_atomic16_cmpset(&s->tcb.state, TCP_ST_CLOSED,
				TCP_ST_LISTEN);
		if (rc != 0) {
			s->tcb.uop |= TCP_OP_LISTEN;
			s->tcb.rcv.wnd = calc_rx_wnd(s, TCP_WSCALE_DEFAULT);
			rc = 0;
		} else
			rc = -EDEADLK;
	} else
		rc = -EINVAL;

	tcp_stream_release(s);
	return rc;
}

/*
 * helper function, updates stream config
 */
static inline int
stream_update_cfg(struct tle_stream *ts,struct tle_tcp_stream_cfg *prm)
{
	struct tle_tcp_stream *s;

	s = TCP_STREAM(ts);

	if (tcp_stream_try_acquire(s) < 0 || (s->tcb.uop & TCP_OP_CLOSE) != 0) {
		tcp_stream_release(s);
		return -EINVAL;
	}

	/* setup stream notification menchanism */
	s->rx.ev = prm->recv_ev;
	s->tx.ev = prm->send_ev;
	s->err.ev = prm->err_ev;

	s->rx.cb.data = prm->recv_cb.data;
	s->tx.cb.data = prm->send_cb.data;
	s->err.cb.data = prm->err_cb.data;

	rte_smp_wmb();

	s->rx.cb.func = prm->recv_cb.func;
	s->tx.cb.func = prm->send_cb.func;
	s->err.cb.func = prm->err_cb.func;

	/* store other params */
	s->tcb.snd.nb_retm = (prm->nb_retries != 0) ? prm->nb_retries :
		TLE_TCP_DEFAULT_RETRIES;

	/* invoke async notifications, if any */
	if (rte_ring_count(s->rx.q) != 0) {
		if (s->rx.ev != NULL)
			tle_event_raise(s->rx.ev);
		else if (s->rx.cb.func != NULL)
			s->rx.cb.func(s->rx.cb.data, &s->s);
	}
	if (rte_ring_free_count(s->tx.q) != 0) {
		if (s->tx.ev != NULL)
			tle_event_raise(s->tx.ev);
		else if (s->tx.cb.func != NULL)
			s->tx.cb.func(s->tx.cb.data, &s->s);
	}
	if (s->tcb.state == TCP_ST_CLOSE_WAIT ||
			s->tcb.state ==  TCP_ST_CLOSED) {
		if (s->err.ev != NULL)
			tle_event_raise(s->err.ev);
		else if (s->err.cb.func != NULL)
			s->err.cb.func(s->err.cb.data, &s->s);
	}

	tcp_stream_release(s);
	return 0;
}

uint32_t
tle_tcp_stream_update_cfg(struct tle_stream *ts[],
	struct tle_tcp_stream_cfg prm[], uint32_t num)
{
	int32_t rc;
	uint32_t i;

	for (i = 0; i != num; i++) {
		rc = stream_update_cfg(ts[i], &prm[i]);
		if (rc != 0) {
			rte_errno = -rc;
			break;
		}
	}

	return i;
}

int
tle_tcp_stream_get_mss(const struct tle_stream * ts)
{
	struct tle_tcp_stream *s;

	if (ts == NULL)
		return -EINVAL;

	s = TCP_STREAM(ts);
	return s->tcb.snd.mss;
}

int
tle_tcp_stream_get_info(const struct tle_stream * ts, void *info, socklen_t *optlen)
{
	struct tle_tcp_stream *s;
	struct tcp_info i;

	if (ts == NULL)
		return -EINVAL;

	s = TCP_STREAM(ts);

	memset(&i, 0, sizeof(struct tcp_info));

	/* transform from tldk state into linux kernel state */
	switch (s->tcb.state) {
	case TCP_ST_CLOSED:
		i.tcpi_state = TCP_CLOSE;
		break;
	case TCP_ST_LISTEN:
		i.tcpi_state = TCP_LISTEN;
		break;
	case TCP_ST_SYN_SENT:
		i.tcpi_state = TCP_SYN_SENT;
		break;
	case TCP_ST_SYN_RCVD:
		i.tcpi_state = TCP_SYN_RECV;
		break;
	case TCP_ST_ESTABLISHED:
		i.tcpi_state = TCP_ESTABLISHED;
		break;
	case TCP_ST_FIN_WAIT_1:
		i.tcpi_state = TCP_FIN_WAIT1;
		break;
	case TCP_ST_FIN_WAIT_2:
		i.tcpi_state = TCP_FIN_WAIT2;
		break;
	case TCP_ST_CLOSE_WAIT:
		i.tcpi_state = TCP_CLOSE_WAIT;
		break;
	case TCP_ST_CLOSING:
		i.tcpi_state = TCP_CLOSING;
		break;
	case TCP_ST_LAST_ACK:
		i.tcpi_state = TCP_LAST_ACK;
		break;
	case TCP_ST_TIME_WAIT:
		i.tcpi_state = TCP_TIME_WAIT;
		break;
	}

	/* fix me, total retrans? */
	i.tcpi_total_retrans = s->tcb.snd.nb_retx;

	if (*optlen > sizeof(struct tcp_info))
		*optlen = sizeof(struct tcp_info);
	rte_memcpy(info, &i, *optlen);
	return 0;
}

void
tle_tcp_stream_set_keepalive(struct tle_stream *ts)
{
	struct tle_tcp_stream *s;

	s = TCP_STREAM(ts);

	s->tcb.uop |= TCP_OP_KEEPALIVE;
	txs_enqueue(ts->ctx, s);
}

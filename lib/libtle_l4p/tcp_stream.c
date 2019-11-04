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

#include "tcp_stream.h"
#include "tcp_timer.h"
#include "stream_table.h"
#include "misc.h"
#include "tcp_ctl.h"
#include "tcp_ofo.h"
#include "tcp_txq.h"

#define MAX_STREAM_BURST	0x40

static void
unuse_stream(struct tle_tcp_stream *s)
{
	s->s.type = TLE_VNUM;
	rte_atomic32_set(&s->use, INT32_MIN);
}

static void
tcp_fini_streams(struct tle_ctx *ctx)
{
	struct tcp_streams *ts;

	ts = CTX_TCP_STREAMS(ctx);
	if (ts != NULL) {

		stbl_fini(&ts->st);
		tle_timer_free(ts->tmr);
		rte_free(ts->tsq);
		tle_memtank_dump(stdout, ts->mts, 0);
		tle_memtank_destroy(ts->mts);

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

static void
calc_stream_szofs(struct tle_ctx *ctx, struct stream_szofs *szofs)
{
	uint32_t n, na, sz, tsz;

	sz = sizeof(struct tle_tcp_stream);

	n = RTE_MAX(ctx->prm.max_stream_rbufs, 1U);
	tcp_ofo_calc_elems(n, &szofs->ofo.nb_obj, &szofs->ofo.nb_max, &tsz);
	szofs->ofo.ofs = sz;

	sz += tsz;
	sz = RTE_ALIGN_CEIL(sz, RTE_CACHE_LINE_SIZE);

	na = rte_align32pow2(n);
	szofs->rxq.ofs = sz;
	szofs->rxq.nb_obj = na;

	sz += rte_ring_get_memsize(na);
	sz = RTE_ALIGN_CEIL(sz, RTE_CACHE_LINE_SIZE);

	n = RTE_MAX(ctx->prm.max_stream_sbufs, 1U);
	na = rte_align32pow2(n);
	szofs->txq.ofs = sz;
	szofs->txq.nb_obj = na;

	sz += rte_ring_get_memsize(na);
	sz = RTE_ALIGN_CEIL(sz, RTE_CACHE_LINE_SIZE);

	szofs->drb.nb_obj = drb_nb_elem(ctx);
	szofs->drb.nb_max = calc_stream_drb_num(ctx, szofs->drb.nb_obj);
	szofs->drb.nb_rng = rte_align32pow2(szofs->drb.nb_max);
	szofs->drb.rng_sz = rte_ring_get_memsize(szofs->drb.nb_rng);
	szofs->drb.blk_sz = tle_drb_calc_size(szofs->drb.nb_obj);
	szofs->drb.ofs = sz;

	sz += szofs->drb.rng_sz + szofs->drb.blk_sz * szofs->drb.nb_max;
	sz = RTE_ALIGN_CEIL(sz, RTE_CACHE_LINE_SIZE);

	szofs->size = sz;
}

static void
init_stream(struct tle_ctx *ctx, struct tle_tcp_stream *s,
	const struct stream_szofs *szofs)
{
	uint32_t f, i;
	struct tle_drb *drb;

	f = ((ctx->prm.flags & TLE_CTX_FLAG_ST) == 0) ? 0 :
		(RING_F_SP_ENQ |  RING_F_SC_DEQ);

	/* init RX part. */

	s->rx.ofo = (void *)((uintptr_t)s + szofs->ofo.ofs);
	tcp_ofo_init(s->rx.ofo, szofs->ofo.nb_obj, szofs->ofo.nb_max);

	s->rx.q = (void *)((uintptr_t)s + szofs->rxq.ofs);
	rte_ring_init(s->rx.q, __func__, szofs->rxq.nb_obj, f | RING_F_SP_ENQ);

	/* init TX part. */

	s->tx.q = (void *)((uintptr_t)s + szofs->txq.ofs);
	rte_ring_init(s->tx.q, __func__, szofs->txq.nb_obj, f | RING_F_SC_DEQ);

	s->tx.drb.r = (void *)((uintptr_t)s + szofs->drb.ofs);
	rte_ring_init(s->tx.drb.r, __func__, szofs->drb.nb_rng, f);

	for (i = 0; i != szofs->drb.nb_max; i++) {
		drb = (struct tle_drb *)((uintptr_t)s->tx.drb.r +
			szofs->drb.rng_sz + szofs->drb.blk_sz * i);
		drb->udata = s;
		drb->size = szofs->drb.nb_obj;
		rte_ring_enqueue(s->tx.drb.r, drb);
	}

	s->tx.drb.nb_elem = szofs->drb.nb_obj;
	s->tx.drb.nb_max = szofs->drb.nb_max;

	/* mark stream as avaialble to use. */

	s->s.ctx = ctx;
	unuse_stream(s);
}

static void
tcp_free_drbs(struct tle_stream *s, struct tle_drb *drb[], uint32_t nb_drb)
{
	struct tle_tcp_stream *us;

	us = (struct tle_tcp_stream *)s;
	_rte_ring_enqueue_burst(us->tx.drb.r, (void **)drb, nb_drb);
}

static struct tle_timer_wheel *
alloc_timers(const struct tle_ctx *ctx)
{
	struct tle_timer_wheel *twl;
	struct tle_timer_wheel_args twprm;

	twprm.tick_size = TCP_RTO_GRANULARITY;
	twprm.max_timer = ctx->prm.max_streams;
	twprm.socket_id = ctx->prm.socket_id;

	twl = tle_timer_create(&twprm, tcp_get_tms(ctx->cycles_ms_shift));
	if (twl == NULL)
		TCP_LOG(ERR, "alloc_timers(ctx=%p) failed with error=%d\n",
			ctx, rte_errno);
	return twl;
}

static void *
mts_alloc(size_t sz, void *udata)
{
	struct tle_ctx *ctx;

	ctx = udata;
	return rte_zmalloc_socket(NULL, sz, RTE_CACHE_LINE_SIZE,
		ctx->prm.socket_id);
}

static void
mts_free(void *p, void *udata)
{
	RTE_SET_USED(udata);
	rte_free(p);
}

static void
mts_init(void *pa[], uint32_t num, void *udata)
{
	uint32_t i;
	struct tle_ctx *ctx;
	struct tcp_streams *ts;

	ctx = udata;
	ts = CTX_TCP_STREAMS(ctx);

	for (i = 0; i != num; i++)
		init_stream(ctx, pa[i], &ts->szofs);
}

static struct tle_memtank *
alloc_mts(struct tle_ctx *ctx, uint32_t stream_size)
{
	struct tle_memtank *mts;
	struct tle_memtank_prm prm;

	static const struct tle_memtank_prm cprm = {
		.alloc = mts_alloc,
		.free = mts_free,
		.init = mts_init,
	};

	prm = cprm;
	prm.udata = ctx;

	prm.obj_size = stream_size;

	prm.min_free = (ctx->prm.free_streams.min != 0) ?
		ctx->prm.free_streams.min : ctx->prm.max_streams;
	prm.max_free = (ctx->prm.free_streams.max > prm.min_free) ?
		ctx->prm.free_streams.max : prm.min_free;

	prm.nb_obj_chunk = MAX_STREAM_BURST;
	prm.max_chunk = (ctx->prm.max_streams + prm.nb_obj_chunk - 1) /
		prm.nb_obj_chunk;

	mts = tle_memtank_create(&prm);
	if (mts == NULL)
		TCP_LOG(ERR, "%s(ctx=%p) failed with error=%d\n",
			__func__, ctx, rte_errno);
	else
		tle_memtank_grow(mts);

	return mts;
}

static int
tcp_init_streams(struct tle_ctx *ctx)
{
	uint32_t f;
	int32_t rc;
	struct tcp_streams *ts;
	struct stream_szofs szofs;

	f = ((ctx->prm.flags & TLE_CTX_FLAG_ST) == 0) ? 0 :
		(RING_F_SP_ENQ |  RING_F_SC_DEQ);

	calc_stream_szofs(ctx, &szofs);
	TCP_LOG(NOTICE, "ctx:%p, caluclated stream size: %u\n",
		ctx, szofs.size);

	ts = rte_zmalloc_socket(NULL, sizeof(*ts), RTE_CACHE_LINE_SIZE,
		ctx->prm.socket_id);
	if (ts == NULL)
		return -ENOMEM;

	ts->szofs = szofs;

	STAILQ_INIT(&ts->dr.fe);
	STAILQ_INIT(&ts->dr.be);

	ctx->streams.buf = ts;
	STAILQ_INIT(&ctx->streams.free);

	rc = stbl_init(&ts->st, ctx->prm.max_streams, ctx->prm.socket_id);

	if (rc == 0) {
		ts->tsq = alloc_ring(ctx->prm.max_streams, f | RING_F_SC_DEQ,
			ctx->prm.socket_id);
		ts->tmr = alloc_timers(ctx);
		ts->mts = alloc_mts(ctx, szofs.size);
	
		if (ts->tsq == NULL || ts->tmr == NULL || ts->mts == NULL)
			rc = -ENOMEM;
	}

	if (rc != 0) {
		TCP_LOG(ERR, "initalisation of tcp streams failed");
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
	struct tcp_streams *ts;
	struct tle_tcp_stream *s;
	int32_t rc;

	if (ctx == NULL || prm == NULL || check_stream_prm(ctx, prm) != 0) {
		rte_errno = EINVAL;
		return NULL;
	}

	ts = CTX_TCP_STREAMS(ctx);

	s = tcp_stream_get(ctx, TLE_MTANK_ALLOC_CHUNK | TLE_MTANK_ALLOC_GROW);
	if (s == NULL) {
		rte_errno = ENFILE;
		return NULL;
	}

	/* setup L4 ports and L3 addresses fields. */
	rc = stream_fill_ctx(ctx, &s->s,
		(const struct sockaddr *)&prm->addr.local,
		(const struct sockaddr *)&prm->addr.remote);

	if (rc != 0) {
		tle_memtank_free(ts->mts, (void **)&s, 1,
			TLE_MTANK_FREE_SHRINK);
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
	s->tcb.snd.nb_retm = (prm->cfg.nb_retries != 0) ? prm->cfg.nb_retries :
		TLE_TCP_DEFAULT_RETRIES;
	s->tcb.snd.cwnd = (ctx->prm.icw == 0) ? TCP_INITIAL_CWND_MAX :
				ctx->prm.icw;
	s->tcb.snd.rto_tw = (ctx->prm.timewait == TLE_TCP_TIMEWAIT_DEFAULT) ?
				TCP_RTO_2MSL : ctx->prm.timewait;

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
	uint32_t state;
	static const struct tle_stream_cb zcb;

	/* check was close() already invoked */
	uop = s->tcb.uop;
	if ((uop & TCP_OP_CLOSE) != 0)
		return -EDEADLK;

	/* record that close() was already invoked */
	if (rte_atomic16_cmpset(&s->tcb.uop, uop, uop | TCP_OP_CLOSE) == 0)
		return -EDEADLK;

	/* mark stream as unavaialbe for RX/TX. */
	tcp_stream_down(s);

	/* reset events/callbacks */
	s->rx.ev = NULL;
	s->tx.ev = NULL;
	s->err.ev = NULL;

	s->rx.cb = zcb;
	s->tx.cb = zcb;
	s->err.cb = zcb;

	state = s->tcb.state;

	/* CLOSED, LISTEN, SYN_SENT - we can close the stream straighway */
	if (state <= TCP_ST_SYN_SENT) {
		tcp_stream_reset(ctx, s);
		return 0;
	}

	/* generate FIN and proceed with normal connection termination */
	if (state == TCP_ST_ESTABLISHED || state == TCP_ST_CLOSE_WAIT) {

		/* change state */
		s->tcb.state = (state == TCP_ST_ESTABLISHED) ?
			TCP_ST_FIN_WAIT_1 : TCP_ST_LAST_ACK;

		/* mark stream as writable/readable again */
		tcp_stream_up(s);

		/* queue stream into to-send queue */
		txs_enqueue(ctx, s);
		return 0;
	}

	/*
	 * accroding to the state, close() was already invoked,
	 * should never that point.
	 */
	RTE_ASSERT(0);
	return -EINVAL;
}

uint32_t
tle_tcp_stream_close_bulk(struct tle_stream *ts[], uint32_t num)
{
	int32_t rc;
	uint32_t i;
	struct tle_ctx *ctx;
	struct tle_tcp_stream *s;

	rc = 0;

	for (i = 0; i != num && rc == 0; i++) {

		s = TCP_STREAM(ts[i]);
		if (ts[i] == NULL || s->s.type >= TLE_VNUM)
			rc = EINVAL;

		else {
			ctx = s->s.ctx;
			rc = stream_close(ctx, s);
			tle_memtank_shrink(CTX_TCP_MTS(ctx));
		}
	}

	if (rc != 0)
		rte_errno = -rc;
	return i;
}

int
tle_tcp_stream_close(struct tle_stream *ts)
{
	int32_t rc;
	struct tle_ctx *ctx;
	struct tle_tcp_stream *s;

	s = TCP_STREAM(ts);
	if (ts == NULL || s->s.type >= TLE_VNUM)
		return -EINVAL;

	ctx = s->s.ctx;
	rc = stream_close(ctx, s);
	tle_memtank_shrink(CTX_TCP_MTS(ctx));
	return rc;
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

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

/*
 * Some helper stream control functions definitions.
 */

#ifndef _TCP_CTL_H_
#define _TCP_CTL_H_

#include "tcp_stream.h"
#include "tcp_ofo.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline void
tcp_stream_down(struct tle_tcp_stream *s)
{
	if ((s->flags & TLE_CTX_FLAG_ST) == 0)
		rwl_down(&s->use);
	else
		rte_atomic32_set(&s->use, INT32_MIN);
}

static inline void
tcp_stream_up(struct tle_tcp_stream *s)
{
	int32_t v;

	if ((s->flags & TLE_CTX_FLAG_ST) == 0)
		rwl_up(&s->use);
	else {
		v = rte_atomic32_read(&s->use) - INT32_MIN;
		rte_atomic32_set(&s->use, v);
	}
}

static inline int
tcp_stream_try_acquire(struct tle_tcp_stream *s)
{
	int32_t v;

	if ((s->flags & TLE_CTX_FLAG_ST) == 0)
		return rwl_try_acquire(&s->use);

	v = rte_atomic32_read(&s->use) + 1;
	rte_atomic32_set(&s->use, v);
	return v;
}

static inline void
tcp_stream_release(struct tle_tcp_stream *s)
{
	int32_t v;

	if ((s->flags & TLE_CTX_FLAG_ST) == 0)
		rwl_release(&s->use);
	else {
		v = rte_atomic32_read(&s->use) - 1;
		rte_atomic32_set(&s->use, v);
	}
}

static inline int
tcp_stream_acquire(struct tle_tcp_stream *s)
{
	int32_t v;

	if ((s->flags & TLE_CTX_FLAG_ST) == 0)
		return rwl_acquire(&s->use);

	v = rte_atomic32_read(&s->use) + 1;
	if (v > 0)
		rte_atomic32_set(&s->use, v);
	return v;
}

/* calculate RCV.WND value based on current free size of stream receive buffer */
static inline uint32_t
calc_rcv_wnd(const struct tle_tcp_stream *s)
{
	uint32_t buffer_max;
	uint32_t wscale_max;

	buffer_max = _rte_ring_get_free_count(s->rx.q) * s->s.ctx->prm.window_mbuf_size;
	wscale_max = UINT16_MAX << s->tcb.rcv.wscale;

	return RTE_MIN(buffer_max, wscale_max);
}

/* calculate rcv.wnd value based on maximum capacity of stream receive buffer */
static inline uint32_t
calc_rcv_wnd_max(const struct tle_tcp_stream *s)
{
	uint32_t buffer_capacity;
	uint32_t wscale_max;

	buffer_capacity = _rte_ring_get_capacity(s->rx.q) * s->s.ctx->prm.window_mbuf_size;
	wscale_max = UINT16_MAX << s->tcb.rcv.wscale;

	return RTE_MIN(buffer_capacity, wscale_max);
}

/* calculate the value to put into a packet TCP header for window size */
static inline uint16_t
calc_pkt_rx_wnd(const struct tcb *tcb, uint8_t flags)
{
	uint32_t syn_capped_wnd;
	uint32_t flag_checked_wnd;

	syn_capped_wnd = RTE_MIN((uint32_t)UINT16_MAX, tcb->rcv.wnd);
	flag_checked_wnd = (flags & TCP_FLAG_SYN) ? syn_capped_wnd : tcb->rcv.wnd;

	assert((flag_checked_wnd >> tcb->rcv.wscale) <= UINT16_MAX);

	return flag_checked_wnd >> tcb->rcv.wscale;
}

/*
 * Helper functions for stream_close()
 */

/* empty stream's send queue */
static inline void
empty_tq(struct tle_tcp_stream *s)
{
	s->tx.q->cons.head = s->tx.q->cons.tail;
	empty_mbuf_ring(s->tx.q);
}

/* empty stream's receive queue */
static inline void
empty_rq(struct tle_tcp_stream *s)
{
	uint32_t n;
	struct rte_mbuf *mb[MAX_PKT_BURST];

	do {
		n = _rte_ring_mcs_dequeue_burst(s->rx.q, (void **)mb,
			RTE_DIM(mb));
		free_mbufs(mb, n);
	} while (n != 0);

	tcp_ofo_reset(s->rx.ofo);
}

/* empty stream's listen queue */
static inline void
empty_lq(struct tle_tcp_stream *s)
{
	uint32_t n;
	struct tle_stream *ts[MAX_PKT_BURST];

	do {
		n = _rte_ring_dequeue_burst(s->rx.q, (void **)ts, RTE_DIM(ts));
		tle_tcp_stream_close_bulk(ts, n);
	} while (n != 0);
}

static inline void
tcp_stream_reset(struct tle_ctx *ctx, struct tle_tcp_stream *s)
{
	uint16_t uop;
	struct tcp_streams *ts;

	ts = CTX_TCP_STREAMS(ctx);

	/* reset TX armed */
	rte_atomic32_set(&s->tx.arm, 0);

	/* reset TCB */
	uop = s->tcb.uop & ~TLE_TCP_OP_CLOSE_ABORT;
	memset(&s->tcb, 0, sizeof(s->tcb));

	/* reset remote events */
	s->err.rev = 0;

	/* reset cached destination */
	memset(&s->tx.dst, 0, sizeof(s->tx.dst));

	if (uop != TLE_TCP_OP_ACCEPT) {
		/* free stream's destination port */
		stream_clear_ctx(ctx, &s->s);
		if (uop == TLE_TCP_OP_LISTEN)
			empty_lq(s);
	}

	if (s->ste != NULL) {
		/* remove entry from RX streams table */
		stbl_del_stream(&ts->st, s->ste, s,
			(s->flags & TLE_CTX_FLAG_ST) == 0);
		s->ste = NULL;
	}

	/* empty RX queue */
	empty_rq(s);

	/* empty TX queue */
	empty_tq(s);

	/*
	 * mark the stream as free again.
	 * if there still are pkts queued for TX,
	 * then put this stream to the tail of free list.
	 */
	if (TCP_STREAM_TX_PENDING(s)) 
		put_stream(ctx, &s->s, 0);
	else {
		s->s.type = TLE_VNUM;
		tle_memtank_free(ts->mts, (void **)&s, 1, 0);
	}
}

/*
 * - set new uop (CLOSE, ABORT) atomically
 * - mark stream down
 * - reset events/callbacks
 * - if no further actions are necessary, then reset the stream straightway
 * @return
 *   - negative error code
 *   - zero if stream was terminated and no further action is required
 *   - current stream state (TLE_TCP_ST *) otherwise
 */
static inline int
stream_close_prolog(struct tle_ctx *ctx, struct tle_tcp_stream *s, uint16_t nop)
{
	uint16_t uop;
	uint32_t state;
	static const struct tle_stream_cb zcb;

	/* check was *nop* already invoked */
	uop = s->tcb.uop;
	if ((uop & nop) == nop)
		return -EDEADLK;

	/* record that *nop* was already invoked */
	if (rte_atomic16_cmpset(&s->tcb.uop, uop, uop | nop) == 0)
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
	if (state <= TLE_TCP_ST_SYN_SENT) {
		tcp_stream_reset(ctx, s);
		return 0;
	}

	return state;
}

static inline struct tle_tcp_stream *
tcp_stream_get(struct tle_ctx *ctx, uint32_t flag)
{
	struct tle_stream *s;
	struct tle_tcp_stream *cs;
	struct tcp_streams *ts;

	ts = CTX_TCP_STREAMS(ctx);
	
	/* check TX pending list */
	s = get_stream(ctx);
	cs = TCP_STREAM(s);
	if (s != NULL) {
		if (TCP_STREAM_TX_FINISHED(cs))
			return cs;
		put_stream(ctx, &cs->s, 0);
	}

	if (tle_memtank_alloc(ts->mts, (void **)&cs, 1, flag) != 1)
		return NULL;

	return cs;
}

#ifdef __cplusplus
}
#endif

#endif /* _TCP_CTL_H_ */

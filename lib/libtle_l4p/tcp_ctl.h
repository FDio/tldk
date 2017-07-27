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

/* calculate RCV.WND value based on size of stream receive buffer */
static inline uint32_t
calc_rx_wnd(const struct tle_tcp_stream *s, uint32_t scale)
{
	uint32_t wnd;

	/* peer doesn't support WSCALE option, wnd size is limited to 64K */
	if (scale == TCP_WSCALE_NONE) {
		wnd = _rte_ring_get_mask(s->rx.q) << TCP_WSCALE_DEFAULT;
		return RTE_MIN(wnd, (uint32_t)UINT16_MAX);
	} else
		return  _rte_ring_get_mask(s->rx.q) << scale;
}

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
	struct stbl *st;
	uint16_t uop;

	st = CTX_TCP_STLB(ctx);

	/* reset TX armed */
	rte_atomic32_set(&s->tx.arm, 0);

	/* reset TCB */
	uop = s->tcb.uop & ~TCP_OP_CLOSE;
	memset(&s->tcb, 0, sizeof(s->tcb));

	/* reset cached destination */
	memset(&s->tx.dst, 0, sizeof(s->tx.dst));

	if (uop != TCP_OP_ACCEPT) {
		/* free stream's destination port */
		stream_clear_ctx(ctx, &s->s);
		if (uop == TCP_OP_LISTEN)
			empty_lq(s);
	}

	if (s->ste != NULL) {
		/* remove entry from RX streams table */
		stbl_del_stream(st, s->ste, s,
			(s->flags & TLE_CTX_FLAG_ST) == 0);
		s->ste = NULL;
		empty_rq(s);
	}

	/* empty TX queue */
	empty_tq(s);

	/*
	 * mark the stream as free again.
	 * if there still are pkts queued for TX,
	 * then put this stream to the tail of free list.
	 */
	put_stream(ctx, &s->s, TCP_STREAM_TX_FINISHED(s));
}

#ifdef __cplusplus
}
#endif

#endif /* _TCP_CTL_H_ */

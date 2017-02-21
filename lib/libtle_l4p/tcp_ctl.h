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
	rwl_down(&s->rx.use);
	rwl_down(&s->tx.use);
}

static inline void
tcp_stream_up(struct tle_tcp_stream *s)
{
	rwl_up(&s->rx.use);
	rwl_up(&s->tx.use);
}

/* empty stream's receive queue */
static void
empty_rq(struct tle_tcp_stream *s)
{
	empty_mbuf_ring(s->rx.q);
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

static inline void
tcp_stream_reset(struct tle_ctx *ctx, struct tle_tcp_stream *s)
{
	struct stbl *st;
	uint16_t uop;

	st = CTX_TCP_STLB(ctx);

	/* reset TX armed */
	rte_atomic32_set(&s->tx.arm, 0);

	/* reset TCB */
	uop = s->tcb.uop & (TCP_OP_LISTEN | TCP_OP_CONNECT);
	memset(&s->tcb, 0, sizeof(s->tcb));

	/* reset cached destination */
	memset(&s->tx.dst, 0, sizeof(s->tx.dst));

	if (uop != 0) {
		/* free stream's destination port */
		stream_clear_ctx(ctx, &s->s);
		if (uop == TCP_OP_LISTEN)
			empty_lq(s, st);
	}

	if (s->ste != NULL) {
		/* remove entry from RX streams table */
		stbl_del_stream_lock(st, s->ste, s);
		s->ste = NULL;
		empty_rq(s);
	}

	/* empty TX queue */
	empty_mbuf_ring(s->tx.q);

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

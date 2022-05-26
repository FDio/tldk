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

#ifndef _TCP_TXQ_H_
#define _TCP_TXQ_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * ring structure in memory is:
 * [rte_ring][data for circular buffer]
 * _rte_ring_get_data(r) gets the pointer to [data...]
 * ring head is snd.nxt
 * ring tail is snd.una
 * this means
 *   get_data() + head == start of snd.nxt data
 *   get_data() + tail == start of snd.una data
 *
 * this als means in "normal" conditions ring has unack'd sent data
 * [... snd.una (tail) <sent !ack'd data> snd.nxt (head) <!sent data>
 * this puts head forward of tail and things like rst_nxt_head() which
 * move head back to tail "forget" about sent but unack'd data
 */


static inline struct rte_mbuf **
tcp_txq_get_nxt_objs(const struct tle_tcp_stream *s, uint32_t *num)
{
	uint32_t cnt, head, mask, sz, tail;
	struct rte_ring *r;

	r = s->tx.q;
	sz = _rte_ring_get_size(r);
	mask = _rte_ring_get_mask(r);
	head = r->cons.head & mask;
	tail = r->prod.tail & mask;

	cnt = (tail >= head) ? tail - head : sz - head;

	*num = cnt;
	return (struct rte_mbuf **)(_rte_ring_get_data(r) + head);
}

static inline struct rte_mbuf **
tcp_txq_get_una_objs(const struct tle_tcp_stream *s, uint32_t *num)
{
	uint32_t cnt, head, mask, sz, tail;
	struct rte_ring *r;

	r = s->tx.q;
	sz = _rte_ring_get_size(r);
	mask = _rte_ring_get_mask(r);
	head = r->prod.tail & mask;
	tail = r->cons.tail & mask;

	cnt = (head >= tail) ? head - tail : sz - tail;

	*num = cnt;
	return (struct rte_mbuf **)(_rte_ring_get_data(r) + tail);
}

static inline void
tcp_txq_set_nxt_head(struct tle_tcp_stream *s, uint32_t num)
{
	struct rte_ring *r;

	r = s->tx.q;
	r->cons.head += num;
}

static inline void
tcp_txq_rst_nxt_head(struct tle_tcp_stream *s)
{
	struct rte_ring *r;

	r = s->tx.q;
	r->cons.head = r->cons.tail;
}

static inline void
tcp_txq_set_una_tail(struct tle_tcp_stream *s, uint32_t num)
{
	struct rte_ring *r;

	r = s->tx.q;
	rte_smp_rmb();
	r->cons.tail += num;
}

static inline uint32_t
tcp_txq_nxt_cnt(struct tle_tcp_stream *s)
{
	struct rte_ring *r;

	r = s->tx.q;
	return (r->prod.tail - r->cons.head) & _rte_ring_get_mask(r);
}

static inline void
txs_enqueue(struct tle_ctx *ctx, struct tle_tcp_stream *s)
{
	struct rte_ring *r;
	uint32_t n;

	if (rte_atomic32_add_return(&s->tx.arm, 1) == 1) {
		r = CTX_TCP_TSQ(ctx);
		n = _rte_ring_enqueue_burst(r, (void * const *)&s, 1);
		RTE_VERIFY(n == 1);
	}
}

static inline uint32_t
txs_dequeue_bulk(struct tle_ctx *ctx, struct tle_tcp_stream *s[], uint32_t num)
{
	struct rte_ring *r;

	r = CTX_TCP_TSQ(ctx);
	return _rte_ring_dequeue_burst(r, (void **)s, num);
}

#ifdef __cplusplus
}
#endif

#endif /* _TCP_TXQ_H_ */

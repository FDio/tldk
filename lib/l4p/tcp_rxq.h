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

#ifndef _TCP_RXQ_H_
#define _TCP_RXQ_H_

#include "tcp_ctl.h"
#include "tcp_ofo.h"

#ifdef __cplusplus
extern "C" {
#endif

struct rxq_objs {
	struct rte_mbuf **mb;
	uint32_t num;
};

static inline uint32_t
rx_ofo_enqueue(struct tle_tcp_stream *s, union seqlen *sl,
	struct rte_mbuf *mb[], uint32_t num)
{
	uint32_t i, n;

	n = 0;
	do {
		i = _ofo_step(s->rx.ofo, sl, mb + n, num - n);
		n += i;
	} while (i != 0 && n != num);

	_ofo_compact(s->rx.ofo);
	return n;
}

static inline uint32_t
rx_ofo_reduce(struct tle_tcp_stream *s)
{
	uint32_t i, n, seq;
	struct ofo *ofo;
	struct ofodb *db;

	seq = s->tcb.rcv.nxt;
	ofo = s->rx.ofo;

	if (ofo->nb_elem == 0)
		return 0;

	n = 0;
	for (i = 0; i != ofo->nb_elem; i++) {

		db = ofo->db + i;

		/* gap still present */
		if (tcp_seq_lt(seq, db->sl.seq))
			break;

		/* this db is fully overlapped */
		if (tcp_seq_leq(db->sl.seq + db->sl.len, seq))
			_ofodb_free(db);
		else
			n += _ofodb_enqueue(s->rx.q, db, &seq);
	}

	s->tcb.rcv.nxt = seq;
	_ofo_remove(ofo, 0, i);
	return n;
}

static inline uint32_t
rx_ino_enqueue(struct tle_tcp_stream *s, union seqlen *sl,
	struct rte_mbuf *mb[], uint32_t num)
{
	uint32_t i, n;

	n = _rte_ring_enqueue_burst(s->rx.q, (void * const *)mb, num);

	/* error: can'queue some packets into receive buffer. */
	for (i = n; i != num; i++)
		sl->len -= mb[i]->pkt_len;

	s->tcb.rcv.nxt = sl->seq + sl->len;
	s->tcb.rcv.wnd = calc_rcv_wnd(s);
	return n;
}

static inline uint32_t
rx_data_enqueue(struct tle_tcp_stream *s, uint32_t seq, uint32_t len,
	struct rte_mbuf *mb[], uint32_t num)
{
	uint32_t n, r, t;
	union seqlen sl;

	sl.seq = seq;
	sl.len = len;

	r = rte_ring_count(s->rx.q);

	/* in order packets, ready to be delivered */
	if (seq == s->tcb.rcv.nxt) {

		t = rx_ino_enqueue(s, &sl, mb, num);

		/* failed to queue all input in-order packets */
		if (t != num)
			TCP_LOG(DEBUG,
			"%s(s=%p, seq=%u, len=%u, num=%u) failed to queue "
			"%u packets;\n",
			__func__, s, seq, len, num, num - t);

		/* try to consume some out-of-order packets*/
		else {
			n = rx_ofo_reduce(s);
			if (n != 0)
				TCP_LOG(DEBUG,
				"%s(s=%p, rcv.nxt=%u) failed to queue %u "
				"OFO packets;\n",
				__func__, s, s->tcb.rcv.nxt, n);
		}

	/* queue out of order packets */
	} else {
		t = rx_ofo_enqueue(s, &sl, mb, num);
	}

	n = rte_ring_count(s->rx.q);
	if (r != n) {
		/* raise RX event */
		if (s->rx.ev != NULL)
			tle_event_raise(s->rx.ev);
		/* if RX queue was empty invoke RX notification callback. */
		else if (s->rx.cb.func != NULL && r == 0)
			s->rx.cb.func(s->rx.cb.data, &s->s);
	}

	return t;
}

static inline uint32_t
tcp_rxq_get_objs(struct tle_tcp_stream *s, struct rxq_objs obj[2])
{
	struct rte_ring *r;
	uint32_t n, head, sz;

	r = s->rx.q;

	n = _rte_ring_mcs_dequeue_start(r, UINT32_MAX);
	if (n == 0)
		return 0;

	sz = _rte_ring_get_size(r);
	head = (r->cons.head - n) & _rte_ring_get_mask(r);

	obj[0].mb = (struct rte_mbuf **)(_rte_ring_get_data(r) + head);
	obj[1].mb = (struct rte_mbuf **)_rte_ring_get_data(r);

	if (head + n <= sz) {
		obj[0].num = n;
		obj[1].num = 0;
		return 1;
	} else {
		obj[0].num = sz - head;
		obj[1].num = n + head - sz;
		return 2;
	}
}

static inline void
tcp_rxq_consume(struct tle_tcp_stream *s, uint32_t num)
{
	s->tcb.rcv.wnd = calc_rcv_wnd(s);
	_rte_ring_mcs_dequeue_finish(s->rx.q, num);
}

#ifdef __cplusplus
}
#endif

#endif /* _TCP_RXQ_H_ */

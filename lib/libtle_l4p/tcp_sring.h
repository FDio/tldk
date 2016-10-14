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

#ifndef _TCP_SRING_H_
#define _TCP_SRING_H_

#ifdef __cplusplus
extern "C" {
#endif

static inline uint32_t
tcp_rx_ino_enqueue(struct tle_tcp_stream *s, uint32_t seq, uint32_t len,
	struct rte_mbuf *mb[], uint32_t num)
{
	uint32_t i, n, r;
	n = rte_ring_enqueue_burst(s->rx.lq, (void * const *)mb, num); 
	r = rte_ring_count(s->rx.lq);

	/* error: can'queue some packets into receive buffer. */
	for (i = n; i != num; i++)
		len -= mb[i]->pkt_len;

	s->tcb.rcv.nxt = seq + len;

	/* raise RX event */
	if (s->rx.ev != NULL && r != 0)
		tle_event_raise(s->rx.ev);
		
	/* if RX queue was empty invoke user RX notification callback. */
        if (s->rx.cb.func != NULL && n != 0 && r == n)
                s->rx.cb.func(s->rx.cb.data, &s->s);

	return n;
}

#ifdef __cplusplus
}
#endif

#endif /* _TCP_SRING_H_ */

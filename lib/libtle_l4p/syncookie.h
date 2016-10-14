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

#ifndef _SYNCOOKIE_H_
#define _SYNCOOKIE_H_

#include "net_misc.h"

#ifdef __cplusplus
extern "C" {
#endif

/* !!! implement a proper syncookie sequence generation !!! */

#define	DUMMY_SYNCV	0xDEADBEEF
#define	DUMMY_SYNCR	0xDDADBEEF

static inline uint32_t
sync_gen_seq(const union pkt_info *pi, uint32_t seq)
{
	RTE_SET_USED(pi);
	return DUMMY_SYNCV + seq;
}

static inline uint32_t
sync_gen_ts(uint32_t wscale)
{
	return wscale;
}

static inline int
sync_check_ack(const struct rte_mbuf *mb)
{
	const struct tcp_hdr *th;

	th = rte_pktmbuf_mtod_offset(mb, const struct tcp_hdr *,
		mb->l2_len + mb->l3_len);

	if (DUMMY_SYNCR + th->sent_seq + 1 != rte_be_to_cpu_32(th->recv_ack))
		return -EINVAL;
	return 0;
}

static inline uint16_t
sync_get_mss(uint32_t seq)
{
	RTE_SET_USED(seq);
	return 0;
}

static inline void
sync_get_opts(uintptr_t p, struct syn_opts *so, uint32_t len)
{
	RTE_SET_USED(p);
	RTE_SET_USED(len);
	memset(so, 0, sizeof(*so));
}

static inline void
sync_fill_tcb(const struct rte_mbuf *mb, struct tcb *tcb)
{
	uint32_t ack, wnd;
	const struct tcp_hdr *th;

	th = rte_pktmbuf_mtod_offset(mb, const struct tcp_hdr *,
		mb->l2_len + mb->l3_len);

	tcb->rcv.nxt = rte_be_to_cpu_32(th->sent_seq);
	tcb->rcv.irs = tcb->rcv.nxt - 1;

	ack = rte_be_to_cpu_32(th->recv_ack);
	tcb->snd.nxt = ack;
	tcb->snd.una = ack;
	tcb->snd.iss = ack - 1;

	tcb->so.mss = sync_get_mss(ack);
	sync_get_opts((uintptr_t)(th + 1), &tcb->so, mb->l4_len - sizeof(*th));

	tcb->snd.wscale = tcb->so.wscale;
	tcb->snd.mss = tcb->so.mss;

	tcb->snd.ts = tcb->so.ts.ecr;
	tcb->rcv.ts = tcb->so.ts.val;

	wnd = rte_be_to_cpu_16(th->rx_win);
	tcb->snd.wnd = wnd << tcb->snd.wscale;
}

#ifdef __cplusplus
}
#endif

#endif /* _STREAM_TABLE_H_ */

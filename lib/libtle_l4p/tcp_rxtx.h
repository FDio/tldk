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

#ifndef _TCP_RXTX_H_
#define _TCP_RXTX_H_

#include "tcp_stream.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline uint32_t
calc_seg_cnt(uint32_t plen, uint32_t mss)
{
	if (plen > mss)
		return (plen + mss - 1) / mss;
	else
		return 1;
}

static inline uint32_t
get_ip_pid(struct tle_dev *dev, uint32_t num, uint32_t type, uint32_t st)
{
	uint32_t pid;
	rte_atomic32_t *pa;

	pa = &dev->tx.packet_id[type];

	if (st == 0) {
		pid = rte_atomic32_add_return(pa, num);
		return pid - num;
	} else {
		pid = rte_atomic32_read(pa);
		rte_atomic32_set(pa, pid + num);
		return pid;
	}
}

static inline void
fill_tcph(struct tcp_hdr *l4h, const struct tcb *tcb, union l4_ports port,
	uint32_t seq, uint8_t hlen, uint8_t flags)
{
	uint16_t wnd;

	l4h->src_port = port.dst;
	l4h->dst_port = port.src;

	wnd = (flags & TCP_FLAG_SYN) ?
		RTE_MIN(tcb->rcv.wnd, (uint32_t)UINT16_MAX) :
		tcb->rcv.wnd >> tcb->rcv.wscale;

	/* ??? use sse shuffle to hton all remaining 16 bytes at once. ??? */
	l4h->sent_seq = rte_cpu_to_be_32(seq);
	l4h->recv_ack = rte_cpu_to_be_32(tcb->rcv.nxt);
	l4h->data_off = hlen / TCP_DATA_ALIGN << TCP_DATA_OFFSET;
	l4h->tcp_flags = flags;
	l4h->rx_win = rte_cpu_to_be_16(wnd);
	l4h->cksum = 0;
	l4h->tcp_urp = 0;

	if (flags & TCP_FLAG_SYN)
		fill_syn_opts(l4h + 1, &tcb->so);
	else if ((flags & TCP_FLAG_RST) == 0 && tcb->so.ts.raw != 0)
		fill_tms_opts(l4h + 1, tcb->snd.ts, tcb->rcv.ts);
}

static inline int
tcp_fill_mbuf(struct rte_mbuf *m, const struct tle_tcp_stream *s,
	const struct tle_dest *dst, uint64_t ol_flags,
	union l4_ports port, uint32_t seq, uint32_t flags,
	uint32_t pid, uint32_t swcsm)
{
	uint32_t l4, len, plen;
	struct tcp_hdr *l4h;
	char *l2h, *l3;

	len = dst->l2_len + dst->l3_len;
	plen = m->pkt_len;

	if (flags & TCP_FLAG_SYN) {
		/* basic length */
		l4 = sizeof(*l4h) + TCP_OPT_LEN_MSS;

		/* add wscale space and nop  */
		if (s->tcb.so.wscale) {
			l4 += TCP_OPT_LEN_WSC + TCP_OPT_LEN_NOP;
		}

		/* add timestamp space and nop  */
		if (s->tcb.so.ts.raw) {
			l4 += TCP_TX_OPT_LEN_TMS;
		}
	} else if ((flags & TCP_FLAG_RST) == 0 && s->tcb.rcv.ts != 0) {
		l4 = sizeof(*l4h) + TCP_TX_OPT_LEN_TMS;
	} else {
		l4 = sizeof(*l4h);
	}

	/* adjust mbuf to put L2/L3/L4 headers into it. */
	l2h = rte_pktmbuf_prepend(m, len + l4);
	if (l2h == NULL)
		return -EINVAL;

	/* copy L2/L3 header */
	rte_memcpy(l2h, dst->hdr, len);

	/* setup TCP header & options */
	l4h = (struct tcp_hdr *)(l2h + len);
	fill_tcph(l4h, &s->tcb, port, seq, l4, flags);

	/* setup mbuf TX offload related fields. */
	m->tx_offload = _mbuf_tx_offload(dst->l2_len, dst->l3_len, l4, 0, 0, 0);
	m->ol_flags |= ol_flags;

	/* update proto specific fields. */

	l3 = l2h + dst->l2_len;
	if (((struct ipv4_hdr*)l3)->version_ihl>>4 == 4) {
		struct ipv4_hdr *l3h;
		l3h = (struct ipv4_hdr *)l3;
		l3h->packet_id = rte_cpu_to_be_16(pid);
		l3h->total_length = rte_cpu_to_be_16(plen + dst->l3_len + l4);

		if ((ol_flags & PKT_TX_TCP_CKSUM) != 0)
			l4h->cksum = _ipv4x_phdr_cksum(l3h, m->l3_len,
				ol_flags);
		else if (swcsm != 0)
			l4h->cksum = _ipv4_udptcp_mbuf_cksum(m, len, l3h);

		if ((ol_flags & PKT_TX_IP_CKSUM) == 0 && swcsm != 0)
			l3h->hdr_checksum = _ipv4x_cksum(l3h, m->l3_len);
	} else {
		struct ipv6_hdr *l3h;
		l3h = (struct ipv6_hdr *)l3;
		l3h->payload_len = rte_cpu_to_be_16(plen + l4);
		if ((ol_flags & PKT_TX_TCP_CKSUM) != 0)
			l4h->cksum = rte_ipv6_phdr_cksum(l3h, ol_flags);
		else if (swcsm != 0)
			l4h->cksum = _ipv6_udptcp_mbuf_cksum(m, len, l3h);
	}

	return 0;
}

static inline int
stream_drb_empty(struct tle_tcp_stream *s)
{
	return rte_ring_empty(s->tx.drb.r);
}

static inline void
stream_drb_free(struct tle_tcp_stream *s, struct tle_drb *drbs[],
	uint32_t nb_drb)
{
	_rte_ring_enqueue_burst(s->tx.drb.r, (void **)drbs, nb_drb);
}

static inline uint32_t
stream_drb_alloc(struct tle_tcp_stream *s, struct tle_drb *drbs[],
	uint32_t nb_drb)
{
	return _rte_ring_dequeue_burst(s->tx.drb.r, (void **)drbs, nb_drb);
}

/*
 * queue standalone packet to he particular output device
 * It assumes that:
 * - L2/L3/L4 headers should be already set.
 * - packet fits into one segment.
 */
static inline int
send_pkt(struct tle_tcp_stream *s, struct tle_dev *dev, struct rte_mbuf *m)
{
	uint32_t n, nb;
	struct tle_drb *drb;

	if (stream_drb_alloc(s, &drb, 1) == 0)
		return -ENOBUFS;

	/* enqueue pkt for TX. */
	nb = 1;
	n = tle_dring_mp_enqueue(&dev->tx.dr, (const void * const*)&m, 1,
		&drb, &nb);

	/* free unused drbs. */
	if (nb != 0)
		stream_drb_free(s, &drb, 1);

	return (n == 1) ? 0 : -ENOBUFS;
}

#define TCP_OLFLAGS_CKSUM(flags) (flags & (PKT_TX_IP_CKSUM | PKT_TX_TCP_CKSUM))

static inline int
send_ctrl_pkt(struct tle_tcp_stream *s, struct rte_mbuf *m, uint32_t seq,
	uint32_t flags)
{
	const struct tle_dest *dst;
	uint32_t pid, type;
	int32_t rc;

	dst = &s->tx.dst;
	type = s->s.type;
	pid = get_ip_pid(dst->dev, 1, type, (s->flags & TLE_CTX_FLAG_ST) != 0);

	rc = tcp_fill_mbuf(m, s, dst, TCP_OLFLAGS_CKSUM(dst->ol_flags),
			   s->s.port, seq, flags, pid, 1);
	if (rc == 0)
		rc = send_pkt(s, dst->dev, m);

	return rc;
}

static inline int
send_rst(struct tle_tcp_stream *s, uint32_t seq)
{
	struct rte_mbuf *m;
	int32_t rc;

	m = rte_pktmbuf_alloc(s->tx.dst.head_mp);
	if (m == NULL)
		return -ENOMEM;

	rc = send_ctrl_pkt(s, m, seq, TCP_FLAG_RST | TCP_FLAG_ACK);
	if (rc != 0)
		rte_pktmbuf_free(m);
	else
		TCP_INC_STATS(TCP_MIB_OUTRSTS);

	return rc;
}



#ifdef __cplusplus
}
#endif

#endif /* _TCP_RXTX_H_ */

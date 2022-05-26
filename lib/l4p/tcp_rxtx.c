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

#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_ip_frag.h>
#include <rte_tcp.h>

#include "tcp_stream.h"
#include "tcp_timer.h"
#include "stream_table.h"
#include "syncookie.h"
#include "misc.h"
#include "tcp_ctl.h"
#include "tcp_rxq.h"
#include "tcp_txq.h"
#include "tcp_tx_seg.h"

#define	TCP_MAX_PKT_SEG	0x20

/*
 * checks if input TCP ports and IP addresses match given stream.
 * returns zero on success.
 */
static inline int
rx_check_stream(const struct tle_tcp_stream *s, const union pkt_info *pi)
{
	int32_t rc;

	if (pi->tf.type == TLE_V4)
		rc = (pi->port.raw & s->s.pmsk.raw) != s->s.port.raw ||
			(pi->addr4.raw & s->s.ipv4.mask.raw) !=
			s->s.ipv4.addr.raw;
	else
		rc = (pi->port.raw & s->s.pmsk.raw) != s->s.port.raw ||
			ymm_mask_cmp(&pi->addr6->raw, &s->s.ipv6.addr.raw,
			&s->s.ipv6.mask.raw) != 0;

	return rc;
}

static inline struct tle_tcp_stream *
rx_obtain_listen_stream(const struct tle_dev *dev, const union pkt_info *pi,
	uint32_t type)
{
	struct tle_tcp_stream *s;

	s = (struct tle_tcp_stream *)dev->dp[type]->streams[pi->port.dst];
	if (s == NULL || tcp_stream_acquire(s) < 0)
		return NULL;

	/* check that we have a proper stream. */
	if (s->tcb.state != TLE_TCP_ST_LISTEN) {
		tcp_stream_release(s);
		s = NULL;
	}

	return s;
}

static inline struct tle_tcp_stream *
rx_acquire_stream(struct tle_stream *ts)
{
	struct tle_tcp_stream *s;

	s = TCP_STREAM(ts);
	if (tcp_stream_acquire(s) < 0)
		return NULL;

	else if (s->tcb.state == TLE_TCP_ST_CLOSED) {
		tcp_stream_release(s);
		return NULL;
	}

	return s;
}

static inline struct tle_tcp_stream *
rx_obtain_stream(const struct tle_dev *dev, struct stbl *st,
	const union pkt_info *pi, uint32_t type)
{
	struct tle_tcp_stream *s;

	s = stbl_find_data(st, pi);
	if (s == NULL) {
		if (pi->tf.flags == TCP_FLAG_ACK)
			return rx_obtain_listen_stream(dev, pi, type);
		return NULL;
	}

	if (tcp_stream_acquire(s) < 0)
		return NULL;
	/* check that we have a proper stream. */
	else if (s->tcb.state == TLE_TCP_ST_CLOSED) {
		tcp_stream_release(s);
		s = NULL;
	}

	return s;
}

/*
 * Consider 2 pkt_info *equal* if their:
 * - types (IPv4/IPv6)
 * - TCP flags
 * - checksum flags
 * - TCP src and dst ports
 * - IP src and dst addresses
 * are equal.
 */
static inline int
pkt_info_bulk_eq(const union pkt_info pi[], uint32_t num)
{
	uint32_t i;

	i = 1;

	if (pi[0].tf.type == TLE_V4) {
		while (i != num && xmm_cmp(&pi[0].raw, &pi[i].raw) == 0)
			i++;

	} else if (pi[0].tf.type == TLE_V6) {
		while (i != num &&
				pi[0].raw.u64[0] == pi[i].raw.u64[0] &&
				ymm_cmp(&pi[0].addr6->raw,
				&pi[i].addr6->raw) == 0)
			i++;
	}

	return i;
}

static inline int
pkt_info_bulk_syneq(const union pkt_info pi[], uint32_t num)
{
	uint32_t i;

	i = 1;

	if (pi[0].tf.type == TLE_V4) {
		while (i != num && pi[0].tf.raw == pi[i].tf.raw &&
				pi[0].port.dst == pi[i].port.dst &&
				pi[0].addr4.dst == pi[i].addr4.dst)
			i++;

	} else if (pi[0].tf.type == TLE_V6) {
		while (i != num && pi[0].tf.raw == pi[i].tf.raw &&
				pi[0].port.dst == pi[i].port.dst &&
				xmm_cmp(&pi[0].addr6->dst,
				&pi[i].addr6->dst) == 0)
			i++;
	}

	return i;
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

static inline uint32_t
tcp_stream_adjust_tms(const struct tle_tcp_stream *s, uint32_t tms)
{
	return tms - s->ts_offset;
}

static inline void
fill_tcph(struct rte_tcp_hdr *l4h, const struct tcb *tcb, union l4_ports port,
	uint32_t seq, uint8_t hlen, uint8_t flags)
{
	uint16_t wnd;

	l4h->src_port = port.dst;
	l4h->dst_port = port.src;

	wnd = calc_pkt_rx_wnd(tcb, flags);

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
	struct rte_tcp_hdr *l4h;
	char *l2h;

	len = dst->l2_len + dst->l3_len;
	plen = m->pkt_len;

	if (flags & TCP_FLAG_SYN)
		l4 = sizeof(*l4h) + TCP_TX_OPT_LEN_MAX;
	else if ((flags & TCP_FLAG_RST) == 0 && s->tcb.rcv.ts != 0)
		l4 = sizeof(*l4h) + TCP_TX_OPT_LEN_TMS;
	else
		l4 = sizeof(*l4h);

	/* adjust mbuf to put L2/L3/L4 headers into it. */
	l2h = rte_pktmbuf_prepend(m, len + l4);
	if (l2h == NULL)
		return -EINVAL;

	/* copy L2/L3 header */
	rte_memcpy(l2h, dst->hdr, len);

	/* setup TCP header & options */
	l4h = (struct rte_tcp_hdr *)(l2h + len);
	fill_tcph(l4h, &s->tcb, port, seq, l4, flags);

	/* setup mbuf TX offload related fields. */
	m->tx_offload = _mbuf_tx_offload(dst->l2_len, dst->l3_len, l4, 0, 0, 0);
	m->ol_flags |= ol_flags;

	/* update proto specific fields. */

	if (s->s.type == TLE_V4) {
		struct rte_ipv4_hdr *l3h;
		l3h = (struct rte_ipv4_hdr *)(l2h + dst->l2_len);
		l3h->packet_id = rte_cpu_to_be_16(pid);
		l3h->total_length = rte_cpu_to_be_16(plen + dst->l3_len + l4);

		if ((ol_flags & RTE_MBUF_F_TX_TCP_CKSUM) != 0)
			l4h->cksum = _ipv4x_phdr_cksum(l3h, m->l3_len,
				ol_flags);
		else if (swcsm != 0)
			l4h->cksum = _ipv4_udptcp_mbuf_cksum(m, len, l3h);

		if ((ol_flags & RTE_MBUF_F_TX_IP_CKSUM) == 0 && swcsm != 0)
			l3h->hdr_checksum = _ipv4x_cksum(l3h, m->l3_len);
	} else {
		struct rte_ipv6_hdr *l3h;
		l3h = (struct rte_ipv6_hdr *)(l2h + dst->l2_len);
		l3h->payload_len = rte_cpu_to_be_16(plen + l4);
		if ((ol_flags & RTE_MBUF_F_TX_TCP_CKSUM) != 0)
			l4h->cksum = rte_ipv6_phdr_cksum(l3h, ol_flags);
		else if (swcsm != 0)
			l4h->cksum = _ipv6_udptcp_mbuf_cksum(m, len, l3h);
	}

	return 0;
}

/*
 * That function supposed to be used only for data packets.
 * Assumes that L2/L3/L4 headers and mbuf fields already setup properly.
 *  - updates tcp SEG.SEQ, SEG.ACK, TS.VAL, TS.ECR.
 *  - if no HW cksum offloads are enabled, calculates TCP checksum.
 */
static inline void
tcp_update_mbuf(struct rte_mbuf *m, uint32_t type, const struct tcb *tcb,
	uint32_t seq, uint32_t pid, uint8_t tcp_flags)
{
	struct rte_tcp_hdr *l4h;
	uint32_t len;
	uint16_t wnd;

	len = m->l2_len + m->l3_len;
	l4h = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *, len);

	wnd = calc_pkt_rx_wnd(tcb, tcp_flags);

	l4h->sent_seq = rte_cpu_to_be_32(seq);
	l4h->recv_ack = rte_cpu_to_be_32(tcb->rcv.nxt);
	l4h->rx_win = rte_cpu_to_be_16(wnd);

	l4h->tcp_flags |= tcp_flags;

	if (tcb->so.ts.raw != 0)
		fill_tms_opts(l4h + 1, tcb->snd.ts, tcb->rcv.ts);

	if (type == TLE_V4) {
		struct rte_ipv4_hdr *l3h;
		l3h = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *,
			m->l2_len);
		l3h->hdr_checksum = 0;
		l3h->packet_id = rte_cpu_to_be_16(pid);
		if ((m->ol_flags & RTE_MBUF_F_TX_IP_CKSUM) == 0)
			l3h->hdr_checksum = _ipv4x_cksum(l3h, m->l3_len);
	}

	/* have to calculate TCP checksum in SW */
	if ((m->ol_flags & RTE_MBUF_F_TX_TCP_CKSUM) == 0) {

		l4h->cksum = 0;

		if (type == TLE_V4) {
			struct rte_ipv4_hdr *l3h;
			l3h = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *,
				m->l2_len);
			l4h->cksum = _ipv4_udptcp_mbuf_cksum(m, len, l3h);

		} else {
			struct rte_ipv6_hdr *l3h;
			l3h = rte_pktmbuf_mtod_offset(m, struct rte_ipv6_hdr *,
				m->l2_len);
			l4h->cksum = _ipv6_udptcp_mbuf_cksum(m, len, l3h);
		}
	}
}

/* Send data packets that need to be ACK-ed by peer */
static inline uint32_t
tx_data_pkts(struct tle_tcp_stream *s, struct rte_mbuf *const m[], uint32_t num)
{
	uint32_t bsz, i, nb, nbm;
	struct tle_dev *dev;
	struct tle_drb *drb[num];

	/* calculate how many drbs are needed.*/
	bsz = s->tx.drb.nb_elem;
	nbm = (num + bsz - 1) / bsz;

	/* allocate drbs, adjust number of packets. */
	nb = stream_drb_alloc(s, drb, nbm);

	/* drb ring is empty. */
	if (nb == 0)
		return 0;

	else if (nb != nbm)
		num = nb * bsz;

	dev = s->tx.dst.dev;

	/* enqueue pkts for TX. */
	nbm = nb;
	i = tle_dring_mp_enqueue(&dev->tx.dr, (const void * const*)m,
		num, drb, &nb);

	/* free unused drbs. */
	if (nb != 0)
		stream_drb_free(s, drb + nbm - nb, nb);

	return i;
}

static inline uint32_t
tx_data_bulk(struct tle_tcp_stream *s, union seqlen *sl, struct rte_mbuf *mi[],
	uint32_t num)
{
	uint32_t fail, i, k, n, mss, pid, plen, sz, tn, type;
	struct tle_dev *dev;
	struct rte_mbuf *mb;
	struct rte_mbuf *mo[MAX_PKT_BURST + TCP_MAX_PKT_SEG];
	uint8_t tcp_flags;

	mss = s->tcb.snd.mss;
	type = s->s.type;

	dev = s->tx.dst.dev;
	pid = get_ip_pid(dev, num, type, (s->flags & TLE_CTX_FLAG_ST) != 0);

	k = 0;
	tn = 0;
	fail = 0;
	tcp_flags = 0x0;

	for (i = 0; i != num && sl->len != 0 && fail == 0; i++) {

		mb = mi[i];
		sz = RTE_MIN(sl->len, mss);
		plen = PKT_L4_PLEN(mb);

		/*fast path, no need to use indirect mbufs. */
		if (plen <= sz) {

			if (i == (num - 1)) {
				tcp_flags |= TCP_FLAG_PSH;
			}

			/* update pkt TCP header */
			tcp_update_mbuf(mb, type, &s->tcb, sl->seq, pid + i, tcp_flags);

			/* keep mbuf till ACK is received. */
			rte_pktmbuf_refcnt_update(mb, 1);
			sl->len -= plen;
			sl->seq += plen;
			mo[k++] = mb;
		/* remaining snd.wnd is less them MSS, send nothing */
		} else if (sz < mss)
			break;
		/* packet indirection needed */
		else
			RTE_VERIFY(0);

		if (k >= MAX_PKT_BURST) {
			n = tx_data_pkts(s, mo, k);
			fail = k - n;
			tn += n;
			k = 0;
		}
	}

	if (k != 0) {
		n = tx_data_pkts(s, mo, k);
		fail = k - n;
		tn += n;
	}

	if (fail != 0) {
		sz = tcp_mbuf_seq_free(mo + n, fail);
		sl->seq -= sz;
		sl->len += sz;
	}

	return tn;
}

/*
 * gets data from stream send buffer, updates it and
 * queues it into TX device queue.
 * Note that this function and is not MT safe.
 */
static inline uint32_t
tx_nxt_data(struct tle_tcp_stream *s, uint32_t tms)
{
	uint32_t n, num, tn, wnd;
	struct rte_mbuf **mi;
	union seqlen sl;

	tn = 0;
	wnd = s->tcb.snd.wnd - (uint32_t)(s->tcb.snd.nxt - s->tcb.snd.una);
	sl.seq = s->tcb.snd.nxt;
	sl.len = RTE_MIN(wnd, s->tcb.snd.cwnd);

	if (sl.len == 0)
		return tn;

	/* update send timestamp */
	s->tcb.snd.ts = tms;

	do {
		/* get group of packets */
		mi = tcp_txq_get_nxt_objs(s, &num);

		/* stream send buffer is empty */
		if (num == 0)
			break;

		/* queue data packets for TX */
		n = tx_data_bulk(s, &sl, mi, num);
		tn += n;

		/* update consumer head */
		tcp_txq_set_nxt_head(s, n);
	} while (n == num);

	s->tcb.snd.nxt += sl.seq - (uint32_t)s->tcb.snd.nxt;
	return tn;
}

static inline void
free_una_data(struct tle_tcp_stream *s, uint32_t len)
{
	uint32_t i, num, plen;
	struct rte_mbuf **mi;

	plen = 0;

	do {
		/* get group of packets */
		mi = tcp_txq_get_una_objs(s, &num);

		if (num == 0)
			break;

		/* free acked data */
		for (i = 0; i != num && plen != len; i++) {
			uint32_t next_pkt_len = PKT_L4_PLEN(mi[i]);
			if (plen + next_pkt_len > len) {
				/* keep SND.UNA at the start of the packet */
				len = plen;
				break;
			} else {
				plen += next_pkt_len;
			}
			rte_pktmbuf_free(mi[i]);
		}

		/* update consumer tail */
		tcp_txq_set_una_tail(s, i);
	} while (plen < len);

	s->tcb.snd.una += len;

	/*
	 * that could happen in case of retransmit,
	 * adjust SND.NXT with SND.UNA.
	 */
	if (s->tcb.snd.una > s->tcb.snd.nxt) {
		tcp_txq_rst_nxt_head(s);
		s->tcb.snd.nxt = s->tcb.snd.una;
	}
}

static inline uint16_t
calc_smss(uint16_t mss, const struct tle_dest *dst)
{
	uint16_t n;

	n = dst->mtu - dst->l2_len - dst->l3_len - TCP_TX_HDR_DACK;
	mss = RTE_MIN(n, mss);
	return mss;
}

/*
 * RFC 6928 2
 * min (10*MSS, max (2*MSS, 14600))
 *
 * or using user provided initial congestion window (icw)
 * min (10*MSS, max (2*MSS, icw))
 */
static inline uint32_t
initial_cwnd(uint32_t smss, uint32_t icw)
{
	return RTE_MIN(10 * smss, RTE_MAX(2 * smss, icw));
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

	rc = tcp_fill_mbuf(m, s, dst, 0, s->s.port, seq, flags, pid, 1);
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

	rc = send_ctrl_pkt(s, m, seq, TCP_FLAG_RST);
	if (rc != 0)
		rte_pktmbuf_free(m);

	return rc;
}

static inline int
send_ack(struct tle_tcp_stream *s, uint32_t tms, uint32_t flags)
{
	struct rte_mbuf *m;
	uint32_t seq;
	int32_t rc;

	m = rte_pktmbuf_alloc(s->tx.dst.head_mp);
	if (m == NULL)
		return -ENOMEM;

	seq = s->tcb.snd.nxt - ((flags & (TCP_FLAG_FIN | TCP_FLAG_SYN)) != 0);
	s->tcb.snd.ts = tms;

	rc = send_ctrl_pkt(s, m, seq, flags);
	if (rc != 0) {
		rte_pktmbuf_free(m);
		return rc;
	}

	s->tcb.snd.ack = s->tcb.rcv.nxt;
	return 0;
}


static int
sync_ack(struct tle_tcp_stream *s, const union pkt_info *pi,
	const union seg_info *si, uint32_t ts, struct rte_mbuf *m)
{
	uint16_t len;
	int32_t rc;
	uint32_t pid, seq, type;
	struct tle_dev *dev;
	const void *da;
	struct tle_dest dst;
	const struct rte_tcp_hdr *th;

	type = s->s.type;

	/* get destination information. */
	if (type == TLE_V4)
		da = &pi->addr4.src;
	else
		da = &pi->addr6->src;

	rc = stream_get_dest(&s->s, da, &dst);
	if (rc < 0)
		return rc;

	th = rte_pktmbuf_mtod_offset(m, const struct rte_tcp_hdr *,
		m->l2_len + m->l3_len);
	get_syn_opts(&s->tcb.so, (uintptr_t)(th + 1), m->l4_len - sizeof(*th));

	/* reset wscale option if timestamp is not present */
	if (s->tcb.so.ts.val == 0)
		s->tcb.so.wscale = 0;

	s->tcb.rcv.nxt = si->seq + 1;
	seq = sync_gen_seq(pi, s->tcb.rcv.nxt, ts, s->tcb.so.mss,
				s->s.ctx->prm.hash_alg,
				&s->s.ctx->prm.secret_key);
	s->tcb.so.ts.ecr = s->tcb.so.ts.val;
	s->tcb.so.ts.val = sync_gen_ts(ts, s->tcb.so.wscale);
	s->tcb.so.wscale = (s->tcb.so.wscale == TCP_WSCALE_NONE) ?
		TCP_WSCALE_NONE : TCP_WSCALE_DEFAULT;
	s->tcb.so.mss = calc_smss(dst.mtu, &dst);

	/* reset mbuf's data contents. */
	len = m->l2_len + m->l3_len + m->l4_len;
	m->tx_offload = 0;
	if (rte_pktmbuf_adj(m, len) == NULL)
		return -EINVAL;

	dev = dst.dev;
	pid = get_ip_pid(dev, 1, type, (s->flags & TLE_CTX_FLAG_ST) != 0);

	rc = tcp_fill_mbuf(m, s, &dst, 0, pi->port, seq,
		TCP_FLAG_SYN | TCP_FLAG_ACK, pid, 1);
	if (rc == 0)
		rc = send_pkt(s, dev, m);

	return rc;
}

/*
 * RFC 793:
 * There are four cases for the acceptability test for an incoming segment:
 * Segment Receive  Test
 * Length  Window
 * ------- -------  -------------------------------------------
 *    0       0     SEG.SEQ = RCV.NXT
 *    0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
 *   >0       0     not acceptable
 *   >0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
 *                  or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
 */
static inline int
check_seqn(const struct tcb *tcb, uint32_t seqn, uint32_t len)
{
	uint32_t n;

	n = seqn + len;
	if (seqn - tcb->rcv.nxt >= tcb->rcv.wnd &&
			n - tcb->rcv.nxt > tcb->rcv.wnd)
		return -ERANGE;

	return 0;
}

static inline union tle_tcp_tsopt
rx_tms_opt(const struct tcb *tcb, const struct rte_mbuf *mb)
{
	union tle_tcp_tsopt ts;
	uintptr_t opt;
	const struct rte_tcp_hdr *th;

	if (tcb->so.ts.val != 0) {
		opt = rte_pktmbuf_mtod_offset(mb, uintptr_t,
			mb->l2_len + mb->l3_len + sizeof(*th));
		ts = get_tms_opts(opt, mb->l4_len - sizeof(*th));
	} else
		ts.raw = 0;

	return ts;
}

/*
 * PAWS and sequence check.
 * RFC 1323 4.2.1
 */
static inline int
rx_check_seq(struct tcb *tcb, uint32_t seq, uint32_t len,
	const union tle_tcp_tsopt ts)
{
	int32_t rc;

	/* RFC 1323 4.2.1 R2 */
	rc = check_seqn(tcb, seq, len);
	if (rc < 0)
		return rc;

	if (ts.raw != 0) {

		/* RFC 1323 4.2.1 R1 */
		if (tcp_seq_lt(ts.val, tcb->rcv.ts))
			return -ERANGE;

		/* RFC 1323 4.2.1 R3 */
		if (tcp_seq_leq(seq, tcb->snd.ack) &&
				tcp_seq_lt(tcb->snd.ack, seq + len))
			tcb->rcv.ts = ts.val;
	}

	return rc;
}

static inline int
rx_check_ack(const struct tcb *tcb, uint32_t ack)
{
	uint32_t max;

	max = (uint32_t)RTE_MAX(tcb->snd.nxt, tcb->snd.rcvr);

	if (tcp_seq_leq(tcb->snd.una, ack) && tcp_seq_leq(ack, max))
		return 0;

	return -ERANGE;
}

static inline int
rx_check_seqack(struct tcb *tcb, uint32_t seq, uint32_t ack, uint32_t len,
	const union tle_tcp_tsopt ts)
{
	int32_t rc;

	rc = rx_check_seq(tcb, seq, len, ts);
	rc |= rx_check_ack(tcb, ack);
	return rc;
}

static inline int
restore_syn_opt(union seg_info *si, union tle_tcp_tsopt *to,
	const union pkt_info *pi, uint32_t ts, const struct rte_mbuf *mb,
	uint32_t hash_alg, rte_xmm_t *secret_key)
{
	int32_t rc;
	uint32_t len;
	const struct rte_tcp_hdr *th;

	/* check that ACK, etc fields are what we expected. */
	rc = sync_check_ack(pi, si->seq, si->ack - 1, ts,
				hash_alg,
				secret_key);
	if (rc < 0)
		return rc;

	si->mss = rc;

	th = rte_pktmbuf_mtod_offset(mb, const struct rte_tcp_hdr *,
		mb->l2_len + mb->l3_len);
	len = mb->l4_len - sizeof(*th);
	to[0] = get_tms_opts((uintptr_t)(th + 1), len);
	return 0;
}

static inline void
stream_term(struct tle_tcp_stream *s)
{
	struct sdr *dr;

	s->tcb.state = TLE_TCP_ST_CLOSED;
	rte_smp_wmb();

	timer_stop(s);

	/* close() was already invoked, schedule final cleanup */
	if ((s->tcb.uop & TLE_TCP_OP_CLOSE) != 0) {

		dr = CTX_TCP_SDR(s->s.ctx);
		STAILQ_INSERT_TAIL(&dr->be, &s->s, link);

	/* notify user that stream need to be closed */
	} else if (s->err.ev != NULL)
		tle_event_raise(s->err.ev);
	else if (s->err.cb.func != NULL)
		s->err.cb.func(s->err.cb.data, &s->s);
}

static inline int
stream_fill_dest(struct tle_tcp_stream *s)
{
	int32_t rc;
	uint32_t type;
	const void *da;

        type = s->s.type;
	if (type == TLE_V4)
		da = &s->s.ipv4.addr.src;
	else
		da = &s->s.ipv6.addr.src;

	rc = stream_get_dest(&s->s, da, &s->tx.dst);
	return (rc < 0) ? rc : 0;
}

/*
 * estimate the rto
 * for now rtt is calculated based on the tcp TMS option,
 * later add real-time one
 */
static inline void
estimate_stream_rto(struct tle_tcp_stream *s, uint32_t tms)
{
	uint32_t rtt;

	if (s->tcb.so.ts.ecr) {
		rtt = tms - s->tcb.so.ts.ecr;
		rto_estimate(&s->tcb, rtt);
	} else
		s->tcb.snd.rto = TCP_RTO_DEFAULT;
}

/*
 * helper function, prepares a new accept stream.
 */
static inline int
accept_prep_stream(struct tle_tcp_stream *ps, struct stbl *st,
	struct tle_tcp_stream *cs, const union tle_tcp_tsopt *to,
	uint32_t tms, const union pkt_info *pi, const union seg_info *si)
{
	int32_t rc;

	/* some TX still pending for that stream. */
	if (TCP_STREAM_TX_PENDING(cs))
		return -EAGAIN;

	/* setup L4 ports and L3 addresses fields. */
	cs->s.port.raw = pi->port.raw;
	cs->s.pmsk.raw = UINT32_MAX;

	if (pi->tf.type == TLE_V4) {
		cs->s.ipv4.addr = pi->addr4;
		cs->s.ipv4.mask.src = INADDR_NONE;
		cs->s.ipv4.mask.dst = INADDR_NONE;
	} else if (pi->tf.type == TLE_V6) {
		cs->s.ipv6.addr = *pi->addr6;
		rte_memcpy(&cs->s.ipv6.mask.src, &tle_ipv6_none,
			sizeof(cs->s.ipv6.mask.src));
		rte_memcpy(&cs->s.ipv6.mask.dst, &tle_ipv6_none,
			sizeof(cs->s.ipv6.mask.dst));
	}

	/* setup TCB */
	sync_fill_tcb(&cs->tcb, si, to);
	cs->tcb.rcv.wnd = calc_rcv_wnd_max(cs);

	estimate_stream_rto(cs, tms);

	/* copy streams type & flags. */
	cs->s.type = ps->s.type;
	cs->flags = ps->flags;

	/* retrive and cache destination information. */
	rc = stream_fill_dest(cs);
	if (rc != 0)
		return rc;

	/* update snd.mss with SMSS value */
	cs->tcb.snd.mss = calc_smss(cs->tcb.snd.mss, &cs->tx.dst);

	/* setup congestion variables */
	cs->tcb.snd.cwnd = initial_cwnd(cs->tcb.snd.mss, ps->tcb.snd.cwnd);
	cs->tcb.snd.ssthresh = cs->tcb.snd.wnd;
	cs->tcb.snd.rto_tw = ps->tcb.snd.rto_tw;

	cs->tcb.state = TLE_TCP_ST_ESTABLISHED;

	/* add stream to the table */
	cs->ste = stbl_add_stream(st, pi, cs);
	if (cs->ste == NULL)
		return -ENOBUFS;

	cs->tcb.uop |= TLE_TCP_OP_ACCEPT;
	tcp_stream_up(cs);
	return 0;
}


/*
 * ACK for new connection request arrived.
 * Check that the packet meets all conditions and try to open a new stream.
 * returns:
 * < 0  - invalid packet
 * == 0 - packet is valid and new stream was opened for it.
 * > 0  - packet is valid, but failed to open new stream.
 */
static inline int
rx_ack_listen(struct tle_tcp_stream *s, struct stbl *st,
	const union pkt_info *pi, union seg_info *si,
	uint32_t tms, struct rte_mbuf *mb, struct tle_tcp_stream **csp)
{
	int32_t rc;
	struct tle_ctx *ctx;
	struct tle_stream *ts;
	struct tle_tcp_stream *cs;
	union tle_tcp_tsopt to;

	*csp = NULL;

	if (pi->tf.flags != TCP_FLAG_ACK || rx_check_stream(s, pi) != 0)
		return -EINVAL;

	ctx = s->s.ctx;
	rc = restore_syn_opt(si, &to, pi, tms, mb, ctx->prm.hash_alg,
				&ctx->prm.secret_key);
	if (rc < 0)
		return rc;

	/* allocate new stream */
	cs = tcp_stream_get(ctx, 0);
	if (cs == NULL)
		return ENFILE;

	/* prepare stream to handle new connection */
	if (accept_prep_stream(s, st, cs, &to, tms, pi, si) == 0) {

		/* put new stream in the accept queue */
		ts = &cs->s;
		if (_rte_ring_enqueue_burst(s->rx.q,
				(void * const *)&ts, 1) == 1) {
			*csp = cs;
			return 0;
		}

		/* cleanup on failure */
		tcp_stream_down(cs);
		stbl_del_stream(st, cs->ste, cs, 0);
		cs->ste = NULL;
	}

	tcp_stream_reset(ctx, cs);
	return ENOBUFS;
}

static inline int
data_pkt_adjust(const struct tcb *tcb, struct rte_mbuf **mb, uint32_t hlen,
	uint32_t *seqn, uint32_t *plen)
{
	uint32_t len, n, seq;

	seq = *seqn;
	len = *plen;

	rte_pktmbuf_adj(*mb, hlen);
	if (len == 0)
		return -ENODATA;
	/* cut off the start of the packet */
	else if (tcp_seq_lt(seq, tcb->rcv.nxt)) {
		n = tcb->rcv.nxt - seq;
		if (n >= len)
			return -ENODATA;

		*mb = _rte_pktmbuf_adj(*mb, n);
		*seqn = seq + n;
		*plen = len - n;
	}

	return 0;
}

static inline uint32_t
rx_ackdata(struct tle_tcp_stream *s, uint32_t ack)
{
	uint32_t k, n;

	n = ack - (uint32_t)s->tcb.snd.una;

	/* some more data was acked. */
	if (n != 0) {

		/* advance SND.UNA and free related packets. */
		k = rte_ring_free_count(s->tx.q);
		free_una_data(s, n);

		/* mark the stream as available for writing */
		if (rte_ring_free_count(s->tx.q) != 0) {
			if (s->tx.ev != NULL)
				tle_event_raise(s->tx.ev);
			else if (k == 0 && s->tx.cb.func != NULL)
				s->tx.cb.func(s->tx.cb.data, &s->s);
		}
	}

	return n;
}

static void
stream_timewait(struct tle_tcp_stream *s, uint32_t rto)
{
	if (rto != 0) {
		s->tcb.state = TLE_TCP_ST_TIME_WAIT;
		s->tcb.snd.rto = rto;
		timer_reset(s);
	} else
		stream_term(s);
}

static void
rx_fin_state(struct tle_tcp_stream *s, struct resp_info *rsp)
{
	uint32_t state;
	int32_t ackfin;

	s->tcb.rcv.nxt += 1;
	s->err.rev |= TLE_TCP_REV_FIN;

	ackfin = (s->tcb.snd.una == s->tcb.snd.fss);
	state = s->tcb.state;

	if (state == TLE_TCP_ST_ESTABLISHED) {
		s->tcb.state = TLE_TCP_ST_CLOSE_WAIT;
		/* raise err.ev & err.cb */
		if (s->err.ev != NULL)
			tle_event_raise(s->err.ev);
		else if (s->err.cb.func != NULL)
			s->err.cb.func(s->err.cb.data, &s->s);
	} else if (state == TLE_TCP_ST_FIN_WAIT_1 ||
			state == TLE_TCP_ST_CLOSING) {
		rsp->flags |= TCP_FLAG_ACK;
		if (ackfin != 0)
			stream_timewait(s, s->tcb.snd.rto_tw);
		else
			s->tcb.state = TLE_TCP_ST_CLOSING;
	} else if (state == TLE_TCP_ST_FIN_WAIT_2) {
		rsp->flags |= TCP_FLAG_ACK;
		stream_timewait(s, s->tcb.snd.rto_tw);
	} else if (state == TLE_TCP_ST_LAST_ACK && ackfin != 0) {
		stream_term(s);
	}
}

/*
 * FIN process for ESTABLISHED state
 * returns:
 * 0 < - error occurred
 * 0 - FIN was processed OK, and mbuf can be free/reused.
 * 0 > - FIN was processed OK and mbuf can't be free/reused.
 */
static inline int
rx_fin(struct tle_tcp_stream *s, uint32_t state,
	const union seg_info *si, struct rte_mbuf *mb,
	struct resp_info *rsp)
{
	uint32_t hlen, plen, seq;
	int32_t ret;
	union tle_tcp_tsopt ts;

	hlen = PKT_L234_HLEN(mb);
	plen = mb->pkt_len - hlen;
	seq = si->seq;

	ts = rx_tms_opt(&s->tcb, mb);
	ret = rx_check_seqack(&s->tcb, seq, si->ack, plen, ts);
	if (ret != 0)
		return ret;

	if (state < TLE_TCP_ST_ESTABLISHED)
		return -EINVAL;

	if (plen != 0) {

		ret = data_pkt_adjust(&s->tcb, &mb, hlen, &seq, &plen);
		if (ret != 0)
			return ret;
		if (rx_data_enqueue(s, seq, plen, &mb, 1) != 1)
			return -ENOBUFS;
	}

	/*
	 * fast-path: all data & FIN was already sent out
	 * and now is acknowledged.
	 */
	if (s->tcb.snd.fss == s->tcb.snd.nxt &&
			si->ack == (uint32_t)s->tcb.snd.nxt) {
		s->tcb.snd.una = s->tcb.snd.fss;
		empty_tq(s);
	/* conventional ACK processiing */
	} else
		rx_ackdata(s, si->ack);

	/* some fragments still missing */
	if (seq + plen != s->tcb.rcv.nxt) {
		s->tcb.rcv.frs.seq = seq + plen;
		s->tcb.rcv.frs.on = 1;
	} else
		rx_fin_state(s, rsp);

	return plen;
}

static inline int
rx_rst(struct tle_tcp_stream *s, uint32_t state, uint32_t flags,
	const union seg_info *si)
{
	int32_t rc;

	/*
	 * RFC 793: In all states except SYN-SENT, all reset (RST) segments
	 * are validated by checking their SEQ-fields.
	 * A reset is valid if its sequence number is in the window.
	 * In the SYN-SENT state (a RST received in response to an initial SYN),
	 * the RST is acceptable if the ACK field acknowledges the SYN.
	 */
	if (state == TLE_TCP_ST_SYN_SENT) {
		rc = ((flags & TCP_FLAG_ACK) == 0 ||
				si->ack != s->tcb.snd.nxt) ?
			-ERANGE : 0;
	}

	else
		rc = check_seqn(&s->tcb, si->seq, 0);

	if (rc == 0) {
		s->err.rev |= TLE_TCP_REV_RST;
		stream_term(s);
	}

	return rc;
}

/*
 *  check do we have FIN  that was received out-of-order.
 *  if yes, try to process it now.
 */
static inline void
rx_ofo_fin(struct tle_tcp_stream *s, struct resp_info *rsp)
{
	if (s->tcb.rcv.frs.on != 0 && s->tcb.rcv.nxt == s->tcb.rcv.frs.seq)
		rx_fin_state(s, rsp);
}

static inline void
dack_info_init(struct dack_info *tack, const struct tcb *tcb)
{
	static const struct dack_info zero_dack;

	tack[0] = zero_dack;
	tack->ack = tcb->snd.una;
	tack->segs.dup = tcb->rcv.dupack;
	tack->wu.raw = tcb->snd.wu.raw;
	tack->wnd = tcb->snd.wnd >> tcb->snd.wscale;
}

static inline void
ack_window_update(struct tcb *tcb, const struct dack_info *tack)
{
	tcb->snd.wu.raw = tack->wu.raw;
	tcb->snd.wnd = tack->wnd << tcb->snd.wscale;
}

static inline void
ack_cwnd_update(struct tcb *tcb, uint32_t acked, const struct dack_info *tack)
{
	uint32_t n;

	n = tack->segs.ack * tcb->snd.mss;

	/* slow start phase, RFC 5681 3.1 (2)  */
	if (tcb->snd.cwnd < tcb->snd.ssthresh)
		tcb->snd.cwnd += RTE_MIN(acked, n);
	/* congestion avoidance phase, RFC 5681 3.1 (3) */
	else
		tcb->snd.cwnd += RTE_MAX(1U, n * tcb->snd.mss / tcb->snd.cwnd);
}

static inline void
rto_ssthresh_update(struct tcb *tcb)
{
	uint32_t k, n;

	/* RFC 5681 3.1 (4)  */
	n = (tcb->snd.nxt - tcb->snd.una) / 2;
	k = 2 * tcb->snd.mss;
	tcb->snd.ssthresh = RTE_MAX(n, k);
}

static inline void
rto_cwnd_update(struct tcb *tcb)
{

	if (tcb->snd.nb_retx == 0)
		rto_ssthresh_update(tcb);

	/*
	 * RFC 5681 3.1: upon a timeout cwnd MUST be set to
	 * no more than 1 full-sized segment.
	 */
	tcb->snd.cwnd = tcb->snd.mss;
}

static inline void
ack_info_update(struct dack_info *tack, const union seg_info *si,
	int32_t badseq, uint32_t dlen, const union tle_tcp_tsopt ts)
{
	if (badseq != 0) {
		tack->segs.badseq++;
		return;
	}

	/* segnt with incoming data */
	tack->segs.data += (dlen != 0);

	/* segment with newly acked data */
	if (tcp_seq_lt(tack->ack, si->ack)) {
		tack->segs.dup = 0;
		tack->segs.ack++;
		tack->ack = si->ack;
		tack->ts = ts;

	/*
	 * RFC 5681: An acknowledgment is considered a "duplicate" when:
	 * (a) the receiver of the ACK has outstanding data
	 * (b) the incoming acknowledgment carries no data
	 * (c) the SYN and FIN bits are both off
	 * (d) the acknowledgment number is equal to the TCP.UNA
	 * (e) the advertised window in the incoming acknowledgment equals the
	 * advertised window in the last incoming acknowledgment.
	 *
	 * Here will have only to check only for (b),(d),(e).
	 * (a) will be checked later for the whole bulk of packets,
	 * (c) should never happen here.
	 */
	} else if (dlen == 0 && si->wnd == tack->wnd && ++tack->segs.dup == 3) {
		tack->dup3.seg = tack->segs.ack + 1;
		tack->dup3.ack = tack->ack;
	}

	/*
	 * RFC 793:
	 * If SND.UNA < SEG.ACK =< SND.NXT, the send window should be
	 * updated.  If (SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ and
	 * SND.WL2 =< SEG.ACK)), set SND.WND <- SEG.WND, set
	 * SND.WL1 <- SEG.SEQ, and set SND.WL2 <- SEG.ACK.
	 */
	if (tcp_seq_lt(tack->wu.wl1, si->seq) ||
			(si->seq == tack->wu.wl1 &&
			tcp_seq_leq(tack->wu.wl2, si->ack))) {

		tack->wu.wl1 = si->seq;
		tack->wu.wl2 = si->ack;
		tack->wnd = si->wnd;
	}
}

static inline uint32_t
rx_data_ack(struct tle_tcp_stream *s, struct dack_info *tack,
	const union seg_info si[], struct rte_mbuf *mb[], struct rte_mbuf *rp[],
	int32_t rc[], uint32_t num)
{
	uint32_t i, j, k, n, t;
	uint32_t hlen, plen, seq, tlen;
	int32_t ret;
	union tle_tcp_tsopt ts;

	k = 0;
	for (i = 0; i != num; i = j) {

		hlen = PKT_L234_HLEN(mb[i]);
		plen = mb[i]->pkt_len - hlen;
		seq = si[i].seq;

		ts = rx_tms_opt(&s->tcb, mb[i]);
		ret = rx_check_seqack(&s->tcb, seq, si[i].ack, plen, ts);

		/* account segment received */
		ack_info_update(tack, &si[i], ret != 0, plen, ts);

		if (ret == 0) {
			/* skip duplicate data, if any */
			ret = data_pkt_adjust(&s->tcb, &mb[i], hlen,
				&seq, &plen);
		}

		j = i + 1;
		if (ret != 0) {
			rp[k] = mb[i];
			rc[k] = -ret;
			k++;
			continue;
		}

		/* group sequential packets together. */
		for (tlen = plen; j != num; tlen += plen, j++) {

			hlen = PKT_L234_HLEN(mb[j]);
			plen = mb[j]->pkt_len - hlen;

			/* not consecutive packet */
			if (plen == 0 || seq + tlen != si[j].seq)
				break;

			/* check SEQ/ACK */
			ts = rx_tms_opt(&s->tcb, mb[j]);
			ret = rx_check_seqack(&s->tcb, si[j].seq, si[j].ack,
				plen, ts);

			if (ret != 0)
				break;

			/* account for segment received */
			ack_info_update(tack, &si[j], ret != 0, plen, ts);

			rte_pktmbuf_adj(mb[j], hlen);
		}

		n = j - i;

		/* account for OFO data */
		if (seq != s->tcb.rcv.nxt)
			tack->segs.ofo += n;

		/* enqueue packets */
		t = rx_data_enqueue(s, seq, tlen, mb + i, n);

		/* if we are out of space in stream recv buffer. */
		for (; t != n; t++) {
			rp[k] = mb[i + t];
			rc[k] = -ENOBUFS;
			k++;
		}
	}

	return num - k;
}

static inline void
start_fast_retransmit(struct tle_tcp_stream *s)
{
	struct tcb *tcb;

	tcb = &s->tcb;

	/* RFC 6582 3.2.2 */
	tcb->snd.rcvr = tcb->snd.nxt;
	tcb->snd.fastack = 1;

	/* RFC 5681 3.2.2 */
	rto_ssthresh_update(tcb);

	/* RFC 5681 3.2.3 */
	tcp_txq_rst_nxt_head(s);
	tcb->snd.nxt = tcb->snd.una;
	tcb->snd.cwnd = tcb->snd.ssthresh + 3 * tcb->snd.mss;
}

static inline void
stop_fast_retransmit(struct tle_tcp_stream *s)
{
	struct tcb *tcb;
	uint32_t n;

	tcb = &s->tcb;
	n = tcb->snd.nxt - tcb->snd.una;
	tcb->snd.cwnd = RTE_MIN(tcb->snd.ssthresh,
		RTE_MAX(n, tcb->snd.mss) + tcb->snd.mss);
	tcb->snd.fastack = 0;
}

static inline int
in_fast_retransmit(struct tle_tcp_stream *s, uint32_t ack_len, uint32_t ack_num,
	uint32_t dup_num)
{
	uint32_t n;
	struct tcb *tcb;

	tcb = &s->tcb;

	/* RFC 5682 3.2.3 partial ACK */
	if (ack_len != 0) {

		n = ack_num * tcb->snd.mss;
		if (ack_len >= n)
			tcb->snd.cwnd -= ack_len - n;
		else
			tcb->snd.cwnd -= ack_len % tcb->snd.mss;

		/*
		 * For the first partial ACK that arrives
		 * during fast recovery, also reset the
		 * retransmit timer.
		 */
		if (tcb->snd.fastack == 1)
			timer_reset(s);

		tcb->snd.fastack += ack_num;
		return 1;

	/* RFC 5681 3.2.4 */
	} else if (dup_num > 3) {
		s->tcb.snd.cwnd += (dup_num - 3) * tcb->snd.mss;
		return 1;
	}

	return 0;
}

static inline int
process_ack(struct tle_tcp_stream *s, uint32_t acked,
	const struct dack_info *tack)
{
	int32_t send;

	send = 0;

	/* normal mode */
	if (s->tcb.snd.fastack == 0) {

		send = 1;

		/* RFC 6582 3.2.2 switch to fast retransmit mode */
		if (tack->dup3.seg != 0 && s->tcb.snd.una != s->tcb.snd.nxt &&
				s->tcb.snd.una >= s->tcb.snd.rcvr) {

			start_fast_retransmit(s);
			in_fast_retransmit(s,
				tack->ack - tack->dup3.ack,
				tack->segs.ack - tack->dup3.seg - 1,
				tack->segs.dup);

		/* remain in normal mode */
		} else if (acked != 0) {
			ack_cwnd_update(&s->tcb, acked, tack);
			timer_stop(s);
		}

	/* fast retransmit mode */
	} else {

		/* remain in fast retransmit mode */
		if (s->tcb.snd.una < s->tcb.snd.rcvr) {

			send = in_fast_retransmit(s, acked, tack->segs.ack,
				tack->segs.dup);
		} else {
			/* RFC 5682 3.2.3 full ACK */
			stop_fast_retransmit(s);
			timer_stop(s);

			/* if we have another series of dup ACKs */
			if (tack->dup3.seg != 0 &&
					s->tcb.snd.una != s->tcb.snd.nxt &&
					tcp_seq_leq((uint32_t)s->tcb.snd.rcvr,
					tack->dup3.ack)) {

				/* restart fast retransmit again. */
				start_fast_retransmit(s);
				send = in_fast_retransmit(s,
					tack->ack - tack->dup3.ack,
					tack->segs.ack - tack->dup3.seg - 1,
					tack->segs.dup);
			}
		}
	}

	return send;
}

/*
 * our FIN was acked, stop rto timer, change stream state,
 * and possibly close the stream.
 */
static inline void
rx_ackfin(struct tle_tcp_stream *s)
{
	uint32_t state;

	s->tcb.snd.una = s->tcb.snd.fss;
	empty_tq(s);

	state = s->tcb.state;
	if (state == TLE_TCP_ST_LAST_ACK)
		stream_term(s);
	else if (state == TLE_TCP_ST_FIN_WAIT_1) {
		timer_stop(s);
		s->tcb.state = TLE_TCP_ST_FIN_WAIT_2;
	} else if (state == TLE_TCP_ST_CLOSING) {
		stream_timewait(s, s->tcb.snd.rto_tw);
	}
}

static inline void
rx_process_ack(struct tle_tcp_stream *s, uint32_t ts,
	const struct dack_info *tack)
{
	int32_t send;
	uint32_t n;

	s->tcb.rcv.dupack = tack->segs.dup;

	n = rx_ackdata(s, tack->ack);
	send = process_ack(s, n, tack);

	/* try to send more data. */
	if ((n != 0 || send != 0) && tcp_txq_nxt_cnt(s) != 0)
		txs_enqueue(s->s.ctx, s);

	/* restart RTO timer. */
	if (s->tcb.snd.nxt != s->tcb.snd.una)
		timer_start(s);

	/* update rto, if fresh packet is here then calculate rtt */
	if (tack->ts.ecr != 0)
		rto_estimate(&s->tcb, ts - tack->ts.ecr);
}

/*
 * process <SYN,ACK>
 * returns negative value on failure, or zero on success.
 */
static inline int
rx_synack(struct tle_tcp_stream *s, uint32_t ts, uint32_t state,
	const union seg_info *si, struct rte_mbuf *mb,
	struct resp_info *rsp)
{
	struct tle_tcp_syn_opts so;
	struct rte_tcp_hdr *th;

	if (state != TLE_TCP_ST_SYN_SENT)
		return -EINVAL;

	/*
	 * RFC 793 3.9: in the SYN-SENT state
	 * If SEG.ACK =< ISS, or SEG.ACK > SND.NXT, send a reset
	 * <SEQ=SEG.ACK><CTL=RST>
	 * and discard the segment.
	 * The connection remains in the same state.
	 */
	if (si->ack != (uint32_t)s->tcb.snd.nxt) {
		send_rst(s, si->ack);
		return 0;
	}

	th = rte_pktmbuf_mtod_offset(mb, struct rte_tcp_hdr *,
		mb->l2_len + mb->l3_len);
	get_syn_opts(&so, (uintptr_t)(th + 1), mb->l4_len - sizeof(*th));

	s->tcb.so = so;

	s->tcb.snd.una = s->tcb.snd.nxt;
	s->tcb.snd.mss = calc_smss(so.mss, &s->tx.dst);
	s->tcb.snd.wnd = si->wnd << so.wscale;
	s->tcb.snd.wu.wl1 = si->seq;
	s->tcb.snd.wu.wl2 = si->ack;
	s->tcb.snd.wscale = so.wscale;

	/* setup congestion variables */
	s->tcb.snd.cwnd = initial_cwnd(s->tcb.snd.mss, s->tcb.snd.cwnd);
	s->tcb.snd.ssthresh = s->tcb.snd.wnd;

	s->tcb.rcv.ts = so.ts.val;
	s->tcb.rcv.irs = si->seq;
	s->tcb.rcv.nxt = si->seq + 1;

	/* if peer doesn't support WSCALE opt, recalculate RCV.WND */
	s->tcb.rcv.wscale = (so.wscale == TCP_WSCALE_NONE) ?
		TCP_WSCALE_NONE : TCP_WSCALE_DEFAULT;
	/* need to know wscale first to pick max rcv.wnd */
	s->tcb.rcv.wnd = calc_rcv_wnd_max(s);

	/* calculate initial rto */
	rto_estimate(&s->tcb, ts - s->tcb.snd.ts);

	rsp->flags |= TCP_FLAG_ACK;

	timer_stop(s);
	s->tcb.state = TLE_TCP_ST_ESTABLISHED;
	rte_smp_wmb();

	if (s->tx.ev != NULL)
		tle_event_raise(s->tx.ev);
	else if (s->tx.cb.func != NULL)
		s->tx.cb.func(s->tx.cb.data, &s->s);

	return 0;
}

static inline uint32_t
rx_stream(struct tle_tcp_stream *s, uint32_t ts,
	const union pkt_info *pi, const union seg_info si[],
	struct rte_mbuf *mb[], struct rte_mbuf *rp[], int32_t rc[],
	uint32_t num)
{
	uint32_t i, k, n, state;
	int32_t ret;
	struct resp_info rsp;
	struct dack_info tack;

	k = 0;
	rsp.flags = 0;

	state = s->tcb.state;

	/*
	 * first check for the states/flags where we don't
	 * expect groups of packets.
	 */

	/* process RST */
	if ((pi->tf.flags & TCP_FLAG_RST) != 0) {
		for (i = 0;
				i != num &&
				rx_rst(s, state, pi->tf.flags, &si[i]);
				i++)
			;
		i = 0;

	/* RFC 793: if the ACK bit is off drop the segment and return */
	} else if ((pi->tf.flags & TCP_FLAG_ACK) == 0) {
		i = 0;
	/*
	 * first check for the states/flags where we don't
	 * expect groups of packets.
	 */

	/* process <SYN,ACK> */
	} else if ((pi->tf.flags & TCP_FLAG_SYN) != 0) {
		for (i = 0; i != num; i++) {
			ret = rx_synack(s, ts, state, &si[i], mb[i], &rsp);
			if (ret == 0)
				break;

			rc[k] = -ret;
			rp[k] = mb[i];
			k++;
		}

	/* process FIN */
	} else if ((pi->tf.flags & TCP_FLAG_FIN) != 0) {
		ret = 0;
		for (i = 0; i != num; i++) {
			ret = rx_fin(s, state, &si[i], mb[i], &rsp);
			if (ret >= 0)
				break;

			rc[k] = -ret;
			rp[k] = mb[i];
			k++;
		}
		i += (ret > 0);

	/* normal data/ack packets */
	} else if (state >= TLE_TCP_ST_ESTABLISHED &&
			state <= TLE_TCP_ST_LAST_ACK) {

		/* process incoming data packets. */
		dack_info_init(&tack, &s->tcb);
		n = rx_data_ack(s, &tack, si, mb, rp, rc, num);

		/* follow up actions based on aggregated information */

		/* update SND.WND */
		ack_window_update(&s->tcb, &tack);

		/*
		 * fast-path: all data & FIN was already sent out
		 * and now is acknowledged.
		 */
		if (s->tcb.snd.fss == s->tcb.snd.nxt &&
				tack.ack == (uint32_t)s->tcb.snd.nxt)
			rx_ackfin(s);
		else
			rx_process_ack(s, ts, &tack);

		/*
		 * send an immediate ACK if either:
		 * - received segment with invalid seq/ack number
		 * - received segment with OFO data
		 * - received segment with INO data and no TX is scheduled
		 *   for that stream.
		 */
		if (tack.segs.badseq != 0 || tack.segs.ofo != 0 ||
				(tack.segs.data != 0 &&
				rte_atomic32_read(&s->tx.arm) == 0))
			rsp.flags |= TCP_FLAG_ACK;

		rx_ofo_fin(s, &rsp);

		k += num - n;
		i = num;

	/* unhandled state, drop all packets. */
	} else
		i = 0;

	/* we have a response packet to send. */
	if (rsp.flags != 0) {
		send_ack(s, ts, rsp.flags);

		/* start the timer for FIN packet */
		if ((rsp.flags & TCP_FLAG_FIN) != 0)
			timer_reset(s);
	}

	/* unprocessed packets */
	for (; i != num; i++, k++) {
		rc[k] = ENODATA;
		rp[k] = mb[i];
	}

	return num - k;
}

static inline uint32_t
rx_new_stream(struct tle_tcp_stream *s, uint32_t ts,
	const union pkt_info *pi, const union seg_info si[],
	struct rte_mbuf *mb[], struct rte_mbuf *rp[], int32_t rc[],
	uint32_t num)
{
	uint32_t i;

	if (tcp_stream_acquire(s) > 0) {
		i = rx_stream(s, ts, pi, si, mb, rp, rc, num);
		tcp_stream_release(s);
		return i;
	}

	for (i = 0; i != num; i++) {
		rc[i] = ENOENT;
		rp[i] = mb[i];
	}
	return 0;
}

static inline uint32_t
rx_postsyn(struct tle_dev *dev, struct stbl *st, uint32_t type, uint32_t ts,
	const union pkt_info pi[], union seg_info si[],
	struct rte_mbuf *mb[], struct rte_mbuf *rp[], int32_t rc[],
	uint32_t num)
{
	struct tle_tcp_stream *cs, *s;
	uint32_t i, k, n, state;
	int32_t ret;

	s = rx_obtain_stream(dev, st, &pi[0], type);
	if (s == NULL) {
		for (i = 0; i != num; i++) {
			rc[i] = ENOENT;
			rp[i] = mb[i];
		}
		return 0;
	}

	k = 0;
	state = s->tcb.state;

	if (state == TLE_TCP_ST_LISTEN) {

		/* one connection per flow */
		cs = NULL;
		ret = -EINVAL;
		for (i = 0; i != num; i++) {

			ret = rx_ack_listen(s, st, pi, &si[i], ts, mb[i], &cs);

			/* valid packet encountered */
			if (ret >= 0)
				break;

			/* invalid packet, keep trying to find a proper one */
			rc[k] = -ret;
			rp[k] = mb[i];
			k++;
		}

		/* packet is valid, but we are out of streams to serve it */
		if (ret > 0) {
			for (; i != num; i++, k++) {
				rc[k] = ret;
				rp[k] = mb[i];
			}
		/* new stream is accepted */
		} else if (ret == 0) {

			/* inform listen stream about new connections */
			if (s->rx.ev != NULL)
				tle_event_raise(s->rx.ev);
			else if (s->rx.cb.func != NULL &&
					rte_ring_count(s->rx.q) == 1)
				s->rx.cb.func(s->rx.cb.data, &s->s);

			/* if there is no data, drop current packet */
			if (PKT_L4_PLEN(mb[i]) == 0) {
				rc[k] = ENODATA;
				rp[k++] = mb[i++];
			}

			/*  process remaining packets for that stream */
			if (num != i) {
				n = rx_new_stream(cs, ts, pi + i, si + i,
					mb + i, rp + k, rc + k, num - i);
				k += num - n - i;
			}
		}

	} else {
		i = rx_stream(s, ts, pi, si, mb, rp, rc, num);
		k = num - i;
	}

	tcp_stream_release(s);
	return num - k;
}


static inline uint32_t
rx_syn(struct tle_dev *dev, uint32_t type, uint32_t ts,
	const union pkt_info pi[], const union seg_info si[],
	struct rte_mbuf *mb[], struct rte_mbuf *rp[], int32_t rc[],
	uint32_t num)
{
	struct tle_tcp_stream *s;
	uint32_t i, k;
	int32_t ret;

	s = rx_obtain_listen_stream(dev, &pi[0], type);
	if (s == NULL) {
		for (i = 0; i != num; i++) {
			rc[i] = ENOENT;
			rp[i] = mb[i];
		}
		return 0;
	}

	k = 0;
	for (i = 0; i != num; i++) {

		/* check that this remote is allowed to connect */
		if (rx_check_stream(s, &pi[i]) != 0)
			ret = -ENOENT;
		else
			/* syncokie: reply with <SYN,ACK> */
			ret = sync_ack(s, &pi[i], &si[i], ts, mb[i]);

		if (ret != 0) {
			rc[k] = -ret;
			rp[k] = mb[i];
			k++;
		}
	}

	tcp_stream_release(s);
	return num - k;
}

uint16_t
tle_tcp_rx_bulk(struct tle_dev *dev, struct rte_mbuf *pkt[],
	struct rte_mbuf *rp[], int32_t rc[], uint16_t num)
{
	struct stbl *st;
	struct tle_ctx *ctx;
	uint32_t i, j, k, mt, n, t, ts;
	union pkt_info pi[num];
	union seg_info si[num];
	union {
		uint8_t t[TLE_VNUM];
		uint32_t raw;
	} stu;

	ctx = dev->ctx;
	ts = tcp_get_tms(ctx->cycles_ms_shift);
	st = CTX_TCP_STLB(ctx);
	mt = ((ctx->prm.flags & TLE_CTX_FLAG_ST) == 0);

	stu.raw = 0;

	/* extract packet info and check the L3/L4 csums */
	for (i = 0; i != num; i++) {

		get_pkt_info(pkt[i], &pi[i], &si[i]);

		t = pi[i].tf.type;
		pi[i].csf = check_pkt_csum(pkt[i], pi[i].csf, t, IPPROTO_TCP);
		stu.t[t] = mt;
	}

	if (stu.t[TLE_V4] != 0)
		stbl_lock(st, TLE_V4);
	if (stu.t[TLE_V6] != 0)
		stbl_lock(st, TLE_V6);

	k = 0;
	for (i = 0; i != num; i += j) {

		t = pi[i].tf.type;

		/*basic checks for incoming packet */
		if (t >= TLE_VNUM || pi[i].csf != 0 || dev->dp[t] == NULL) {
			rc[k] = EINVAL;
			rp[k] = pkt[i];
			j = 1;
			k++;
		/* process input SYN packets */
		} else if (pi[i].tf.flags == TCP_FLAG_SYN) {
			j = pkt_info_bulk_syneq(pi + i, num - i);
			n = rx_syn(dev, t, ts, pi + i, si + i, pkt + i,
				rp + k, rc + k, j);
			k += j - n;
		} else {
			j = pkt_info_bulk_eq(pi + i, num - i);
			n = rx_postsyn(dev, st, t, ts, pi + i, si + i, pkt + i,
				rp + k, rc + k, j);
			k += j - n;
		}
	}

	if (stu.t[TLE_V4] != 0)
		stbl_unlock(st, TLE_V4);
	if (stu.t[TLE_V6] != 0)
		stbl_unlock(st, TLE_V6);

	return num - k;
}

uint16_t
tle_tcp_stream_rx_bulk(struct tle_stream *ts, struct rte_mbuf *pkt[],
	struct rte_mbuf *rp[], int32_t rc[], uint16_t num)
{
	struct tle_ctx *ctx;
	struct tle_tcp_stream *s;
	uint32_t i, j, k, n, t, tms;
	union pkt_info pi[num];
	union seg_info si[num];

	ctx = ts->ctx;
	tms = tcp_get_tms(ctx->cycles_ms_shift);

	s = rx_acquire_stream(ts);
	if (s == NULL) {
		for (i = 0; i != num; i++) {
			rc[i] = ENOENT;
			rp[i] = pkt[i];
		}
		return 0;
	}

	tms = tcp_stream_adjust_tms(s, tms);

	/* extract packet info and check the L3/L4 csums */
	for (i = 0; i != num; i++) {
		get_pkt_info(pkt[i], &pi[i], &si[i]);
		pi[i].csf = check_pkt_csum(pkt[i], pi[i].csf, pi[i].tf.type,
			IPPROTO_TCP);
	}

	k = 0;
	for (i = 0; i != num; i += j) {

		t = pi[i].tf.type;
		j = 1;

		/*basic checks for incoming packet */
		if (t != ts->type || pi[i].csf != 0 ||
				 rx_check_stream(s, pi + i) != 0) {
			rc[k] = EINVAL;
			rp[k] = pkt[i];
			k++;
			continue;
		}

		j = pkt_info_bulk_eq(pi + i, num - i);
		n = rx_stream(s, tms, pi + i, si + i, pkt + i,
			rp + k, rc + k, j);
		k += j - n;
	}

	tcp_stream_release(s);
	return num - k;
}

uint16_t
tle_tcp_stream_accept(struct tle_stream *ts, struct tle_stream *rs[],
	uint32_t num)
{
	uint32_t n;
	struct tle_tcp_stream *s;
	struct tle_memtank *mts;

	s = TCP_STREAM(ts);
	n = _rte_ring_dequeue_burst(s->rx.q, (void **)rs, num);
	if (n == 0)
		return 0;

	mts = CTX_TCP_MTS(ts->ctx);

	/*
	 * if we still have packets to read,
	 * then rearm stream RX event.
	 */
	if (n == num && rte_ring_count(s->rx.q) != 0) {
		if (tcp_stream_try_acquire(s) > 0 && s->rx.ev != NULL)
			tle_event_raise(s->rx.ev);
		tcp_stream_release(s);
	}

	tle_memtank_grow(mts);
	return n;
}

uint16_t
tle_tcp_tx_bulk(struct tle_dev *dev, struct rte_mbuf *pkt[], uint16_t num)
{
	uint32_t i, j, k, n;
	struct tle_drb *drb[num];
	struct tle_tcp_stream *s;

	/* extract packets from device TX queue. */

	k = num;
	n = tle_dring_sc_dequeue(&dev->tx.dr, (const void **)(uintptr_t)pkt,
		num, drb, &k);

	if (n == 0)
		return 0;

	/* free empty drbs and notify related streams. */

	for (i = 0; i != k; i = j) {
		s = drb[i]->udata;
		for (j = i + 1; j != k && s == drb[j]->udata; j++)
			;
		stream_drb_free(s, drb + i, j - i);
	}

	return n;
}

static inline void
stream_fill_pkt_info(const struct tle_tcp_stream *s, union pkt_info *pi)
{
	if (s->s.type == TLE_V4)
		pi->addr4 = s->s.ipv4.addr;
	else
		pi->addr6 = &s->s.ipv6.addr;

	pi->port = s->s.port;
	pi->tf.type = s->s.type;
}

static int
stream_fill_addr(struct tle_tcp_stream *s, const struct sockaddr *addr)
{
	const struct sockaddr_in *in4;
	const struct sockaddr_in6 *in6;
	const struct tle_dev_param *prm;
	int32_t rc;

	rc = 0;
	s->s.pmsk.raw = UINT32_MAX;

	/* setup L4 src ports and src address fields. */
	if (s->s.type == TLE_V4) {
		in4 = (const struct sockaddr_in *)addr;
		if (in4->sin_addr.s_addr == INADDR_ANY || in4->sin_port == 0)
			return -EINVAL;

		s->s.port.src = in4->sin_port;
		s->s.ipv4.addr.src = in4->sin_addr.s_addr;
		s->s.ipv4.mask.src = INADDR_NONE;
		s->s.ipv4.mask.dst = INADDR_NONE;

	} else if (s->s.type == TLE_V6) {
		in6 = (const struct sockaddr_in6 *)addr;
		if (memcmp(&in6->sin6_addr, &tle_ipv6_any,
				sizeof(tle_ipv6_any)) == 0 ||
				in6->sin6_port == 0)
			return -EINVAL;

		s->s.port.src = in6->sin6_port;
		rte_memcpy(&s->s.ipv6.addr.src, &in6->sin6_addr,
			sizeof(s->s.ipv6.addr.src));
		rte_memcpy(&s->s.ipv6.mask.src, &tle_ipv6_none,
			sizeof(s->s.ipv6.mask.src));
		rte_memcpy(&s->s.ipv6.mask.dst, &tle_ipv6_none,
			sizeof(s->s.ipv6.mask.dst));
	}

	/* setup the destination device. */
	rc = stream_fill_dest(s);
	if (rc != 0)
		return rc;

	/* setup L4 dst address from device param */
	prm = &s->tx.dst.dev->prm;
	if (s->s.type == TLE_V4) {
		if (s->s.ipv4.addr.dst == INADDR_ANY)
			s->s.ipv4.addr.dst = prm->local_addr4.s_addr;
	} else if (memcmp(&s->s.ipv6.addr.dst, &tle_ipv6_any,
			sizeof(tle_ipv6_any)) == 0)
		memcpy(&s->s.ipv6.addr.dst, &prm->local_addr6,
			sizeof(s->s.ipv6.addr.dst));

	return rc;
}

static inline int
tx_syn(struct tle_tcp_stream *s, const struct sockaddr *addr)
{
	int32_t rc;
	uint32_t tms, seq;
	union pkt_info pi;
	struct stbl *st;
	struct stbl_entry *se;

	/* fill stream address */
	rc = stream_fill_addr(s, addr);
	if (rc != 0)
		return rc;

	/* fill pkt info to generate seq.*/
	stream_fill_pkt_info(s, &pi);

	tms = tcp_get_tms(s->s.ctx->cycles_ms_shift);
	s->tcb.so.ts.val = tms;
	s->tcb.so.ts.ecr = 0;
	s->tcb.so.wscale = TCP_WSCALE_DEFAULT;
	s->tcb.so.mss = calc_smss(s->tx.dst.mtu, &s->tx.dst);

	/* note that rcv.nxt is 0 here for sync_gen_seq.*/
	seq = sync_gen_seq(&pi, s->tcb.rcv.nxt, tms, s->tcb.so.mss,
				s->s.ctx->prm.hash_alg,
				&s->s.ctx->prm.secret_key);
	s->tcb.snd.iss = seq;
	s->tcb.snd.rcvr = seq;
	s->tcb.snd.una = seq;
	s->tcb.snd.nxt = seq + 1;
	s->tcb.snd.rto = TCP_RTO_DEFAULT;
	s->tcb.snd.ts = tms;

	s->tcb.rcv.mss = s->tcb.so.mss;
	s->tcb.rcv.wscale = TCP_WSCALE_DEFAULT;
	s->tcb.rcv.wnd = calc_rcv_wnd_max(s);
	s->tcb.rcv.ts = 0;

	/* add the stream in stream table */
	st = CTX_TCP_STLB(s->s.ctx);
	se = stbl_add_stream_lock(st, s);
	if (se == NULL)
		return -ENOBUFS;
	s->ste = se;

	/* put stream into the to-send queue */
	txs_enqueue(s->s.ctx, s);

	return 0;
}

int
tle_tcp_stream_connect(struct tle_stream *ts, const struct sockaddr *addr)
{
	struct tle_tcp_stream *s;
	uint32_t type;
	int32_t rc;

	if (ts == NULL || addr == NULL)
		return -EINVAL;

	s = TCP_STREAM(ts);
	type = s->s.type;
	if (type >= TLE_VNUM)
		return -EINVAL;

	if (tcp_stream_try_acquire(s) > 0) {
		rc = rte_atomic16_cmpset(&s->tcb.state, TLE_TCP_ST_CLOSED,
			TLE_TCP_ST_SYN_SENT);
		rc = (rc == 0) ? -EDEADLK : 0;
	} else
		rc = -EINVAL;

	if (rc != 0) {
		tcp_stream_release(s);
		return rc;
	}

	/* fill stream, prepare and transmit syn pkt */
	s->tcb.uop |= TLE_TCP_OP_CONNECT;
	rc = tx_syn(s, addr);
	tcp_stream_release(s);

	/* error happened, do a cleanup */
	if (rc != 0)
		tle_tcp_stream_close(ts);

	return rc;
}

/*
 * Helper function for tle_tcp_stream_establish().
 * updates stream's TCB.
 */
static inline void
tcb_establish(struct tle_tcp_stream *s, const struct tle_tcp_conn_info *ci)
{
	uint32_t mss, tms;

	tms = tcp_get_tms(s->s.ctx->cycles_ms_shift);

	/* set a default MSS if it is unset (0) */
	if ((ci->so.mss == 0) && (s->s.type == TLE_V4)) {
		mss = calc_smss(TCP4_MIN_MSS, &s->tx.dst);
	}
	else if ((ci->so.mss == 0) && (s->s.type == TLE_V6)) {
		mss = calc_smss(TCP6_MIN_MSS, &s->tx.dst);
	}
	else {
		mss = calc_smss(ci->so.mss, &s->tx.dst);
	}

	s->tcb.so = ci->so;
	fill_tcb_snd(&s->tcb, ci->ack, ci->seq, mss,
		ci->wnd, ci->so.wscale, &ci->so.ts);
	fill_tcb_rcv(&s->tcb, ci->ack, ci->so.l_wscale, &ci->so.ts);

	s->tcb.rcv.wnd = calc_rcv_wnd_max(s);

	/* setup congestion variables */
	s->tcb.snd.cwnd = initial_cwnd(s->tcb.snd.mss, s->tcb.snd.cwnd);
	s->tcb.snd.ssthresh = s->tcb.snd.wnd;

	/* calculate and store real timestamp offset */
	if (ci->so.ts.raw != 0) {
		s->ts_offset = tms - ci->so.ts.ecr;
		tms -= s->ts_offset;
	}

	estimate_stream_rto(s, tms);
}

struct tle_stream *
tle_tcp_stream_establish(struct tle_ctx *ctx,
	const struct tle_tcp_stream_param *prm,
	const struct tle_tcp_conn_info *ci, uint32_t flags)
{
	int32_t rc;
	struct tle_tcp_stream *s;
	struct stbl *st;

	if (ctx == NULL || prm == NULL || ci == NULL) {
		rte_errno = -EINVAL;
		return NULL;
	}

	/* allocate new stream */
	s = tcp_stream_get(ctx, TLE_MTANK_ALLOC_CHUNK | TLE_MTANK_ALLOC_GROW);
	if (s == NULL) {
		rte_errno = ENFILE;
		return NULL;
	}

	do {
		s->tcb.uop |= TLE_TCP_OP_ESTABLISH;

		/* check and use stream addresses and parameters */
		rc = tcp_stream_fill_prm(s, prm);
		if (rc != 0)
			break;

		/* retrieve and cache destination information. */
		rc = stream_fill_dest(s);
		if (rc != 0)
			break;

		/* add the stream to the stream table */
		if ((flags & TLE_TCP_STREAM_F_PRIVATE) == 0) {
			st = CTX_TCP_STLB(s->s.ctx);
			s->ste = stbl_add_stream_lock(st, s);
			if (s->ste == NULL) {
				rc = -ENOBUFS;
				break;
			}
		}

		/* fill TCB from user provided data */
		tcb_establish(s, ci);
		s->tcb.state = TLE_TCP_ST_ESTABLISHED;
		tcp_stream_up(s);

	} while (0);

	/* cleanup on failure */
	if (rc != 0) {
		tcp_stream_reset(ctx, s);
		rte_errno = -rc;
		s = NULL;
	}

	return &s->s;
}

uint16_t
tle_tcp_stream_recv(struct tle_stream *ts, struct rte_mbuf *pkt[], uint16_t num)
{
	uint32_t n;
	struct tle_tcp_stream *s;

	s = TCP_STREAM(ts);
	n = _rte_ring_mcs_dequeue_burst(s->rx.q, (void **)pkt, num);
	if (n == 0)
		return 0;

	/*
	 * if we still have packets to read,
	 * then rearm stream RX event.
	 */
	if (n == num && rte_ring_count(s->rx.q) != 0) {
		if (tcp_stream_try_acquire(s) > 0 && s->rx.ev != NULL)
			tle_event_raise(s->rx.ev);
		tcp_stream_release(s);
	}

	return n;
}

ssize_t
tle_tcp_stream_readv(struct tle_stream *ts, const struct iovec *iov,
	int iovcnt)
{
	int32_t i;
	uint32_t mn, n, tn;
	size_t sz;
	struct tle_tcp_stream *s;
	struct iovec iv;
	struct rxq_objs mo[2];

	s = TCP_STREAM(ts);

	/* get group of packets */
	mn = tcp_rxq_get_objs(s, mo);
	if (mn == 0)
		return 0;

	sz = 0;
	n = 0;
	for (i = 0; i != iovcnt; i++) {
		iv = iov[i];
		sz += iv.iov_len;
		n += _mbus_to_iovec(&iv, mo[0].mb + n, mo[0].num - n);
		if (iv.iov_len != 0) {
			sz -= iv.iov_len;
			break;
		}
	}

	tn = n;

	if (i != iovcnt && mn != 1) {
		n = 0;
		do {
			sz += iv.iov_len;
			n += _mbus_to_iovec(&iv, mo[1].mb + n, mo[1].num - n);
			if (iv.iov_len != 0) {
				sz -= iv.iov_len;
				break;
			}
			if (i + 1 != iovcnt)
				iv = iov[i + 1];
		} while (++i != iovcnt);
		tn += n;
	}

	tcp_rxq_consume(s, tn);

	/*
	 * if we still have packets to read,
	 * then rearm stream RX event.
	 */
	if (i == iovcnt && rte_ring_count(s->rx.q) != 0) {
		if (tcp_stream_try_acquire(s) > 0 && s->rx.ev != NULL)
			tle_event_raise(s->rx.ev);
		tcp_stream_release(s);
	}

	return sz;
}

static inline int32_t
tx_segments(struct tle_tcp_stream *s, uint64_t ol_flags,
	struct rte_mbuf *segs[], uint32_t num)
{
	uint32_t i;
	int32_t rc;

	for (i = 0; i != num; i++) {
		/* Build L2/L3/L4 header */
		rc = tcp_fill_mbuf(segs[i], s, &s->tx.dst, ol_flags, s->s.port,
			0, TCP_FLAG_ACK, 0, 0);
		if (rc != 0) {
			free_mbufs(segs, num);
			break;
		}
	}

	if (i == num) {
		/* queue packets for further transmission. */
		rc = _rte_ring_enqueue_bulk(s->tx.q, (void **)segs, num);
		if (rc != 0)
			free_mbufs(segs, num);
	}

	return rc;
}

uint16_t
tle_tcp_stream_send(struct tle_stream *ts, struct rte_mbuf *pkt[], uint16_t num)
{
	uint32_t i, j, k, mss, n, state;
	int32_t rc;
	uint64_t ol_flags;
	struct tle_tcp_stream *s;
	struct rte_mbuf *segs[TCP_MAX_PKT_SEG];

	s = TCP_STREAM(ts);

	/* mark stream as not closable. */
	if (tcp_stream_acquire(s) < 0) {
		rte_errno = EAGAIN;
		return 0;
	}

	state = s->tcb.state;
	if (state != TLE_TCP_ST_ESTABLISHED && state != TLE_TCP_ST_CLOSE_WAIT) {
		rte_errno = ENOTCONN;
		tcp_stream_release(s);
		return 0;
	}

	mss = s->tcb.snd.mss;
	ol_flags = s->tx.dst.ol_flags;

	k = 0;
	rc = 0;
	while (k != num) {
		/* prepare and check for TX */
		for (i = k; i != num; i++) {
			if (pkt[i]->pkt_len > mss ||
					pkt[i]->nb_segs > TCP_MAX_PKT_SEG)
				break;
			rc = tcp_fill_mbuf(pkt[i], s, &s->tx.dst, ol_flags,
				s->s.port, 0, TCP_FLAG_ACK, 0, 0);
			if (rc != 0)
				break;
		}

		if (i != k) {
			/* queue packets for further transmission. */
			n = _rte_ring_enqueue_burst(s->tx.q,
				(void **)pkt + k, (i - k));
			k += n;

			/*
			 * for unsent, but already modified packets:
			 * remove pkt l2/l3 headers, restore ol_flags
			 */
			if (i != k) {
				ol_flags = ~s->tx.dst.ol_flags;
				for (j = k; j != i; j++) {
					rte_pktmbuf_adj(pkt[j], pkt[j]->l2_len +
						pkt[j]->l3_len +
						pkt[j]->l4_len);
					pkt[j]->ol_flags &= ol_flags;
				}
				break;
			}
		}

		if (rc != 0) {
			rte_errno = -rc;
			break;

		/* segment large packet and enqueue for sending */
		} else if (i != num) {
			/* segment the packet. */
			rc = tcp_segmentation(pkt[i], segs, RTE_DIM(segs),
				&s->tx.dst, mss);
			if (rc < 0) {
				rte_errno = -rc;
				break;
			}

			rc = tx_segments(s, ol_flags, segs, rc);
			if (rc == 0) {
				/* free the large mbuf */
				rte_pktmbuf_free(pkt[i]);
				/* set the mbuf as consumed */
				k++;
			} else
				/* no space left in tx queue */
				break;
		}
	}

	/* notify BE about more data to send */
	if (k != 0)
		txs_enqueue(s->s.ctx, s);
	/* if possible, re-arm stream write event. */
	if (rte_ring_free_count(s->tx.q) != 0 && s->tx.ev != NULL)
		tle_event_raise(s->tx.ev);

	tcp_stream_release(s);

	return k;
}

ssize_t
tle_tcp_stream_writev(struct tle_stream *ts, struct rte_mempool *mp,
	const struct iovec *iov, int iovcnt)
{
	int32_t i, rc;
	uint32_t j, k, n, num, slen, state;
	uint64_t ol_flags;
	size_t sz, tsz;
	struct tle_tcp_stream *s;
	struct iovec iv;
	struct rte_mbuf *mb[2 * MAX_PKT_BURST];

	s = TCP_STREAM(ts);

	/* mark stream as not closable. */
	if (tcp_stream_acquire(s) < 0) {
		rte_errno = EAGAIN;
		return -1;
	}

	state = s->tcb.state;
	if (state != TLE_TCP_ST_ESTABLISHED && state != TLE_TCP_ST_CLOSE_WAIT) {
		rte_errno = ENOTCONN;
		tcp_stream_release(s);
		return -1;
	}

	/* figure out how many mbufs do we need */
	tsz = 0;
	for (i = 0; i != iovcnt; i++)
		tsz += iov[i].iov_len;

	slen = rte_pktmbuf_data_room_size(mp);
	slen = RTE_MIN(slen, s->tcb.snd.mss);

	num = (tsz + slen - 1) / slen;
	n = rte_ring_free_count(s->tx.q);
	num = RTE_MIN(num, n);
	n = RTE_MIN(num, RTE_DIM(mb));

	/* allocate mbufs */
	if (rte_pktmbuf_alloc_bulk(mp, mb, n) != 0) {
		rte_errno = ENOMEM;
		tcp_stream_release(s);
		return -1;
	}

	/* copy data into the mbufs */
	k = 0;
	sz = 0;
	for (i = 0; i != iovcnt; i++) {
		iv = iov[i];
		sz += iv.iov_len;
		k += _iovec_to_mbsegs(&iv, slen, mb + k, n - k);
		if (iv.iov_len != 0) {
			sz -= iv.iov_len;
			break;
		}
	}

	/* partially filled segment */
	k += (k != n && mb[k]->data_len != 0);

	/* fill pkt headers */
	ol_flags = s->tx.dst.ol_flags;

	for (j = 0; j != k; j++) {
		rc = tcp_fill_mbuf(mb[j], s, &s->tx.dst, ol_flags,
			s->s.port, 0, TCP_FLAG_ACK, 0, 0);
		if (rc != 0)
			break;
	}

	/* if no error encountered, then enqueue pkts for transmission */
	if (k == j)
		k = _rte_ring_enqueue_burst(s->tx.q, (void **)mb, j);
	else
		k = 0;

	if (k != j) {

		/* free pkts that were not enqueued */
		free_mbufs(mb + k, j - k);

		/* our last segment can be partially filled */
		sz += slen - sz % slen;
		sz -= (j - k) * slen;

		/* report an error */
		if (rc != 0) {
			rte_errno = -rc;
			sz = -1;
		}
	}

        if (k != 0) {

		/* notify BE about more data to send */
		txs_enqueue(s->s.ctx, s);

		/* if possible, re-arm stream write event. */
		if (rte_ring_free_count(s->tx.q) != 0 && s->tx.ev != NULL)
			tle_event_raise(s->tx.ev);
	}

	tcp_stream_release(s);
	return sz;
}

/* send data and FIN (if needed) */
static inline void
tx_data_fin(struct tle_tcp_stream *s, uint32_t tms, uint32_t state)
{
	/* try to send some data */
	tx_nxt_data(s, tms);

	/* we also have to send a FIN */
	if (state != TLE_TCP_ST_ESTABLISHED &&
			state != TLE_TCP_ST_CLOSE_WAIT &&
			tcp_txq_nxt_cnt(s) == 0 &&
			s->tcb.snd.fss != s->tcb.snd.nxt) {
		s->tcb.snd.fss = ++s->tcb.snd.nxt;
		send_ack(s, tms, TCP_FLAG_FIN | TCP_FLAG_ACK);
	}
}

static inline void
tx_stream(struct tle_tcp_stream *s, uint32_t tms)
{
	uint32_t state;

	state = s->tcb.state;

	if (state == TLE_TCP_ST_SYN_SENT) {
		/* send the SYN, start the rto timer */
		send_ack(s, tms, TCP_FLAG_SYN);
		timer_start(s);

	} else if (state >= TLE_TCP_ST_ESTABLISHED &&
			state <= TLE_TCP_ST_LAST_ACK) {

		tx_data_fin(s, tms, state);

		/* start RTO timer. */
		if (s->tcb.snd.nxt != s->tcb.snd.una)
			timer_start(s);
	} else if (state == TLE_TCP_ST_CLOSED) {
		if ((s->tcb.snd.close_flags & TCP_FLAG_RST) != 0)
			send_rst(s, s->tcb.snd.nxt);
		stream_term(s);
	}
}

static inline void
rto_stream(struct tle_tcp_stream *s, uint32_t tms)
{
	uint32_t state;

	state = s->tcb.state;

	TCP_LOG(DEBUG, "%s(%p, tms=%u): state=%u, "
		"retx=%u, retm=%u, "
		"rto=%u, snd.ts=%u, tmo=%u, "
		"snd.nxt=%lu, snd.una=%lu, flight_size=%lu, "
		"snd.rcvr=%lu, snd.fastack=%u, "
		"wnd=%u, cwnd=%u, ssthresh=%u, "
		"bytes sent=%lu, pkt remain=%u;\n",
		__func__, s, tms, s->tcb.state,
		s->tcb.snd.nb_retx, s->tcb.snd.nb_retm,
		s->tcb.snd.rto, s->tcb.snd.ts, tms - s->tcb.snd.ts,
		s->tcb.snd.nxt, s->tcb.snd.una, s->tcb.snd.nxt - s->tcb.snd.una,
		s->tcb.snd.rcvr, s->tcb.snd.fastack,
		s->tcb.snd.wnd, s->tcb.snd.cwnd, s->tcb.snd.ssthresh,
		s->tcb.snd.nxt - s->tcb.snd.iss, tcp_txq_nxt_cnt(s));

	if (s->tcb.snd.nb_retx < s->tcb.snd.nb_retm) {

		if (state >= TLE_TCP_ST_ESTABLISHED &&
				state <= TLE_TCP_ST_LAST_ACK) {

			/* update SND.CWD and SND.SSTHRESH */
			rto_cwnd_update(&s->tcb);

			/* RFC 6582 3.2.4 */
			s->tcb.snd.rcvr = s->tcb.snd.nxt;
			s->tcb.snd.fastack = 0;

			/* restart from last acked data */
			tcp_txq_rst_nxt_head(s);
			s->tcb.snd.nxt = s->tcb.snd.una;

			tx_data_fin(s, tms, state);

		} else if (state == TLE_TCP_ST_SYN_SENT) {
			/* resending SYN */
			s->tcb.so.ts.val = tms;

			/* According to RFC 6928 2:
			 * To reduce the chance for spurious SYN or SYN/ACK
			 * retransmission, it is RECOMMENDED that
			 * implementations refrain from resetting the initial
			 * window to 1 segment, unless there have been more
			 * than one SYN or SYN/ACK retransmissions or true loss
			 * detection has been made.
			 */
			if (s->tcb.snd.nb_retx != 0)
				s->tcb.snd.cwnd = s->tcb.snd.mss;

			send_ack(s, tms, TCP_FLAG_SYN);

		} else if (state == TLE_TCP_ST_TIME_WAIT) {
			s->err.rev |= TLE_TCP_REV_RTO;
			stream_term(s);
		}

		/* RFC6298:5.5 back off the timer */
		s->tcb.snd.rto = rto_roundup(2 * s->tcb.snd.rto);
		s->tcb.snd.nb_retx++;
		timer_restart(s);

	} else {
		s->err.rev |= TLE_TCP_REV_RTO;
		send_rst(s, s->tcb.snd.nxt);
		stream_term(s);
	}
}

int
tle_tcp_process(struct tle_ctx *ctx, uint32_t num)
{
	uint32_t i, k, tms;
	struct sdr *dr;
	struct tle_timer_wheel *tw;
	struct tle_stream *p;
	struct tle_tcp_stream *s, *rs[num];

	/* process streams with RTO exipred */

	tw = CTX_TCP_TMWHL(ctx);
	tms = tcp_get_tms(ctx->cycles_ms_shift);
	tle_timer_expire(tw, tms);

	k = tle_timer_get_expired_bulk(tw, (void **)rs, RTE_DIM(rs));

	for (i = 0; i != k; i++) {

		s = rs[i];
		s->timer.handle = NULL;
		if (tcp_stream_try_acquire(s) > 0)
			rto_stream(s, tcp_stream_adjust_tms(s, tms));
		tcp_stream_release(s);
	}

	/* process streams from to-send queue */

	k = txs_dequeue_bulk(ctx, rs, RTE_DIM(rs));

	for (i = 0; i != k; i++) {

		s = rs[i];
		rte_atomic32_set(&s->tx.arm, 0);

		if (tcp_stream_try_acquire(s) > 0)
			tx_stream(s, tcp_stream_adjust_tms(s, tms));
		else
			txs_enqueue(s->s.ctx, s);
		tcp_stream_release(s);
	}

	/* collect streams to close from the death row */

	dr = CTX_TCP_SDR(ctx);
	for (k = 0, p = STAILQ_FIRST(&dr->be);
			k != num && p != NULL;
			k++, p = STAILQ_NEXT(p, link))
		rs[k] = TCP_STREAM(p);

	if (p == NULL)
		STAILQ_INIT(&dr->be);
	else
		STAILQ_FIRST(&dr->be) = p;

	/* cleanup closed streams */
	for (i = 0; i != k; i++) {
		s = rs[i];
		tcp_stream_down(s);
		tcp_stream_reset(ctx, s);
	}

	return 0;
}

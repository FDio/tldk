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
#include "tcp_rxq.h"

/*
 * checks if input TCP ports and IP addrsses match given stream.
 * returns zero on success.
 */
static inline int
rx_check_stream(const struct tle_tcp_stream *s, const union pkt_info *pi)
{
	int32_t rc;

	if(pi->tf.type == TLE_V4)
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
	if (s == NULL || rwl_acquire(&s->rx.use) < 0)
		return NULL;

	/* check that we have a proper stream. */
	if (s->tcb.state != TCP_ST_LISTEN) {
		rwl_release(&s->rx.use);
		s = NULL;
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

	if (stbl_data_pkt(s) || rwl_acquire(&s->rx.use) < 0)
		return NULL;
	/* check that we have a proper stream. */
	else if (s->tcb.state == TCP_ST_CLOSED) {
		rwl_release(&s->rx.use);
		s = NULL;
	}

	return s;
}

/*
 * Consider 2 pkt_info *euqual* if their:
 * - types (IPv4/IPv6)
 * - TCP flags
 * - checksum flags
 * - TCP src and dst ports
 * - IP src and dst adresses
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
	rte_ring_enqueue_burst(s->tx.drb.r, (void **)drbs, nb_drb);
}

static inline uint32_t
stream_drb_alloc(struct tle_tcp_stream *s, struct tle_drb *drbs[],
	uint32_t nb_drb)
{
	return rte_ring_dequeue_burst(s->tx.drb.r, (void **)drbs, nb_drb);
}

static inline void
fill_tcph(struct tcp_hdr *l4h, const struct tcb *tcb, union l4_ports port,
	uint32_t seq, uint8_t hlen, uint8_t flags)
{
	uint16_t wnd;

	l4h->src_port = port.dst;
	l4h->dst_port = port.src;

	wnd = (flags & TCP_FLAG_SYN) ?
		TCP4_MIN_MSS : tcb->rcv.wnd >> tcb->rcv.wscale;

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
	else if (tcb->rcv.ts != 0)
		fill_tms_opts(l4h + 1, tcb->snd.ts, tcb->rcv.ts);
}

static inline int
tcp_fill_mbuf(struct rte_mbuf *m, const struct tle_tcp_stream *s,
	const struct tle_dest *dst, uint64_t ol_flags,
	union l4_ports port, uint32_t seq, uint32_t flags, uint32_t pid)
{
	uint32_t l4, len, plen;
	struct tcp_hdr *l4h;
	char *l2h;

	len = dst->l2_len + dst->l3_len;
	plen = m->pkt_len;

	if (flags & TCP_FLAG_SYN)
		l4 = sizeof(*l4h) + TCP_TX_OPT_LEN_MAX;
	else
		l4 = sizeof(*l4h) + (s->tcb.rcv.ts != 0) * TCP_TX_OPT_LEN_TMS;

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

	if (s->s.type == TLE_V4) {
		struct ipv4_hdr *l3h;
		l3h = (struct ipv4_hdr *)(l2h + dst->l2_len);
		l3h->packet_id = rte_cpu_to_be_16(pid);
		l3h->total_length = rte_cpu_to_be_16(plen + dst->l3_len + l4);

		if ((ol_flags & PKT_TX_TCP_CKSUM) != 0)
			l4h->cksum = _ipv4x_phdr_cksum(l3h, m->l3_len,
				ol_flags);
		else
			l4h->cksum = _ipv4_udptcp_mbuf_cksum(m, len, l3h);

		if ((ol_flags & PKT_TX_IP_CKSUM) == 0)
			l3h->hdr_checksum = _ipv4x_cksum(l3h, m->l3_len);
	} else {
		struct ipv6_hdr *l3h;
		l3h = (struct ipv6_hdr *)(l2h + dst->l2_len);
		l3h->payload_len = rte_cpu_to_be_16(plen + l4);
		if ((ol_flags & PKT_TX_UDP_CKSUM) != 0)
			l4h->cksum = rte_ipv6_phdr_cksum(l3h, ol_flags);
		else
			l4h->cksum = _ipv6_udptcp_mbuf_cksum(m, len, l3h);
	}

	return 0;
}

/* Send data packets that need to be ACK-ed by peer */
static inline uint32_t
send_data_pkts(struct tle_tcp_stream *s, uint32_t seq, uint32_t flags,
	struct rte_mbuf *const m[], uint32_t num)
{
	uint32_t bsz, i, mss, nb, nbm, pid, type;
	uint64_t ol_flags;
	const struct tle_dest *dst;
	struct tle_dev *dev;
	struct tle_drb *drb[num];

	dst = &s->tx.dst;
	type = s->s.type;
	mss = dst->mtu - dst->l2_len - dst->l3_len - TCP_TX_HDR_MAX;
	mss = RTE_MIN(mss, s->tcb.snd.mss);

	/*
	 * !!! for now segmentation (neither by HW (TSO),
	 * neether by SW) is impeleminted.
	 * So make sure that each packet fits into one MSS.
	 * Has to be changed. !!!
	 */

        /* calulate how many drbs are needed.*/
	bsz = s->tx.drb.nb_elem;
	nbm = (num + bsz - 1) / bsz;

	/* allocate drbs, adjust number of packets. */
	nb = stream_drb_alloc(s, drb, nbm);

	/* drb ring is empty. */
	if (nb == 0)
		return 0;

	else if (nb != nbm)
		num = nb * bsz;

	dev = dst->dev;
	ol_flags = dev->tx.ol_flags[type];
	pid = rte_atomic32_add_return(&dev->tx.packet_id[type], num) - num;

	for (i = 0; i != num; i++) {

		/* !!! for now don't allow packets bigger then MSS !!! */
		if (m[i]->pkt_len > mss)
			break;

		/* prepare for TX */
		if (tcp_fill_mbuf(m[i], s, dst, ol_flags, s->s.port, seq, flags,
				pid + i) != 0)
			break;

		/* keep mbuf till ACK is received. */
		rte_pktmbuf_refcnt_update(m[i], 1);
	}

	/* enqueue pkts for TX. */
	nbm = nb;
	i = tle_dring_mp_enqueue(&dev->tx.dr, (const void * const*)m,
		i, drb, &nb);

	/* free unused drbs. */
	if (nb != 0)
		stream_drb_free(s, drb + nbm - nb, nb);

	return i;
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
	pid = rte_atomic32_add_return(&dst->dev->tx.packet_id[type], 1) - 1;

	rc = tcp_fill_mbuf(m, s, dst, 0, s->s.port, seq, flags, pid);
	if (rc == 0)
		rc = send_pkt(s, dst->dev, m);

	return rc;
}

static inline int
send_rst(struct tle_tcp_stream *s, uint32_t seq)
{
	struct rte_mbuf *m;
	int32_t rc;

	if ((m = rte_pktmbuf_alloc(s->tx.dst.head_mp)) == NULL)
		return -ENOMEM;

	rc = send_ctrl_pkt(s, m, seq, TCP_FLAG_RST);
	if (rc != 0)
		rte_pktmbuf_free(m);

	return rc;
}

static inline int
send_ack(struct tle_tcp_stream *s, uint32_t flags)
{
	struct rte_mbuf *m;
	uint32_t seq;
	int32_t rc;

	if ((m = rte_pktmbuf_alloc(s->tx.dst.head_mp)) == NULL)
		return -ENOMEM;

	seq = s->tcb.snd.nxt - ((flags & TCP_FLAG_FIN) != 0);

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
	const struct tcp_hdr *th;

	th = rte_pktmbuf_mtod_offset(m, const struct tcp_hdr *,
		m->l2_len + m->l3_len);
	get_syn_opts(&s->tcb.so, (uintptr_t)(th + 1), m->l4_len - sizeof(*th));

	s->tcb.rcv.nxt = si->seq + 1;
	seq = sync_gen_seq(pi, s->tcb.rcv.nxt, ts, s->tcb.so.mss);
	s->tcb.so.ts.ecr = s->tcb.so.ts.val;
	s->tcb.so.ts.val = sync_gen_ts(ts, s->tcb.so.wscale);
	s->tcb.so.wscale = (s->tcb.so.wscale == TCP_WSCALE_NONE) ?
		TCP_WSCALE_NONE : TCP_WSCALE_DEFAULT;

	type = s->s.type;
	if (type == TLE_V4)
		da = &pi->addr4.src;
	else
		da = &pi->addr6->src;

	rc = stream_get_dest(&s->s, da, &dst);
	if (rc < 0)
		return rc;

	/* reset mbuf's data contents. */
	len = m->l2_len + m->l3_len + m->l4_len;
	m->tx_offload = 0;
	if (rte_pktmbuf_adj(m, len) == NULL)
		return -EINVAL;

	dev = dst.dev;
	pid = rte_atomic32_add_return(&dev->tx.packet_id[type], 1) - 1;

	rc = tcp_fill_mbuf(m, s, &dst, 0, pi->port, seq,
		TCP_FLAG_SYN | TCP_FLAG_ACK, pid);
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

static inline union tsopt
rx_tms_opt(const struct tcb *tcb, const struct rte_mbuf *mb)
{
	union tsopt ts;
	uintptr_t opt;
	const struct tcp_hdr *th;

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
rx_check_seq(struct tcb *tcb, uint32_t seq, uint32_t len, const union tsopt ts)
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
	if (tcp_seq_leq(tcb->snd.una, ack) && tcp_seq_leq(ack, tcb->snd.nxt))
		return 0;

	return -ERANGE;
}

static inline int
rx_check_seqack(struct tcb *tcb, uint32_t seq, uint32_t ack, uint32_t len,
	const union tsopt ts)
{
	int32_t rc;

	rc = rx_check_seq(tcb, seq, len, ts); 
	rc |= rx_check_ack(tcb, ack);
	return rc;
}

static inline int
restore_syn_pkt(const union pkt_info *pi, const union seg_info *si,
	uint32_t ts, struct rte_mbuf *mb)
{
	int32_t rc;
	uint32_t len;
	struct tcp_hdr *th;
	struct syn_opts so;

	/* check that ACK, etc fields are what we expected. */
	rc = sync_check_ack(pi, si->seq, si->ack - 1, ts);
	if (rc < 0)
		return rc;

	so.mss = rc;

	th = rte_pktmbuf_mtod_offset(mb, struct tcp_hdr *,
		mb->l2_len + mb->l3_len);
	len = mb->l4_len - sizeof(*th);
	sync_get_opts(&so, (uintptr_t)(th + 1), len);

	/* reconstruct SYN options, extend header size if necessary */
	if (len < TCP_TX_OPT_LEN_MAX) {
		len = TCP_TX_OPT_LEN_MAX - len;
		th->data_off = TCP_TX_OPT_LEN_MAX / TCP_DATA_ALIGN <<
			TCP_DATA_OFFSET;
		mb->pkt_len += len;
		mb->data_len += len;
		mb->l4_len += len;
	}

	fill_syn_opts(th + 1, &so);
	return 0;
}
        

static inline int
rx_ack_listen(struct tle_tcp_stream *s, struct stbl *st,
	const union pkt_info *pi, const union seg_info *si,
	uint32_t ts, struct rte_mbuf *mb)
{
	int32_t rc;
	struct stbl_entry *se;

	if (pi->tf.flags != TCP_FLAG_ACK || rx_check_stream(s, pi) != 0)
		return -EINVAL;

	/* ACK for new connection request. */

	rc = restore_syn_pkt(pi, si, ts, mb);
	if (rc < 0)
		return rc;

	se = stbl_add_pkt(st, pi, mb);
	if (se == NULL)
		return -ENOBUFS;

	/* put new connection requests into stream listen queue */
	if (rte_ring_enqueue_burst(s->rx.q,
			(void * const *)&se, 1) != 1) {
		stbl_del_pkt(st, se, pi);
		return -ENOBUFS;
	}

	return 0;
}

static inline void
stream_close(struct tle_tcp_stream *s)
{
	s->tcb.state = TCP_ST_CLOSED;
	rte_smp_wmb();

	timer_stop(s);

	if (s->err.ev != NULL)
		tle_event_raise(s->err.ev);
	else if (s->err.cb.func != NULL)
		s->err.cb.func(s->err.cb.data, &s->s);
}

static inline int
rx_last_ack(struct tle_tcp_stream *s, const union pkt_info *pi,
	const union seg_info *si, const struct rte_mbuf *mb,
	struct resp_info *rsp)
{
	uint32_t len;
	union tsopt ts;

	len = PKT_L4_PLEN(mb);

	ts = rx_tms_opt(&s->tcb, mb);
	if (rx_check_seq(&s->tcb, si->seq, len, ts) != 0) {
		/* something wrong is going on */
		rsp->flags = TCP_FLAG_RST;
		return 0;
	}

	/* our <FIN,ACK> was probably lost, try to resend it. */
	if ((pi->tf.flags & TCP_FLAG_FIN) != 0 &&
			s->tcb.rcv.nxt == si->seq + 1) {
		rsp->flags =  TCP_FLAG_ACK | TCP_FLAG_FIN;
		return -EINVAL;
	}

	if (si->ack != s->tcb.snd.nxt)
		return -ERANGE;

	stream_close(s);
	return 0;
}

static inline int
data_pkt_adjust(const struct tcb *tcb, struct rte_mbuf *mb, uint32_t hlen,
	uint32_t *seqn, uint32_t *plen)
{
	uint32_t len, n, seq;

	seq = *seqn;
	len = *plen;

	rte_pktmbuf_adj(mb, hlen);
	if(len == 0)
		return -ENODATA;
	/* cut off the start of the packet */
	else if (tcp_seq_lt(seq, tcb->rcv.nxt)) {
		n = tcb->rcv.nxt - seq;
		if (n >= len)
			return -ENODATA;

		rte_pktmbuf_adj(mb, n);
		*seqn = seq + n;
		*plen = len - n;
	}

	return 0;
}

static void
rx_fin_state(struct tle_tcp_stream *s, struct resp_info *rsp)
{
	s->tcb.rcv.nxt += 1;
	rsp->flags |= TCP_FLAG_ACK;

	/* send buffer is empty */
	if (s->tcb.snd.nxt == s->tcb.snd.una) {
		rsp->flags |= TCP_FLAG_FIN;
		s->tcb.snd.nxt++;
		s->tcb.state = TCP_ST_LAST_ACK;
	} else
		s->tcb.state = TCP_ST_CLOSE_WAIT;
}

/*
 * FIN process for ESTABLISHED state
 * returns:
 * 0 < - error occured
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
	union tsopt ts;

	hlen = PKT_L234_HLEN(mb);
	plen = mb->pkt_len - hlen;
	seq = si->seq;

	ts = rx_tms_opt(&s->tcb, mb);
	ret = rx_check_seqack(&s->tcb, seq, si->ack, plen, ts);
	if (ret != 0)
		return ret;

	if (state != TCP_ST_ESTABLISHED)
		return -EINVAL;

	if (plen != 0) {

		ret = data_pkt_adjust(&s->tcb, mb, hlen, &seq, &plen);
		if (ret != 0)
			return ret;
		if (rx_data_enqueue(s, seq, plen, &mb, 1) != 1)
			return -ENOBUFS;
	}

	/* some fragments still missing */
	if (seq + plen != s->tcb.rcv.nxt) {
		s->tcb.rcv.frs.seq = seq + plen;
		s->tcb.rcv.frs.on = 1;
	} else
		rx_fin_state(s, rsp);

	return plen;
}

/*
 *  check do we have FIN  taht was received out-of-order.
 *  if yes, try to process it now.
 */
static inline void
rx_ofo_fin(struct tle_tcp_stream *s, struct resp_info *rsp)
{
	if (s->tcb.rcv.frs.on != 0 && s->tcb.rcv.nxt == s->tcb.rcv.frs.seq)
		rx_fin_state(s, rsp);
}

static inline void
ack_info_init(struct ack_info *tack, const struct tle_tcp_stream *s)
{
	tack->ack = s->tcb.snd.una;
	tack->dup = 0;
	tack->ts.raw = 0;
}

static inline void
ack_info_update(struct ack_info *tack, uint32_t ack, const union tsopt ts)
{
	if (tcp_seq_lt(tack->ack, ack)) {
		tack->ack = ack;
		tack->ts = ts;
	}
}

static inline uint32_t
rx_data_ack(struct tle_tcp_stream *s, struct ack_info *tack,
	const union seg_info si[], struct rte_mbuf *mb[], struct rte_mbuf *rp[],
	int32_t rc[], uint32_t num)
{
	uint32_t i, j, k, n, t;
	uint32_t hlen, plen, seq, tlen;
	int32_t ret;
	union tsopt ts;

	ack_info_init(tack, s);
	
	k = 0;
	for (i = 0; i != num; i = j) {

		hlen = PKT_L234_HLEN(mb[i]);
		plen = mb[i]->pkt_len - hlen;
		seq = si[i].seq;

		ts = rx_tms_opt(&s->tcb, mb[i]);
		ret = rx_check_seqack(&s->tcb, seq, si[i].ack, plen, ts);

		if (ret == 0) {
			ret = data_pkt_adjust(&s->tcb, mb[i], hlen,
				&seq, &plen);
			ack_info_update(tack, si[i].ack, ts);
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

			/* wrong SEQ/ACK */
			ts = rx_tms_opt(&s->tcb, mb[j]);
			ret = rx_check_seqack(&s->tcb, si[j].seq, si[j].ack,
				plen, ts);
			if (ret != 0) {
				rp[k] = mb[j];
				rc[k] = -ret;
				k++;
				break;
			}
			rte_pktmbuf_adj(mb[j], hlen);
			ack_info_update(tack, si[j].ack, ts);
		}

		n = j - i;
		j += (ret != 0);

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
rx_process_ack(struct tle_tcp_stream *s, uint32_t ts,
	const struct ack_info *tack)
{
	s->tcb.snd.una = tack->ack;

	/* update rto, if fresh packet is here then calculate rtt */
	 if (tack->ts.ecr != 0)
		estimate_rto(&s->tcb, ts - tack->ts.ecr);

	/* if all data are acked, reset retransmit info */
	if (tack->ack == s->tcb.snd.nxt) {
		timer_stop(s);
		s->tcb.snd.nb_retx = 0;
	}
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
	struct ack_info tack;

	k = 0;
	rsp.flags = 0;

	state = s->tcb.state;

	/* RFC 793: if the ACK bit is off drop the segment and return */
	if ((pi->tf.flags & TCP_FLAG_ACK) == 0) {
		i = 0;
	/*
	 * first check for the states/flags where we don't
	 * expect groups of packets.
	 */
	} else if (state == TCP_ST_LAST_ACK) {
		for (i = 0;
				i != num &&
				rx_last_ack(s, pi, &si[i], mb[i], &rsp);
				i++)
			;
		i = 0;

	/* process FIN */
	} else if ((pi->tf.flags & TCP_FLAG_FIN) != 0) {
		ret = 0;
		for (i = 0; i != num; i++) {
			ret = rx_fin(s, state, &si[i], mb[i], &rsp);
			if (ret >= 0)
				break;
			else {
				rc[k] = -ret;
				rp[k] = mb[i];
				k++;
                        }
		}
		i += (ret > 0);

	/* normal data/ack packets */
	} else if (state == TCP_ST_ESTABLISHED || 
			state == TCP_ST_FIN_WAIT_1 ||
			state == TCP_ST_FIN_WAIT_2) {
		n = rx_data_ack(s, &tack, si, mb, rp, rc, num);
		rx_process_ack(s, ts, &tack);
		rx_ofo_fin(s, &rsp);
		rsp.flags |= TCP_FLAG_ACK;
		k += num - n;
		i = num;
	/* unhandled state, drop all packets. */
	} else
		i = 0;

	/* we have a response packet to send. */
	if (rsp.flags == TCP_FLAG_RST) {
		send_rst(s, si[i].ack);
		stream_close(s);
	} else if (rsp.flags != 0) {
		send_ack(s, rsp.flags);

		/* start the timer for FIN packet */
		if ((rsp.flags & TCP_FLAG_FIN) != 0)
			timer_restart(s);
	}

	/* unprocessed packets */
	for (; i != num; i++, k++) {
		rc[k] = EINVAL;
		rp[k] = mb[i];
	}

	return num - k;
}

static inline uint32_t
rx_postsyn(struct tle_dev *dev, struct stbl *st, uint32_t type, uint32_t ts,
	const union pkt_info pi[], const union seg_info si[],
	struct rte_mbuf *mb[], struct rte_mbuf *rp[], int32_t rc[],
	uint32_t num)
{
	struct tle_tcp_stream *s;
	uint32_t i, k, state;
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

	if (state == TCP_ST_LISTEN) {

		/* one connection per flow */
		ret = EINVAL;
		for (i = 0; i != num && ret != 0; i++) {
			ret = rx_ack_listen(s, st, pi, &si[i], ts, mb[i]);
			if (ret != 0) {
				rc[k] = -ret;
				rp[k] = mb[i];
				k++;
			}
		}
		/* duplicate SYN requests */
		for (; i != num; i++, k++) {
			rc[k] = EINVAL;
			rp[k] = mb[i];
		}

		if (k != num && s->rx.ev != NULL)
			tle_event_raise(s->rx.ev);
		else if(s->rx.cb.func != NULL && rte_ring_count(s->rx.q) == 1)
			s->rx.cb.func(s->rx.cb.data, &s->s);

	} else {
		i = rx_stream(s, ts, pi, si, mb, rp, rc, num);
		k = num - i;
	}

	rwl_release(&s->rx.use);
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

	rwl_release(&s->rx.use);
	return num - k;
}

uint16_t
tle_tcp_rx_bulk(struct tle_dev *dev, struct rte_mbuf *pkt[],
	struct rte_mbuf *rp[], int32_t rc[], uint16_t num)
{
	struct stbl *st;
	uint32_t i, j, k, n, t, ts;
	uint64_t csf;
	union pkt_info pi[num];
	union seg_info si[num];
	union {
		uint8_t t[TLE_VNUM];
		uint32_t raw;
	} stu;

	ts = tcp_get_tms();
	st = CTX_TCP_STLB(dev->ctx);

	stu.raw = 0;

	/* extract packet info and check the L3/L4 csums */
	for (i = 0; i != num; i++) {

		get_pkt_info(pkt[i], &pi[i], &si[i]);

		t = pi[i].tf.type;
		csf = dev->rx.ol_flags[t] &
			(PKT_RX_IP_CKSUM_BAD | PKT_RX_L4_CKSUM_BAD);
		
		/* check csums in SW */
		if (pi[i].csf == 0 && csf != 0 && check_pkt_csum(pkt[i], csf,
				pi[i].tf.type, IPPROTO_TCP) != 0)
			pi[i].csf = csf;

		stu.t[t] = 1;
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
tle_tcp_stream_synreqs(struct tle_stream *ts, struct tle_syn_req rq[],
	uint32_t num)
{
	uint32_t i, n;
	struct tle_tcp_stream *s;
	struct stbl_entry *se[num];

	s = TCP_STREAM(ts);
	n = rte_ring_mc_dequeue_burst(s->rx.q, (void **)se, num);
	if (n == 0)
		return 0;

	for (i = 0; i != n; i++) {
		rq[i].pkt = stbl_get_pkt(se[i]);
		rq[i].opaque = se[i];
	}

	/*
	 * if we still have packets to read,
	 * then rearm stream RX event.
	 */
	if (n == num && rte_ring_count(s->rx.q) != 0) {
		if (rwl_try_acquire(&s->rx.use) > 0 && s->rx.ev != NULL)
			tle_event_raise(s->rx.ev);
		rwl_release(&s->rx.use);
	}

	return n;
}

static int
stream_fill_dest(struct tle_tcp_stream *s)
{
	int32_t rc;
	const void *da;

	if (s->s.type == TLE_V4)
		da = &s->s.ipv4.addr.src;
	else
		da = &s->s.ipv6.addr.src;

	rc = stream_get_dest(&s->s, da, &s->tx.dst);
	return (rc < 0) ? rc : 0;
}

/*
 * helper function, prepares an accepted stream.
 */
static int
accept_fill_stream(struct tle_tcp_stream *ps, struct tle_tcp_stream *cs,
	const struct tle_tcp_accept_param *prm, uint32_t tms,
	const union pkt_info *pi, const union seg_info *si)
{
	int32_t rc;
	uint32_t rtt;

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
	sync_fill_tcb(&cs->tcb, si, prm->syn.pkt);
	cs->tcb.rcv.wnd = cs->rx.q->prod.mask << cs->tcb.rcv.wscale;
	cs->tcb.state = TCP_ST_ESTABLISHED;

	/* setup stream notification menchanism */
	cs->rx.ev = prm->cfg.recv_ev;
	cs->rx.cb = prm->cfg.recv_cb;
	cs->tx.ev = prm->cfg.send_ev;
	cs->tx.cb = prm->cfg.send_cb;
	cs->err.ev = prm->cfg.err_ev;
	cs->err.cb = prm->cfg.err_cb;

	/* store other params */
	cs->tcb.snd.nb_retm = (prm->cfg.nb_retries != 0) ? prm->cfg.nb_retries :
		TLE_TCP_DEFAULT_RETRIES;

	/*
	 * estimate the rto
	 * for now rtt is calculated based on the tcp TMS option,
	 * later add real-time one
	 */
	if (cs->tcb.so.ts.ecr) {
		rtt = tms - cs->tcb.so.ts.ecr;
		estimate_rto(&cs->tcb, rtt);
	} else
		cs->tcb.snd.rto = TCP_DEFAUT_RTO;

	tcp_stream_up(cs);

	/* copy streams type. */
	cs->s.type = ps->s.type;

	/* retrive and cache destination information. */
	rc = stream_fill_dest(cs);
	if (rc != 0)
		return rc;

	/* add stream to the table */
	cs->ste = prm->syn.opaque;
	rte_smp_wmb();
	cs->ste->data = cs;
	return 0;
}

/*
 * !!!
 * Right now new stream rcv.wnd is set to zero.
 * That simplifies handling of new connection establishment
 * (as no data segments could be received),
 * but has to be addressed.
 * possible ways:
 *  - send ack after accept creates new stream with new rcv.wnd value.
 *    the problem with that approach that single ack is not delivered
 *    reliably (could be lost), plus might slowdown connection establishment
 *    (extra packet per connection, that client has to wait for).
 *  - allocate new stream at ACK recieve stage.
 *    As a drawback - whole new stream allocation/connection establishment
 *    will be done in BE.
 * !!!
 */
int
tle_tcp_stream_accept(struct tle_stream *ts,
	const struct tle_tcp_accept_param prm[], struct tle_stream *rs[],
	uint32_t num)
{
	struct tle_tcp_stream *cs, *s;
	struct tle_ctx *ctx;
	uint32_t i, j, n, tms;
	int32_t rc;
	union pkt_info pi[num];
	union seg_info si[num];

	tms = tcp_get_tms();
	s = TCP_STREAM(ts);

	for (i = 0; i != num; i++)
		get_pkt_info(prm[i].syn.pkt, &pi[i], &si[i]);

	/* mark stream as not closable */
	if (rwl_acquire(&s->rx.use) < 0)
		return -EINVAL;

	ctx = s->s.ctx;
	n = get_streams(ctx, rs, num);

	rc = 0;
	for (i = 0; i != n; i++) {

		/* prepare new stream */
		cs = TCP_STREAM(rs[i]);
		rc = accept_fill_stream(s, cs, prm + i, tms, pi + i, si + i);
		if (rc != 0)
			break;
	}

	rwl_release(&s->rx.use);

	/* free 'SYN' mbufs. */
	for (j = 0; j != i; j++)
		rte_pktmbuf_free(prm[j].syn.pkt);

	/* close failed stream, put unused streams back to the free list. */
	if (rc != 0) {
		tle_tcp_stream_close(rs[i]);
		for (j = i + 1; j != n; j++) {
			cs = TCP_STREAM(rs[j]);
			put_stream(ctx, rs[j], TCP_STREAM_TX_PENDING(cs));
		}
		rte_errno = -rc;

	/* not enough streams are available */
	} else if (n != num)
		rte_errno = ENFILE;

	return i;
}

/*
 * !!! implement a proper one, or delete !!!
 * need to make sure no race conditions with add/lookup stream table.
 */
void
tle_tcp_reject(struct tle_stream *s, const struct tle_syn_req rq[],
	uint32_t num)
{
	uint32_t i;
	struct rte_mbuf *mb;
	struct stbl *st;
	union pkt_info pi;
	union seg_info si;

	st = CTX_TCP_STLB(s->ctx);

	for (i = 0; i != num; i++) {
		mb = rq[i].pkt;
		get_pkt_info(mb, &pi, &si);
		if (pi.tf.type < TLE_VNUM)
			stbl_del_pkt_lock(st, rq[i].opaque, &pi);

		/* !!! send RST pkt to the peer !!! */
		rte_pktmbuf_free(mb);
	}
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
		for (j = i + 1; j != k && s == drb[i]->udata; j++)
			;
		stream_drb_free(s, drb + i, j - i);
	}

	return n;
}

int
tle_tcp_stream_connect(struct tle_stream *ts, const struct sockaddr *addr)
{
	RTE_SET_USED(ts);
	RTE_SET_USED(addr);
	return 0;
}

uint16_t
tle_tcp_stream_recv(struct tle_stream *ts, struct rte_mbuf *pkt[], uint16_t num)
{
	uint32_t n;
	struct tle_tcp_stream *s;

	s = TCP_STREAM(ts);
	n = rte_ring_mc_dequeue_burst(s->rx.q, (void **)pkt, num);
	if (n == 0)
		return 0;

	/*
	 * if we still have packets to read,
	 * then rearm stream RX event.
	 */
	if (n == num && rte_ring_count(s->rx.q) != 0) {
		if (rwl_try_acquire(&s->rx.use) > 0 && s->rx.ev != NULL)
			tle_event_raise(s->rx.ev);
		rwl_release(&s->rx.use);
	}

	return n;
}

uint16_t
tle_tcp_stream_send(struct tle_stream *ts, struct rte_mbuf *pkt[], uint16_t num)
{
	RTE_SET_USED(ts);
	RTE_SET_USED(pkt);
	RTE_SET_USED(num);
	return 0;
}

static inline void
stream_rto(struct tle_tcp_stream *s)
{
	if (s->tcb.snd.nb_retx < s->tcb.snd.nb_retm) {
		if (s->tcb.state == TCP_ST_ESTABLISHED) {

			/* TODO: retx the packet */

		} else if (s->tcb.state == TCP_ST_LAST_ACK) {
			/* resending ack */
			send_ack(s, TCP_FLAG_FIN | TCP_FLAG_ACK);
		}

		/* RFC6298:5.5 back off the timer */
		s->tcb.snd.rto = RTE_MIN(s->tcb.snd.rto * 2, TCP_MAX_RTO);
		s->tcb.snd.nb_retx++;
		timer_start(s);

	} else {
		s->timer.handle = NULL;
		stream_close(s);
	}
}

int
tle_tcp_process(struct tle_ctx *ctx, uint32_t num)
{
	struct tle_timer_wheel *tw;
	struct tle_tcp_stream *s, *rs[num];
	uint32_t k, i, tms;

	tw = CTX_TCP_TMWHL(ctx);
	tms= tcp_get_tms();
	tle_timer_expire(tw, tms);

	k = tle_timer_get_expired_bulk(tw, (void **)rs, RTE_DIM(rs));

	for (i = 0; i != k; i++) {

		s = rs[i];
		if (rwl_try_acquire(&s->rx.use) > 0)
			stream_rto(s);
		rwl_release(&s->rx.use);
	}

	return 0;
}

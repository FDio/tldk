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
#include "stream_table.h"
#include "syncookie.h"
#include "misc.h"

#define	TCP_WSCALE_DEFAULT	7
#define	TCP_WSCALE_NONE		0

#define	TCP_MIN_MSS	536

#define	TCP_TX_HDR_MAX	(sizeof(struct tcp_hdr) + TCP_TX_OPT_LEN_MAX)

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
rx_obtain_stream(const struct tle_dev *dev, const struct stbl *st,
	const union pkt_info *pi)
{
	uint32_t type;
	struct tle_stream *ts;
	struct tle_tcp_stream *s;

	type = pi->tf.type;
	if (type >= TLE_VNUM || dev->dp[type] == NULL)
		return NULL;

	s = (struct tle_tcp_stream *)dev->dp[type]->streams[pi->port.dst];
	if (s == NULL || rwl_acquire(&s->rx.use) < 0)
		return NULL;

	/*
	 * if we found a listen stream, and this is not a SYN request,
	 * then try to find a proper stream for that flow.
	 */
	if (pi->tf.flags != TCP_FLAG_SYN && s->tcb.state == TCP_ST_LISTEN) {
		ts = stbl_find_data(st, pi);
		if (ts != NULL) {
			rwl_release(&s->rx.use);
			s = TCP_STREAM(ts);
			if (stbl_data_pkt(ts) || rwl_acquire(&s->rx.use) < 0)
				return NULL;
		}
	}

	/* check that we have a proper stream. */
	if (s->tcb.state == TCP_ST_CLOSED || rx_check_stream(s, pi) != 0) {
		rwl_release(&s->rx.use);
		s = NULL;
	}

	return s;
}


static inline uint8_t
get_pkt_type(const struct rte_mbuf *m)
{
	uint32_t v;

	v = m->packet_type &
		(RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_MASK);
	if (v == (RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_TCP))
		return TLE_V4;
	else if (v == (RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_TCP))
		return TLE_V6;
	else
		return TLE_VNUM;
}

static inline void
pkt_info(const struct rte_mbuf *m, union pkt_info *pi)
{
	uint32_t len, type;
	const struct tcp_hdr *tcph;
	const union l4_ports *prt;
	const union ipv4_addrs *pa4;

	type = get_pkt_type(m);
	len = m->l2_len;

	if (type == TLE_V4) {
		pa4 = rte_pktmbuf_mtod_offset(m, const union ipv4_addrs *,
			len + offsetof(struct ipv4_hdr, src_addr));
		pi->addr4.raw = pa4->raw;
	} else if (type == TLE_V6) {
		pi->addr6 = rte_pktmbuf_mtod_offset(m, const union ipv6_addrs *,
			len + offsetof(struct ipv6_hdr, src_addr));
	}

	len += m->l3_len;
	tcph = rte_pktmbuf_mtod_offset(m, const struct tcp_hdr *, len);
	prt = (const union l4_ports *)
		((uintptr_t)tcph + offsetof(struct tcp_hdr, src_port));
	pi->tf.flags = tcph->tcp_flags;
	pi->tf.type = type;
	pi->reserve1 = 0;
	pi->port.raw = prt->raw;
}

/*
 * Consider 2 pkt_info *euqual* if their:
 * types (IPv4/IPv6)
 * TCP flags
 * TCP src and dst ports
 * IP src and dst adresses
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

static inline void
get_syn_opts(uintptr_t p, struct syn_opts *so, uint32_t len)
{
	uint32_t i, kind;
	const struct tcpopt *opt;

	memset(so, 0, sizeof(*so));

	i = 0;
	while (i < len) {
		opt = (const struct tcpopt *)(p + i);
		kind = opt->kl.kind;
		if (kind == TCP_OPT_KIND_EOL)
			return;
		else if (kind == TCP_OPT_KIND_NOP) 
			i += sizeof(opt->kl.kind);
		else if ((i += opt->kl.len) <= len) {
			if (opt->kl.raw == TCP_OPT_KL_MSS)
				so->mss = rte_be_to_cpu_16(opt->mss);
			else if (opt->kl.raw == TCP_OPT_KL_WSC)
				so->wscale = opt->wscale;
			else if (opt->kl.raw == TCP_OPT_KL_TMS) {
				so->ts.val = rte_be_to_cpu_32(opt->ts.val);
				so->ts.ecr = rte_be_to_cpu_32(opt->ts.ecr);
			}
		}
	}
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

/*
 * generates SYN options, assumes that there are
 * at least TCP_TX_OPT_LEN_MAX bytes avaliable.
 */
static inline void
fill_syn_opts(void *p, const struct syn_opts *so)
{
	uint8_t *to;
	struct tcpopt *opt;

	to = (uint8_t *)p;

	/* setup MSS*/ 
	opt = (struct tcpopt *)to;
	opt->kl.raw = TCP_OPT_KL_MSS;
	opt->mss = rte_cpu_to_be_16(so->mss);

	to += TCP_OPT_LEN_MSS;
	opt = (struct tcpopt *)to;

	/* setup TMS*/
	if (so->ts.val != 0) {

		opt->kl.raw = TCP_OPT_KL_TMS;
		opt->ts.val = rte_cpu_to_be_32(so->ts.val);
		opt->ts.ecr = rte_cpu_to_be_32(so->ts.ecr);

		to += TCP_OPT_LEN_TMS;
		opt = (struct tcpopt *)to;
	}

	/* setup TMS*/
	if (so->wscale != 0) {

		opt->kl.raw = TCP_OPT_KL_WSC;
		opt->wscale = so->wscale;

		to += TCP_OPT_LEN_WSC;
		opt = (struct tcpopt *)to;
	}

	to[0] = TCP_OPT_KIND_EOL;
}

/*
 * generate TMS option, for non SYN packet, make sure
 * there at least TCP_TX_OPT_LEN_TMS avaliable.
 */
static inline void
fill_tms_opts(void *p, const struct tcb *tcb)
{
	uint32_t *opt;

	opt = (uint32_t *)p;
	opt[0] = TCP_OPT_TMS_HDR;
	opt[1] = rte_cpu_to_be_32(tcb->snd.ts);
	opt[2] = rte_cpu_to_be_32(tcb->rcv.ts);
}

static inline void
fill_tcph(struct tcp_hdr *l4h, const struct tcb *tcb, union l4_ports port,
	uint32_t seq, uint8_t hlen, uint8_t flags)
{
	l4h->src_port = port.dst;
	l4h->dst_port = port.src;

	/* ??? use sse shuffle to hton all remaining 16 bytes at once. ??? */ 
	l4h->sent_seq = rte_cpu_to_be_32(seq);
	l4h->recv_ack = rte_cpu_to_be_32(tcb->rcv.nxt);
	l4h->data_off = hlen / TCP_DATA_ALIGN << TCP_DATA_OFFSET;
	l4h->tcp_flags = flags;
	l4h->rx_win = rte_cpu_to_be_16(tcb->rcv.wnd >> tcb->rcv.wscale);
	l4h->cksum = 0;
	l4h->tcp_urp = 0;

	if (flags & TCP_FLAG_SYN)
		fill_syn_opts(l4h + 1, &tcb->so);
	else if (tcb->rcv.ts != 0)
		fill_tms_opts(l4h + 1, tcb);
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
	if (nb != nbm)
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

static int
sync_ack(struct tle_tcp_stream *s, const union pkt_info *pi,
	struct rte_mbuf *m)
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
	get_syn_opts((uintptr_t)(th + 1), &s->tcb.so, m->l4_len - sizeof(*th));

	s->tcb.rcv.nxt = rte_be_to_cpu_32(th->sent_seq) + 1;
	seq = sync_gen_seq(pi, th->sent_seq);
	s->tcb.so.ts.ecr = s->tcb.so.ts.val;
	s->tcb.so.ts.val = sync_gen_ts(s->tcb.so.wscale);
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

static inline int
rx_listen(struct tle_tcp_stream *s, struct stbl *st, const union pkt_info *pi,
	struct rte_mbuf *mb)
{
	struct stbl_entry *se;

	/* new connection request. */
	if (pi->tf.flags == TCP_FLAG_SYN) {

		/* syncokie: reply with <SYN,ACK> */
		return sync_ack(s, pi, mb);

	/* ACK for new connection request. */
	} else if (pi->tf.flags == TCP_FLAG_ACK) {

		/* check that ACK, etc fields are what we expected. */
		if (sync_check_ack(mb) != 0)
			return -EINVAL;

		se = stbl_add_pkt(st, pi, mb);
		if (se == NULL)
			return -ENOBUFS;

		/* put new connection requests into stream listen queue */
		if (rte_ring_enqueue_burst(s->rx.lq,
				(void * const *)&se, 1) != 1) {
			stbl_del_pkt(st, se, pi);
			return -ENOBUFS;
		}

		return 0;
	}

	return -EINVAL;
}

static inline uint16_t
rx_stream(struct tle_tcp_stream *s, struct stbl *st,
	uint64_t ol_flags, const union pkt_info *pi,
	struct rte_mbuf *mb[], struct rte_mbuf *rp[], int32_t rc[],
	uint32_t num)
{
	uint32_t i, k, n, state;
	int32_t ret;

	/* need to check packets csum. */
	if ((ol_flags & (PKT_RX_IP_CKSUM_BAD | PKT_RX_L4_CKSUM_BAD)) != 0) {
	}

	n = 0;
	k = 0;

	state = s->tcb.state;
	if (state == TCP_ST_LISTEN) {
		ret = rx_listen(s, st, pi, mb[0]);
		if (ret != 0) {
			rc[k] = -ret;
			rp[k] = mb[0];
			k++;
		} else
			n++;
	} else if (state == TCP_ST_ESTABLISHED) {
	}

	for (i = 0; i + n != num; i++) {
		rc[k + i] = EINVAL;
		rp[k + i] = mb[n + i];
	}

	return n;
}

uint16_t
tle_tcp_rx_bulk(struct tle_dev *dev, struct rte_mbuf *pkt[],
	struct rte_mbuf *rp[], int32_t rc[], uint16_t num)
{
	struct stbl *st;
	struct tle_tcp_stream *s;
	uint32_t i, j, k, n, t;
	union pkt_info pi[num];

	st = CTX_TCP_STLB(dev->ctx);

	for (i = 0; i != num; i++)
		pkt_info(pkt[i], &pi[i]);

	k = 0;
	for (i = 0; i != num; i += j) {

		j = pkt_info_bulk_eq(pi + i, num - i);

		s = rx_obtain_stream(dev, st, &pi[i]);
		if (s != NULL) {

			t = pi[i].tf.type;
			n = rx_stream(s, st, dev->rx.ol_flags[t], pi + i,
				pkt + i, rp + k, rc + k, j);
			k += j - n;

			if (n != 0 && s->rx.ev != NULL)
				tle_event_raise(s->rx.ev);
			rwl_release(&s->rx.use);

		} else {
			for (n = 0; n != j; n++) {
				rc[k + n] = ENOENT;
				rp[k + n] = pkt[i + n];
			}
			k += j;
		}
	}

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
	n = rte_ring_mc_dequeue_burst(s->rx.lq, (void **)se, num);
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
	if (n == num && rte_ring_count(s->rx.lq) != 0) {
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
	const struct tle_tcp_accept_param *prm)
{
	int32_t rc;
	union pkt_info pi;

	/* some TX still pending for that stream. */
	if (TCP_STREAM_TX_PENDING(cs))
		return -EAGAIN;

	pkt_info(prm->syn.pkt, &pi);

	/* setup L4 ports and L3 addresses fields. */
	cs->s.port.raw = pi.port.raw;
	cs->s.pmsk.raw = UINT32_MAX;

	if (pi.tf.type == TLE_V4) {
		cs->s.ipv4.addr = pi.addr4;
		cs->s.ipv4.mask.src = INADDR_NONE;
		cs->s.ipv4.mask.dst = INADDR_NONE;
	} else if (pi.tf.type == TLE_V4) {
		cs->s.ipv6.addr = *pi.addr6;
		rte_memcpy(&cs->s.ipv6.mask.src, &tle_ipv6_none,
			sizeof(cs->s.ipv6.mask.src));
		rte_memcpy(&cs->s.ipv6.mask.dst, &tle_ipv6_none,
			sizeof(cs->s.ipv6.mask.dst));
	}

	/* setup TCB */
	sync_fill_tcb(prm->syn.pkt, &cs->tcb);
	cs->tcb.state = TCP_ST_ESTABLISHED;

	/* setup stream notification menchanism */
	cs->rx.ev = prm->prm.recv_ev;
	cs->rx.cb = prm->prm.recv_cb;
	cs->tx.ev = prm->prm.send_ev;
	cs->tx.cb = prm->prm.send_cb;

	cs->prm = prm->prm;
	rte_atomic32_add(&ps->nb_kids, 1);
	cs->lrs = ps;

	tcp_stream_up(cs);

	/* copy streams type. */
	cs->s.type = ps->s.type;

	/* retrive and cache destination information. */
	rc = stream_fill_dest(cs);
	if (rc != 0)
		return rc;

	/* add stream to the table */
	cs->ste =  prm->syn.opaque;
	rte_smp_wmb();
	cs->ste->data = &cs->s;
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
	uint32_t i, j, n;
	int32_t rc;

	s = TCP_STREAM(ts);
	n = get_streams(s->s.ctx, rs, num);

	rc = 0;
	for (i = 0; rc == 0 && i != n; i++) {

		/* prepare new stream */
		cs = TCP_STREAM(rs[i]);
		rc = accept_fill_stream(s, cs, prm + i);
	}

	/* close failed stream, put unused streams back to the free list. */
	if (rc != 0) {
		tle_tcp_stream_close(rs[i - 1]);
		for (j = i; i != n; j++) {
			cs = TCP_STREAM(rs[j]);
			put_stream(s->s.ctx, rs[j], TCP_STREAM_TX_PENDING(cs));
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

	st = CTX_TCP_STLB(s->ctx);

	for (i = 0; i != num; i++) {
		mb = rq[i].pkt;
		pkt_info(mb, &pi);
		if (pi.tf.type < TLE_VNUM)
			stbl_del_pkt(st, rq[i].opaque, &pi);

		/* !!! send RST pkt to the peer !!! */
		rte_pktmbuf_free(mb);
	}
}

static inline void
stream_drb_release(struct tle_tcp_stream *s, struct tle_drb * drb[],
	uint32_t nb_drb)
{
	uint32_t n;

	n = rte_ring_count(s->tx.drb.r);
	rte_ring_enqueue_burst(s->tx.drb.r, (void **)drb, nb_drb);

	/*
	 * If stream is still open and has pkts to TX,
	 * then mark it as avaialble for TX again.
	 */
	if (n == 0 && rte_ring_count(s->tx.q) != 0 &&
			rwl_try_acquire(&s->tx.use) > 0) {
		/* !!! mark stream as ready for TX !!! */
	}

	rwl_release(&s->tx.use);
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
		stream_drb_release(s, drb + i, j - i);
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
	RTE_SET_USED(ts);
	RTE_SET_USED(pkt);
	RTE_SET_USED(num);
	return 0;
}

uint16_t
tle_tcp_stream_send(struct tle_stream *ts, struct rte_mbuf *pkt[], uint16_t num)
{
	RTE_SET_USED(ts);
	RTE_SET_USED(pkt);
	RTE_SET_USED(num);
	return 0;
}

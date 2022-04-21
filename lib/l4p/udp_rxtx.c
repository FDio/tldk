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

#include <rte_malloc.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_ip_frag.h>
#include <rte_udp.h>

#include "udp_stream.h"
#include "misc.h"

static inline struct tle_udp_stream *
rx_stream_obtain(struct tle_dev *dev, uint32_t type, uint32_t port)
{
	struct tle_udp_stream *s;

	if (type >= TLE_VNUM || dev->dp[type] == NULL)
		return NULL;

	s = (struct tle_udp_stream *)dev->dp[type]->streams[port];
	if (s == NULL)
		return NULL;

	if (rwl_acquire(&s->rx.use) < 0)
		return NULL;

	return s;
}

static inline uint16_t
get_pkt_type(const struct rte_mbuf *m)
{
	uint32_t v;

	v = m->packet_type &
		(RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_MASK);
	if (v == (RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_UDP))
		return TLE_V4;
	else if (v == (RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_UDP))
		return TLE_V6;
	else
		return TLE_VNUM;
}

static inline union l4_ports
pkt_info(struct rte_mbuf *m, union l4_ports *ports, union ipv4_addrs *addr4,
	union ipv6_addrs **addr6)
{
	uint32_t len;
	union l4_ports ret, *up;
	union ipv4_addrs *pa4;

	ret.src = get_pkt_type(m);

	len = m->l2_len;
	if (ret.src == TLE_V4) {
		pa4 = rte_pktmbuf_mtod_offset(m, union ipv4_addrs *,
			len + offsetof(struct rte_ipv4_hdr, src_addr));
		addr4->raw = pa4->raw;
	} else if (ret.src == TLE_V6) {
		*addr6 = rte_pktmbuf_mtod_offset(m, union ipv6_addrs *,
			len + offsetof(struct rte_ipv6_hdr, src_addr));
	}

	len += m->l3_len;
	up = rte_pktmbuf_mtod_offset(m, union l4_ports *,
		len + offsetof(struct rte_udp_hdr, src_port));
	ports->raw = up->raw;
	ret.dst = ports->dst;
	return ret;
}

/*
 * Helper routine, enqueues packets to the stream and calls RX
 * notification callback, if needed.
 */
static inline uint16_t
rx_stream(struct tle_udp_stream *s, void *mb[], struct rte_mbuf *rp[],
	int32_t rc[], uint32_t num)
{
	uint32_t i, k, r;

	r = _rte_ring_enqueue_burst(s->rx.q, mb, num);

	/* if RX queue was empty invoke user RX notification callback. */
	if (s->rx.cb.func != NULL && r != 0 && rte_ring_count(s->rx.q) == r)
		s->rx.cb.func(s->rx.cb.data, &s->s);

	for (i = r, k = 0; i != num; i++, k++) {
		rc[k] = ENOBUFS;
		rp[k] = mb[i];
	}

	return r;
}

static inline uint16_t
rx_stream6(struct tle_udp_stream *s, struct rte_mbuf *pkt[],
	union ipv6_addrs *addr[], union l4_ports port[],
	struct rte_mbuf *rp[], int32_t rc[], uint16_t num)
{
	uint32_t i, k, n;
	void *mb[num];

	k = 0;
	n = 0;

	for (i = 0; i != num; i++) {

		if ((port[i].raw & s->s.pmsk.raw) != s->s.port.raw ||
				ymm_mask_cmp(&addr[i]->raw, &s->s.ipv6.addr.raw,
				&s->s.ipv6.mask.raw) != 0) {
			rc[k] = ENOENT;
			rp[k] = pkt[i];
			k++;
		} else {
			mb[n] = pkt[i];
			n++;
		}
	}

	return rx_stream(s, mb, rp + k, rc + k, n);
}

static inline uint16_t
rx_stream4(struct tle_udp_stream *s, struct rte_mbuf *pkt[],
	union ipv4_addrs addr[], union l4_ports port[],
	struct rte_mbuf *rp[], int32_t rc[], uint16_t num)
{
	uint32_t i, k, n;
	void *mb[num];

	k = 0;
	n = 0;

	for (i = 0; i != num; i++) {

		if ((addr[i].raw & s->s.ipv4.mask.raw) != s->s.ipv4.addr.raw ||
				(port[i].raw & s->s.pmsk.raw) !=
				s->s.port.raw) {
			rc[k] = ENOENT;
			rp[k] = pkt[i];
			k++;
		} else {
			mb[n] = pkt[i];
			n++;
		}
	}

	return rx_stream(s, mb, rp + k, rc + k, n);
}

uint16_t
tle_udp_rx_bulk(struct tle_dev *dev, struct rte_mbuf *pkt[],
	struct rte_mbuf *rp[], int32_t rc[], uint16_t num)
{
	struct tle_udp_stream *s;
	uint32_t i, j, k, n, p, t;
	union l4_ports tp[num], port[num];
	union ipv4_addrs a4[num];
	union ipv6_addrs *pa6[num];

	for (i = 0; i != num; i++)
		tp[i] = pkt_info(pkt[i], &port[i], &a4[i], &pa6[i]);

	k = 0;
	for (i = 0; i != num; i = j) {

		for (j = i + 1; j != num && tp[j].raw == tp[i].raw; j++)
			;

		t = tp[i].src;
		p = tp[i].dst;
		s = rx_stream_obtain(dev, t, p);
		if (s != NULL) {

			if (t == TLE_V4)
				n = rx_stream4(s, pkt + i, a4 + i,
					port + i, rp + k, rc + k, j - i);
			else
				n = rx_stream6(s, pkt + i, pa6 + i, port + i,
					rp + k, rc + k, j - i);

			k += j - i - n;

			if (s->rx.ev != NULL)
				tle_event_raise(s->rx.ev);
			rwl_release(&s->rx.use);

		} else {
			for (; i != j; i++) {
				rc[k] = ENOENT;
				rp[k] = pkt[i];
				k++;
			}
		}
	}

	return num - k;
}

static inline void
stream_drb_release(struct tle_udp_stream *s, struct tle_drb *drb[],
	uint32_t nb_drb)
{
	uint32_t n;

	n = rte_ring_count(s->tx.drb.r);
	_rte_ring_enqueue_burst(s->tx.drb.r, (void **)drb, nb_drb);

	/* If stream is still open, then mark it as avaialble for writing. */
	if (rwl_try_acquire(&s->tx.use) > 0) {

		if (s->tx.ev != NULL)
			tle_event_raise(s->tx.ev);

		/* if stream send buffer was full invoke TX callback */
		else if (s->tx.cb.func != NULL && n == 0)
			s->tx.cb.func(s->tx.cb.data, &s->s);

	}

	rwl_release(&s->tx.use);
}

uint16_t
tle_udp_tx_bulk(struct tle_dev *dev, struct rte_mbuf *pkt[], uint16_t num)
{
	uint32_t i, j, k, n;
	struct tle_drb *drb[num];
	struct tle_udp_stream *s;

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
		stream_drb_release(s, drb + i, j - i);
	}

	return n;
}

/*
 * helper function, do the necessary pre-processing for the received packets
 * before handiing them to the strem_recv caller.
 */
static inline uint32_t
recv_pkt_process(struct rte_mbuf *m[], uint32_t num, uint32_t type)
{
	uint32_t i, k;
	uint64_t flg[num], ofl[num];

	for (i = 0; i != num; i++) {
		flg[i] = m[i]->ol_flags;
		ofl[i] = m[i]->tx_offload;
	}

	k = 0;
	for (i = 0; i != num; i++) {

		/* drop packets with invalid cksum(s). */
		if (check_pkt_csum(m[i], flg[i], type, IPPROTO_UDP) != 0) {
			rte_pktmbuf_free(m[i]);
			m[i] = NULL;
			k++;
		} else
			rte_pktmbuf_adj(m[i], _tx_offload_l4_offset(ofl[i]));
	}

	return k;
}

uint16_t
tle_udp_stream_recv(struct tle_stream *us, struct rte_mbuf *pkt[], uint16_t num)
{
	uint32_t k, n;
	struct tle_udp_stream *s;

	s = UDP_STREAM(us);
	n = _rte_ring_mc_dequeue_burst(s->rx.q, (void **)pkt, num);
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

	k = recv_pkt_process(pkt, n, s->s.type);
	return compress_pkt_list(pkt, n, k);
}

static inline int
udp_fill_mbuf(struct rte_mbuf *m,
	uint32_t type, uint64_t ol_flags, uint32_t pid,
	union udph udph, const struct tle_dest *dst)
{
	uint32_t len, plen;
	char *l2h;
	union udph *l4h;

	len = dst->l2_len + dst->l3_len;
	plen = m->pkt_len;

	/* copy to mbuf L2/L3 header template. */

	l2h = rte_pktmbuf_prepend(m, len + sizeof(*l4h));
	if (l2h == NULL)
		return -ENOBUFS;

	/* copy L2/L3 header */
	rte_memcpy(l2h, dst->hdr, len);

	/* copy UDP header */
	l4h = (union udph *)(l2h + len);
	l4h->raw = udph.raw;

	/* setup mbuf TX offload related fields. */
	m->tx_offload = _mbuf_tx_offload(dst->l2_len, dst->l3_len,
		sizeof(*l4h), 0, 0, 0);
	m->ol_flags |= ol_flags;

	l4h->len = rte_cpu_to_be_16(plen + sizeof(*l4h));

	/* update proto specific fields. */

	if (type == TLE_V4) {
		struct rte_ipv4_hdr *l3h;
		l3h = (struct rte_ipv4_hdr *)(l2h + dst->l2_len);
		l3h->packet_id = rte_cpu_to_be_16(pid);
		l3h->total_length = rte_cpu_to_be_16(plen + dst->l3_len +
			sizeof(*l4h));

		if ((ol_flags & RTE_MBUF_F_TX_UDP_CKSUM) != 0)
			l4h->cksum = _ipv4x_phdr_cksum(l3h, m->l3_len,
				ol_flags);
		else
			l4h->cksum = _ipv4_udptcp_mbuf_cksum(m, len, l3h);

		if ((ol_flags & RTE_MBUF_F_TX_IP_CKSUM) == 0)
			l3h->hdr_checksum = _ipv4x_cksum(l3h, m->l3_len);
	} else {
		struct rte_ipv6_hdr *l3h;
		l3h = (struct rte_ipv6_hdr *)(l2h + dst->l2_len);
		l3h->payload_len = rte_cpu_to_be_16(plen + sizeof(*l4h));
		if ((ol_flags & RTE_MBUF_F_TX_UDP_CKSUM) != 0)
			l4h->cksum = rte_ipv6_phdr_cksum(l3h, ol_flags);
		else
			l4h->cksum = _ipv6_udptcp_mbuf_cksum(m, len, l3h);
	}

	return 0;
}

/* ???
 * probably this function should be there -
 * rte_ipv[4,6]_fragment_packet should do that.
 */
static inline void
frag_fixup(const struct rte_mbuf *ms, struct rte_mbuf *mf, uint32_t type)
{
	struct rte_ipv4_hdr *l3h;

	mf->ol_flags = ms->ol_flags;
	mf->tx_offload = ms->tx_offload;

	if (type == TLE_V4 && (ms->ol_flags & RTE_MBUF_F_TX_IP_CKSUM) == 0) {
		l3h = rte_pktmbuf_mtod(mf, struct rte_ipv4_hdr *);
		l3h->hdr_checksum = _ipv4x_cksum(l3h, mf->l3_len);
	}
}

/*
 * Returns negative for failure to fragment or actual number of fragments.
 */
static inline int
fragment(struct rte_mbuf *pkt, struct rte_mbuf *frag[], uint32_t num,
	uint32_t type, const struct tle_dest *dst)
{
	int32_t frag_num, i;
	uint16_t mtu;
	void *eth_hdr;

	/* Remove the Ethernet header from the input packet */
	rte_pktmbuf_adj(pkt, dst->l2_len);
	mtu = dst->mtu - dst->l2_len;

	/* fragment packet */
	if (type == TLE_V4)
		frag_num = rte_ipv4_fragment_packet(pkt, frag, num, mtu,
			dst->head_mp, dst->head_mp);
	else
		frag_num = rte_ipv6_fragment_packet(pkt, frag, num, mtu,
			dst->head_mp, dst->head_mp);

	if (frag_num > 0) {
		for (i = 0; i != frag_num; i++) {

			frag_fixup(pkt, frag[i], type);

			/* Move data_off to include l2 header first */
			eth_hdr = rte_pktmbuf_prepend(frag[i], dst->l2_len);

			/* copy l2 header into fragment */
			rte_memcpy(eth_hdr, dst->hdr, dst->l2_len);
		}
	}

	return frag_num;
}

static inline void
stream_drb_free(struct tle_udp_stream *s, struct tle_drb *drbs[],
	uint32_t nb_drb)
{
	_rte_ring_enqueue_burst(s->tx.drb.r, (void **)drbs, nb_drb);
}

static inline uint32_t
stream_drb_alloc(struct tle_udp_stream *s, struct tle_drb *drbs[],
	uint32_t nb_drb)
{
	return _rte_ring_dequeue_burst(s->tx.drb.r, (void **)drbs, nb_drb);
}

/* enqueue up to num packets to the destination device queue. */
static inline uint16_t
queue_pkt_out(struct tle_udp_stream *s, struct tle_dev *dev,
		const void *pkt[], uint16_t nb_pkt,
		struct tle_drb *drbs[], uint32_t *nb_drb, uint8_t all_or_nothing)
{
	uint32_t bsz, i, n, nb, nbc, nbm;

	bsz = s->tx.drb.nb_elem;

	/* calulate how many drbs are needed.*/
	nbc = *nb_drb;
	nbm = (nb_pkt + bsz - 1) / bsz;
	nb = RTE_MAX(nbm, nbc) - nbc;

	/* allocate required drbs */
	if (nb != 0)
		nb = stream_drb_alloc(s, drbs + nbc, nb);

	nb += nbc;

	/* no free drbs, can't send anything */
	if (nb == 0)
		return 0;

	/* not enough free drbs, reduce number of packets to send. */
	else if (nb != nbm) {
		if (all_or_nothing)
			return 0;
		nb_pkt = nb * bsz;
	}

	/* enqueue packets to the destination device. */
	nbc = nb;
	n = tle_dring_mp_enqueue(&dev->tx.dr, pkt, nb_pkt, drbs, &nb);

	/* if not all available drbs were consumed, move them to the start. */
	nbc -= nb;
	for (i = 0; i != nb; i++)
		drbs[i] = drbs[nbc + i];

	*nb_drb = nb;
	return n;
}

uint16_t
tle_udp_stream_send(struct tle_stream *us, struct rte_mbuf *pkt[],
	uint16_t num, const struct sockaddr *dst_addr)
{
	int32_t di, frg, rc;
	uint64_t ol_flags;
	uint32_t i, k, n, nb;
	uint32_t mtu, pid, type;
	const struct sockaddr_in *d4;
	const struct sockaddr_in6 *d6;
	struct tle_udp_stream *s;
	const void *da;
	union udph udph;
	struct tle_dest dst;
	struct tle_drb *drb[num];

	s = UDP_STREAM(us);
	type = s->s.type;

	/* start filling UDP header. */
	udph.raw = 0;
	udph.ports.src = s->s.port.dst;

	/* figure out what destination addr/port to use. */
	if (dst_addr != NULL) {
		if (dst_addr->sa_family != s->prm.remote_addr.ss_family) {
			rte_errno = EINVAL;
			return 0;
		}
		if (type == TLE_V4) {
			d4 = (const struct sockaddr_in *)dst_addr;
			da = &d4->sin_addr;
			udph.ports.dst = d4->sin_port;
		} else {
			d6 = (const struct sockaddr_in6 *)dst_addr;
			da = &d6->sin6_addr;
			udph.ports.dst = d6->sin6_port;
		}
	} else {
		udph.ports.dst = s->s.port.src;
		if (type == TLE_V4)
			da = &s->s.ipv4.addr.src;
		else
			da = &s->s.ipv6.addr.src;
	}

	di = stream_get_dest(&s->s, da, &dst);
	if (di < 0) {
		rte_errno = -di;
		return 0;
	}

	pid = rte_atomic32_add_return(&dst.dev->tx.packet_id[type], num) - num;
	mtu = dst.mtu - dst.l2_len - dst.l3_len;

	/* mark stream as not closable. */
	if (rwl_acquire(&s->tx.use) < 0) {
		rte_errno = EAGAIN;
		return 0;
	}

	nb = 0;
	for (i = 0, k = 0; k != num; k = i) {

		/* copy L2/L3/L4 headers into mbufs, setup mbufs metadata. */

		frg = 0;
		ol_flags = dst.dev->tx.ol_flags[type];

		while (i != num && frg == 0) {
			frg = pkt[i]->pkt_len > mtu;
			if (frg != 0)
				ol_flags &= ~RTE_MBUF_F_TX_UDP_CKSUM;
			rc = udp_fill_mbuf(pkt[i], type, ol_flags, pid + i,
				udph, &dst);
			if (rc != 0) {
				rte_errno = -rc;
				goto out;
			}
			i += (frg == 0);
		}

		/* enqueue non-fragment packets to the destination device. */
		if (k != i) {
			k += queue_pkt_out(s, dst.dev,
				(const void **)(uintptr_t)&pkt[k], i - k,
				drb, &nb, 0);

			/* stream TX queue is full. */
			if (k != i) {
				rte_errno = EAGAIN;
				break;
			}
		}

		/* enqueue packet that need to be fragmented */
		if (i != num) {

			struct rte_mbuf *frag[RTE_LIBRTE_IP_FRAG_MAX_FRAG];

			/* fragment the packet. */
			rc = fragment(pkt[i], frag, RTE_DIM(frag), type, &dst);
			if (rc < 0) {
				rte_errno = -rc;
				break;
			}

			n = queue_pkt_out(s, dst.dev,
				(const void **)(uintptr_t)frag, rc, drb, &nb, 1);
			if (n == 0) {
				while (rc-- != 0)
					rte_pktmbuf_free(frag[rc]);
				rte_errno = EAGAIN;
				break;
			}

			/* all fragments enqueued, free the original packet. */
			rte_pktmbuf_free(pkt[i]);
			i++;
		}
	}

	/* if possible, rearm socket write event. */
	if (k == num && s->tx.ev != NULL)
		tle_event_raise(s->tx.ev);

out:
	/* free unused drbs. */
	if (nb != 0)
		stream_drb_free(s, drb, nb);

	/* stream can be closed. */
	rwl_release(&s->tx.use);

	/*
	 * remove pkt l2/l3 headers, restore ol_flags for unsent, but
	 * already modified packets.
	 */
	ol_flags = ~dst.dev->tx.ol_flags[type];
	for (n = k; n != i; n++) {
		rte_pktmbuf_adj(pkt[n], dst.l2_len + dst.l3_len + sizeof(udph));
		pkt[n]->ol_flags &= ol_flags;
	}

	return k;
}

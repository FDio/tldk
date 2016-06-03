
#include <rte_malloc.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_ip_frag.h>
#include <rte_udp.h>

#include "udp_impl.h"
#include "misc.h"

static inline struct tle_udp_stream *
rx_stream_obtain(struct tle_udp_dev *dev, uint32_t type, uint32_t port)
{
	struct tle_udp_stream *s;

	if (type >= TLE_UDP_VNUM || dev->dp[type] == NULL)
		return NULL;

	s = dev->dp[type]->streams[port];
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
		return TLE_UDP_V4;
	else if (v == (RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_UDP))
		return TLE_UDP_V6;
	else
		return TLE_UDP_VNUM;
}

static inline union udp_ports
pkt_info(const struct tle_udp_dev *dev, struct rte_mbuf *m,
	union udp_ports *ports, union ipv4_addrs *addr4,
	union ipv6_addrs **addr6)
{
	uint32_t len;
	union udp_ports ret, *up;
	union ipv4_addrs *pa4;

	ret.src = get_pkt_type(m);

	len = m->l2_len;
	if (ret.src == TLE_UDP_V4) {
		pa4 = rte_pktmbuf_mtod_offset(m, union ipv4_addrs *,
			len + offsetof(struct ipv4_hdr, src_addr));
		addr4->raw = pa4->raw;
		m->ol_flags |= dev->rx.ol_flags[TLE_UDP_V4];
	} else if (ret.src == TLE_UDP_V6) {
		*addr6 = rte_pktmbuf_mtod_offset(m, union ipv6_addrs *,
			len + offsetof(struct ipv6_hdr, src_addr));
		m->ol_flags |= dev->rx.ol_flags[TLE_UDP_V6];
	}

	len += m->l3_len;
	up = rte_pktmbuf_mtod_offset(m, union udp_ports *,
		len + offsetof(struct udp_hdr, src_port));
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

	r = rte_ring_enqueue_burst(s->rx.q, mb, num);

	/* if RX queue was empty invoke user RX notification callback. */
	if (s->rx.cb.func != NULL && r != 0 && rte_ring_count(s->rx.q) == r)
		s->rx.cb.func(s->rx.cb.data, s);

	for (i = r, k = 0; i != num; i++, k++) {
		rc[k] = ENOBUFS;
		rp[k] = mb[i];
	}

	return r;
}

static inline uint16_t
rx_stream6(struct tle_udp_stream *s, struct rte_mbuf *pkt[],
	union ipv6_addrs *addr[], union udp_ports port[],
	struct rte_mbuf *rp[], int32_t rc[], uint16_t num)
{
	uint32_t i, k, n;
	void *mb[num];

	k = 0;
	n = 0;

	for (i = 0; i != num; i++) {

		if ((port[i].raw & s->pmsk.raw) != s->port.raw ||
				ymm_mask_cmp(&addr[i]->raw, &s->ipv6.addr.raw,
				&s->ipv6.mask.raw) != 0) {
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
	union ipv4_addrs addr[], union udp_ports port[],
	struct rte_mbuf *rp[], int32_t rc[], uint16_t num)
{
	uint32_t i, k, n;
	void *mb[num];

	k = 0;
	n = 0;

	for (i = 0; i != num; i++) {

		if ((addr[i].raw & s->ipv4.mask.raw) != s->ipv4.addr.raw ||
				(port[i].raw & s->pmsk.raw) !=
				s->port.raw) {
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
tle_udp_rx_bulk(struct tle_udp_dev *dev, struct rte_mbuf *pkt[],
	struct rte_mbuf *rp[], int32_t rc[], uint16_t num)
{
	struct tle_udp_stream *s;
	uint32_t i, j, k, n, p, t;
	union udp_ports tp[num], port[num];
	union ipv4_addrs a4[num];
	union ipv6_addrs *pa6[num];

	for (i = 0; i != num; i++)
		tp[i] = pkt_info(dev, pkt[i], &port[i], &a4[i], &pa6[i]);

	k = 0;
	for (i = 0; i != num; i = j) {

		for (j = i + 1; j != num && tp[j].raw == tp[i].raw; j++)
			;

		t = tp[i].src;
		p = tp[i].dst;
		s = rx_stream_obtain(dev, t, p);
		if (s != NULL) {

			if (t == TLE_UDP_V4)
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
tx_cage_release(struct buf_cage *bc)
{
	struct tle_udp_stream *s;
	uint32_t n;

	s = bcg_get_udata(bc);
	n = bcg_free(bc);

	/* If stream is still open, then mark it as avaialble for writing. */
	if (rwl_try_acquire(&s->tx.use) > 0) {

		if (s->tx.ev != NULL)
			tle_event_raise(s->tx.ev);

		/* if stream send buffer was full invoke TX callback */
		else if (s->tx.cb.func != NULL && n == 1)
			s->tx.cb.func(s->tx.cb.data, s);

	}

	rwl_release(&s->tx.use);
}

static inline void
tx_cage_update(struct tle_udp_dev *dev, struct buf_cage *bc)
{
	struct tle_udp_stream *s;
	struct tle_udp_ctx *ctx;
	uint32_t idx;

	ctx = dev->ctx;
	s = bcg_get_udata(bc);
	idx = dev - ctx->dev;

	/* mark cage as closed to the stream. */
	rte_spinlock_lock(&s->tx.lock);
	if (bc == s->tx.cg[idx])
		s->tx.cg[idx] = NULL;
	rte_spinlock_unlock(&s->tx.lock);
}

uint16_t
tle_udp_tx_bulk(struct tle_udp_dev *dev, struct rte_mbuf *pkt[], uint16_t num)
{
	struct buf_cage *bc;
	uint32_t i, n;

	for (i = 0; i != num; i += n) {

		bc = dev->tx.bc;
		if (bc == NULL) {
			if (dev->tx.beq.num == 0)
				bcg_queue_append(&dev->tx.beq, &dev->tx.feq);
			bc = __bcg_dequeue_head(&dev->tx.beq);
			if (bc == NULL)
				break;
			tx_cage_update(dev, bc);
			dev->tx.bc = bc;
		}

		n = bcg_get(bc, (const void **)(uintptr_t)&pkt[i], num - i);

		/* cage is empty, need to free it and notify related stream. */
		if (bcg_fill_count(bc) == 0) {
			tx_cage_release(bc);
			dev->tx.bc = NULL;
		}
	}

	return i;
}

static int
check_pkt_csum(const struct rte_mbuf *m, uint32_t type)
{
	const struct ipv4_hdr *l3h4;
	const struct ipv6_hdr *l3h6;
	const struct udp_hdr *l4h;
	int32_t ret;
	uint16_t csum;

	ret = 0;
	l3h4 = rte_pktmbuf_mtod_offset(m, const struct ipv4_hdr *, m->l2_len);
	l3h6 = rte_pktmbuf_mtod_offset(m, const struct ipv6_hdr *, m->l2_len);

	if ((m->ol_flags & PKT_RX_IP_CKSUM_BAD) != 0) {
		csum = _ipv4x_cksum(l3h4, m->l3_len);
		ret = (csum != UINT16_MAX);
	}

	if (ret == 0 && (m->ol_flags & PKT_RX_L4_CKSUM_BAD) != 0) {

		/*
		 * for IPv4 it is allowed to have zero UDP cksum,
		 * for IPv6 valid UDP cksum is mandatory.
		 */
		if (type == TLE_UDP_V4) {
			l4h = (const struct udp_hdr *)((uintptr_t)l3h4 +
				m->l3_len);
			csum = (l4h->dgram_cksum == 0) ? UINT16_MAX :
				_ipv4_udptcp_mbuf_cksum(m,
				m->l2_len + m->l3_len, l3h4);
		} else
			csum = _ipv6_udptcp_mbuf_cksum(m,
				m->l2_len + m->l3_len, l3h6);

		ret = (csum != UINT16_MAX);
	}

	return ret;
}

/* exclude NULLs from the final list of packets. */
static inline uint32_t
compress_pkt_list(struct rte_mbuf *pkt[], uint32_t nb_pkt, uint32_t nb_zero)
{
	uint32_t i, j, k, l;

	for (j = nb_pkt; nb_zero != 0 && j-- != 0; ) {

		/* found a hole. */
		if (pkt[j] == NULL) {

			/* find how big is it. */
			for (i = j; i-- != 0 && pkt[i] == NULL; )
				;
			/* fill the hole. */
			for (k = j + 1, l = i + 1; k != nb_pkt; k++, l++)
				pkt[l] = pkt[k];

			nb_pkt -= j - i;
			nb_zero -= j - i;
		}
	}

	return nb_pkt;
}

/*
 * helper function, do the necessary pre-processing for the received packets
 * before handiing them to the strem_recv caller.
 */
static inline struct rte_mbuf *
recv_pkt_process(struct rte_mbuf *m, uint32_t type)
{
	uint64_t f;

	f = m->ol_flags & (PKT_RX_IP_CKSUM_BAD | PKT_RX_L4_CKSUM_BAD);
	if (f != 0) {
		if (check_pkt_csum(m, type) == 0)
			m->ol_flags ^= f;
		else {
			rte_pktmbuf_free(m);
			return NULL;
		}
	}

	rte_pktmbuf_adj(m, m->l2_len + m->l3_len + m->l4_len);
	return m;
}

uint16_t
tle_udp_stream_recv(struct tle_udp_stream *s, struct rte_mbuf *pkt[],
	uint16_t num)
{
	uint32_t i, k, n;

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

	k = 0;
	for (i = 0; i != RTE_ALIGN_FLOOR(n, 4); i += 4) {
		pkt[i] = recv_pkt_process(pkt[i], s->type);
		pkt[i + 1] = recv_pkt_process(pkt[i + 1], s->type);
		pkt[i + 2] = recv_pkt_process(pkt[i + 2], s->type);
		pkt[i + 3] = recv_pkt_process(pkt[i + 3], s->type);
		k += (pkt[i] == NULL) + (pkt[i + 1] == NULL) +
			(pkt[i + 2] == NULL) + (pkt[i + 3] == NULL);
	}

	switch (n % 4) {
	case 3:
		pkt[i + 2] = recv_pkt_process(pkt[i + 2], s->type);
		k += (pkt[i + 2] == NULL);
	case 2:
		pkt[i + 1] = recv_pkt_process(pkt[i + 1], s->type);
		k += (pkt[i + 1] == NULL);
	case 1:
		pkt[i] = recv_pkt_process(pkt[i], s->type);
		k += (pkt[i] == NULL);
	}

	return compress_pkt_list(pkt, n, k);
}

static int32_t
udp_get_dest(struct tle_udp_stream *s, const void *dst_addr,
	struct tle_udp_dest *dst)
{
	int32_t rc;
	const struct in_addr *d4;
	const struct in6_addr *d6;
	struct tle_udp_ctx *ctx;
	struct tle_udp_dev *dev;

	ctx = s->ctx;

	/* it is here just to keep gcc happy. */
	d4 = NULL;

	if (s->type == TLE_UDP_V4) {
		d4 = dst_addr;
		rc = ctx->prm.lookup4(ctx->prm.lookup4_data, d4, dst);
	} else if (s->type == TLE_UDP_V6) {
		d6 = dst_addr;
		rc = ctx->prm.lookup6(ctx->prm.lookup6_data, d6, dst);
	} else
		rc = -ENOENT;

	if (rc < 0 || dst->dev == NULL || dst->dev->ctx != ctx)
		return -ENOENT;

	dev = dst->dev;
	if (s->type == TLE_UDP_V4) {
		struct ipv4_hdr *l3h;
		l3h = (struct ipv4_hdr *)(dst->hdr + dst->l2_len);
		l3h->src_addr = dev->prm.local_addr4.s_addr;
		l3h->dst_addr = d4->s_addr;
	} else {
		struct ipv6_hdr *l3h;
		l3h = (struct ipv6_hdr *)(dst->hdr + dst->l2_len);
		rte_memcpy(l3h->src_addr, &dev->prm.local_addr6,
			sizeof(l3h->src_addr));
		rte_memcpy(l3h->dst_addr, d6, sizeof(l3h->dst_addr));
	}

	return dev - ctx->dev;
}

static inline int
udp_fill_mbuf(struct rte_mbuf *m,
	uint32_t type, uint64_t ol_flags, uint32_t pid,
	union udph udph, const struct tle_udp_dest *dst)
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

	if (type == TLE_UDP_V4) {
		struct ipv4_hdr *l3h;
		l3h = (struct ipv4_hdr *)(l2h + dst->l2_len);
		l3h->packet_id = rte_cpu_to_be_16(pid);
		l3h->total_length = rte_cpu_to_be_16(plen + dst->l3_len +
			sizeof(*l4h));

		if ((ol_flags & PKT_TX_UDP_CKSUM) != 0)
			l4h->cksum = _ipv4x_phdr_cksum(l3h, m->l3_len,
				ol_flags);
		else
			l4h->cksum = _ipv4_udptcp_mbuf_cksum(m, len, l3h);

		if ((ol_flags & PKT_TX_IP_CKSUM) == 0)
			l3h->hdr_checksum = _ipv4x_cksum(l3h, m->l3_len);
	} else {
		struct ipv6_hdr *l3h;
		l3h = (struct ipv6_hdr *)(l2h + dst->l2_len);
		l3h->payload_len = rte_cpu_to_be_16(plen + sizeof(*l4h));
		if ((ol_flags & PKT_TX_UDP_CKSUM) != 0)
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
	struct ipv4_hdr *l3h;

	mf->ol_flags = ms->ol_flags;
	mf->tx_offload = ms->tx_offload;

	if (type == TLE_UDP_V4 && (ms->ol_flags & PKT_TX_IP_CKSUM) == 0) {
		l3h = rte_pktmbuf_mtod(mf, struct ipv4_hdr *);
		l3h->hdr_checksum = _ipv4x_cksum(l3h, mf->l3_len);
	}
}

/*
 * Returns negative for failure to fragment or actual number of fragments.
 */
static inline int
fragment(struct rte_mbuf *pkt, struct rte_mbuf *frag[], uint32_t num,
	uint32_t type, const struct tle_udp_dest *dst)
{
	int32_t frag_num, i;
	uint16_t mtu;
	void *eth_hdr;

	/* Remove the Ethernet header from the input packet */
	rte_pktmbuf_adj(pkt, dst->l2_len);
	mtu = dst->mtu - dst->l2_len;

	/* fragment packet */
	if (type == TLE_UDP_V4)
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

/* enqueue up to num packets to the destination device queue. */
static inline uint16_t
queue_pkt_out(struct tle_udp_stream *s, struct bcg_queue *bq, uint32_t di,
	const void *pkt[], uint16_t num)
{
	struct buf_cage *bc;
	uint32_t i, n;

	rte_spinlock_lock(&s->tx.lock);
	bc = s->tx.cg[di];

	for (i = 0; i != num; i += n) {
		if (bc == NULL) {
			bc = bcg_alloc(s->tx.st);
			if (bc == NULL)
				break;
			n = bcg_put(bc, pkt + i, num - i);
			bcg_enqueue_tail(bq, bc);
		} else
			n = bcg_put(bc, pkt + i, num - i);

		if (n != num - i)
			bc = NULL;
	}

	s->tx.cg[di] = bc;
	rte_spinlock_unlock(&s->tx.lock);
	return i;
}

/*
 * etiher enqueue all num packets or none.
 * assumes that all number of input packets not exceed size of buf_cage.
 */
static inline uint16_t
queue_frg_out(struct tle_udp_stream *s, struct bcg_queue *bq, uint32_t di,
	const void *pkt[], uint16_t num)
{
	struct buf_cage *bc, *bcp;
	uint32_t n;

	rte_spinlock_lock(&s->tx.lock);
	bc = s->tx.cg[di];

	n = 0;
	if (bc == NULL || bcg_free_count(bc) < num) {
		bcp = bc;
		bc = bcg_alloc(s->tx.st);
		if (bc != NULL) {
			if (bcp != NULL)
				n = bcg_put(bcp, pkt, num);
			n += bcg_put(bc, pkt, num - n);
			bcg_enqueue_tail(bq, bc);
		}
	} else
		n = bcg_put(bc, pkt, num);

	s->tx.cg[di] = bc;
	rte_spinlock_unlock(&s->tx.lock);
	return n;
}

uint16_t
tle_udp_stream_send(struct tle_udp_stream *s, struct rte_mbuf *pkt[],
	uint16_t num, const struct sockaddr *dst_addr)
{
	int32_t di, frg, rc;
	uint64_t ol_flags;
	uint32_t i, k, n;
	uint32_t mtu, pid, type;
	const struct sockaddr_in *d4;
	const struct sockaddr_in6 *d6;
	const void *da;
	union udph udph;
	struct tle_udp_dest dst;

	type = s->type;

	/* start filling UDP header. */
	udph.raw = 0;
	udph.ports.src = s->port.dst;

	/* figure out what destination addr/port to use. */
	if (dst_addr != NULL) {
		if (dst_addr->sa_family != s->prm.remote_addr.ss_family) {
			rte_errno = EINVAL;
			return 0;
		}
		if (type == TLE_UDP_V4) {
			d4 = (const struct sockaddr_in *)dst_addr;
			da = &d4->sin_addr;
			udph.ports.dst = d4->sin_port;
		} else {
			d6 = (const struct sockaddr_in6 *)dst_addr;
			da = &d6->sin6_addr;
			udph.ports.dst = d6->sin6_port;
		}
	} else {
		udph.ports.dst = s->port.src;
		if (type == TLE_UDP_V4)
			da = &s->ipv4.addr.src;
		else
			da = &s->ipv6.addr.src;
	}

	di = udp_get_dest(s, da, &dst);
	if (di < 0) {
		rte_errno = -di;
		return 0;
	}

	pid = rte_atomic32_add_return(&dst.dev->tx.packet_id[type], num) - num;
	mtu = dst.mtu - dst.l2_len - dst.l3_len;

	/* mark stream as not closable. */
	if (rwl_acquire(&s->tx.use) < 0)
		return 0;

	for (i = 0, k = 0; k != num; k = i) {

		/* copy L2/L3/L4 headers into mbufs, setup mbufs metadata. */

		frg = 0;
		ol_flags = dst.dev->tx.ol_flags[type];

		while (i != num && frg == 0) {
			frg = pkt[i]->pkt_len > mtu;
			if (frg != 0)
				ol_flags &= ~PKT_TX_UDP_CKSUM;
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
			k += queue_pkt_out(s, &dst.dev->tx.feq, di,
				(const void **)(uintptr_t)&pkt[k], i - k);

			/* stream TX queue is full. */
			if (k != i)
				break;
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

			n = queue_frg_out(s, &dst.dev->tx.feq, di,
				(const void **)(uintptr_t)frag, rc);
			if (n == 0) {
				while (rc-- != 0)
					rte_pktmbuf_free(frag[rc]);
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

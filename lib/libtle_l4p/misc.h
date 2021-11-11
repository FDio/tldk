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

#ifndef _MISC_H_
#define _MISC_H_

#include <tle_dpdk_wrapper.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline int
xmm_cmp(const rte_xmm_t *da, const rte_xmm_t *sa)
{
	uint64_t ret;

	ret = (sa->u64[0] ^ da->u64[0]) |
		(sa->u64[1] ^ da->u64[1]);

	return (ret != 0);
}

static inline int
ymm_cmp(const _ymm_t *da, const _ymm_t *sa)
{
	uint64_t ret;

	ret = (sa->u64[0] ^ da->u64[0]) |
		(sa->u64[1] ^ da->u64[1]) |
		(sa->u64[2] ^ da->u64[2]) |
		(sa->u64[3] ^ da->u64[3]);

	return (ret != 0);
}

static inline int
ymm_mask_cmp(const _ymm_t *da, const _ymm_t *sa, const _ymm_t *sm)
{
	uint64_t ret;

	ret = ((da->u64[0] & sm->u64[0]) ^ sa->u64[0]) |
		((da->u64[1] & sm->u64[1]) ^ sa->u64[1]) |
		((da->u64[2] & sm->u64[2]) ^ sa->u64[2]) |
		((da->u64[3] & sm->u64[3]) ^ sa->u64[3]);

	return (ret != 0);
}

/*
 * Setup tx_offload field inside mbuf using raw 64-bit field.
 * Consider to move it into DPDK librte_mbuf.
 */
static inline uint64_t
_mbuf_tx_offload(uint64_t il2, uint64_t il3, uint64_t il4, uint64_t tso,
	uint64_t ol3, uint64_t ol2)
{
	return il2 | il3 << 7 | il4 << 16 | tso << 24 | ol3 << 40 | ol2 << 49;
}

/*
 * Given the value of mbuf's tx_offload, calculate L4 payload offset.
 */
static inline uint32_t
_tx_offload_l4_offset(uint64_t ofl)
{
	uint32_t l2, l3, l4;

	l2 = ofl & 0x7f;
	l3 = ofl >> 7 & 0x1ff;
	l4 = ofl >> 16 & UINT8_MAX;

	return l2 + l3 + l4;
}

/*
 * Routines to calculate L3/L4 checksums in SW.
 * Pretty similar to ones from DPDK librte_net/rte_ip.h,
 * but provide better performance (at least for tested configurations),
 * and extended functionality.
 * Consider to move them into DPDK librte_net/rte_ip.h.
 */

/* make compiler to generate: add %r1, %r2; adc $0, %r1. */
#define CKSUM_ADD_CARRY(s, v)	do {       \
	(s) += (v);                        \
	(s) = ((s) < (v)) ? (s) + 1 : (s); \
} while (0)

/**
 * Process the non-complemented checksum of a buffer.
 * Similar  to rte_raw_cksum(), but provide better performance
 * (at least on IA platforms).
 * @param buf
 *   Pointer to the buffer.
 * @param size
 *   Length of the buffer.
 * @return
 *   The non-complemented checksum.
 */
static inline uint16_t
__raw_cksum(const uint8_t *buf, uint32_t size)
{
	uint64_t s, sum;
	uint32_t i, n;
	uint32_t dw1, dw2;
	uint16_t w1, w2;
	const uint64_t *b;

	b = (const uint64_t *)buf;
	n = size / sizeof(*b);
	sum = 0;

	/* main loop, consume 8 bytes per iteration. */
	for (i = 0; i != n; i++) {
		s = b[i];
		CKSUM_ADD_CARRY(sum, s);
	}

	/* consume the remainder. */
	n = size % sizeof(*b);
	if (n != 0) {
		/* position of the of last 8 bytes of data. */
		b = (const uint64_t *)((uintptr_t)(b + i) + n - sizeof(*b));
		/* calculate shift amount. */
		n = (sizeof(*b) - n) * CHAR_BIT;
		s = b[0] >> n;
		CKSUM_ADD_CARRY(sum, s);
	}

	/* reduce to 16 bits */
	dw1 = sum;
	dw2 = sum >> 32;
	CKSUM_ADD_CARRY(dw1, dw2);
	w1 = dw1;
	w2 = dw1 >> 16;
	CKSUM_ADD_CARRY(w1, w2);
	return w1;
}

/**
 * Process UDP or TCP checksum over possibly multi-segmented packet.
 * @param mb
 *   The pointer to the mbuf with the packet.
 * @param l4_ofs
 *   Offset to the beginning of the L4 header (should be in first segment).
 * @param cksum
 *   Already pre-calculated pseudo-header checksum value.
 * @return
 *   The complemented checksum.
 */
static inline uint32_t
__udptcp_mbuf_cksum(const struct rte_mbuf *mb, uint16_t l4_ofs,
	uint32_t cksum)
{
	uint32_t dlen, i, plen;
	const struct rte_mbuf *ms;
	const void *data;

	plen = rte_pktmbuf_pkt_len(mb);
	ms = mb;

	for (i = l4_ofs; i < plen && ms != NULL; i += dlen) {
		data = rte_pktmbuf_mtod_offset(ms, const void *, l4_ofs);
		dlen = rte_pktmbuf_data_len(ms) - l4_ofs;
		cksum += __raw_cksum(data, dlen);
		ms = ms->next;
		l4_ofs = 0;
	}

	cksum = ((cksum & 0xffff0000) >> 16) + (cksum & 0xffff);
	cksum = (~cksum) & 0xffff;
	if (cksum == 0)
		cksum = 0xffff;

	return cksum;
}

/**
 * Process the pseudo-header checksum of an IPv4 header.
 *
 * Depending on the ol_flags, the pseudo-header checksum expected by the
 * drivers is not the same. For instance, when TSO is enabled, the IP
 * payload length must not be included in the packet.
 *
 * When ol_flags is 0, it computes the standard pseudo-header checksum.
 *
 * @param ipv4_hdr
 *   The pointer to the contiguous IPv4 header.
 * @param ipv4_len
 *   Length of the IPv4 header.
 * @param ol_flags
 *   The ol_flags of the associated mbuf.
 * @return
 *   The non-complemented checksum to set in the L4 header.
 */
static inline uint16_t
_ipv4x_phdr_cksum(const struct rte_ipv4_hdr *ipv4_hdr, size_t ipv4h_len,
	uint64_t ol_flags)
{
	uint32_t s0, s1;

	s0 = ipv4_hdr->src_addr;
	s1 = ipv4_hdr->dst_addr;
	CKSUM_ADD_CARRY(s0, s1);

	if (ol_flags & RTE_MBUF_F_TX_TCP_SEG)
		s1 = 0;
	else
		s1 = rte_cpu_to_be_16(
			(uint16_t)(rte_be_to_cpu_16(ipv4_hdr->total_length) -
			ipv4h_len));

	s1 += rte_cpu_to_be_16(ipv4_hdr->next_proto_id);
	CKSUM_ADD_CARRY(s0, s1);

	return __rte_raw_cksum_reduce(s0);
}

/**
 * Process the IPv4 UDP or TCP checksum.
 *
 * @param mb
 *   The pointer to the IPv4 packet.
 * @param l4_ofs
 *   Offset to the beginning of the L4 header (should be in first segment).
 * @param ipv4_hdr
 *   The pointer to the contiguous IPv4 header.
 * @return
 *   The complemented checksum to set in the IP packet.
 */
static inline int
_ipv4_udptcp_mbuf_cksum(const struct rte_mbuf *mb, uint16_t l4_ofs,
	const struct rte_ipv4_hdr *ipv4_hdr)
{
	uint32_t cksum;

	cksum = _ipv4x_phdr_cksum(ipv4_hdr, mb->l3_len, 0);
	cksum = __udptcp_mbuf_cksum(mb, l4_ofs, cksum);

	return cksum;
}

/**
 * Process the IPv6 UDP or TCP checksum.
 *
 * @param mb
 *   The pointer to the IPv6 packet.
 * @param l4_ofs
 *   Offset to the beginning of the L4 header (should be in first segment).
 * @param ipv6_hdr
 *   The pointer to the contiguous IPv6 header.
 * @return
 *   The complemented checksum to set in the IP packet.
 */
static inline int
_ipv6_udptcp_mbuf_cksum(const struct rte_mbuf *mb, uint16_t l4_ofs,
	const struct rte_ipv6_hdr *ipv6_hdr)
{
	uint32_t cksum;

	cksum = rte_ipv6_phdr_cksum(ipv6_hdr, 0);
	cksum = __udptcp_mbuf_cksum(mb, l4_ofs, cksum);

	return cksum;
}

static inline uint16_t
_ipv4x_cksum(const void *iph, size_t len)
{
	uint16_t cksum;

	cksum = __raw_cksum(iph, len);
	return (cksum == 0xffff) ? cksum : ~cksum;
}

/*
 * helper function to check csum.
 */
static inline int
check_pkt_csum(const struct rte_mbuf *m, uint64_t ol_flags, uint32_t type,
	uint32_t proto)
{
	const struct rte_ipv4_hdr *l3h4;
	const struct rte_ipv6_hdr *l3h6;
	const struct rte_udp_hdr *l4h;
	uint64_t fl3, fl4;
	uint16_t csum;
	int32_t ret;

	fl4 = ol_flags & RTE_MBUF_F_RX_L4_CKSUM_MASK;
	fl3 = (type == TLE_V4) ?
		(ol_flags & RTE_MBUF_F_RX_IP_CKSUM_MASK) : RTE_MBUF_F_RX_IP_CKSUM_GOOD;

	/* case 0: both ip and l4 cksum is verified or data is valid */
	if ((fl3 | fl4) == (RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_GOOD))
		return 0;

	/* case 1: either ip or l4 cksum bad */
	if (fl3 == RTE_MBUF_F_RX_IP_CKSUM_BAD || fl4 == RTE_MBUF_F_RX_L4_CKSUM_BAD)
		return 1;

	/* case 2: either ip or l4 or both cksum is unknown */
	l3h4 = rte_pktmbuf_mtod_offset(m, const struct rte_ipv4_hdr *,
		m->l2_len);
	l3h6 = rte_pktmbuf_mtod_offset(m, const struct rte_ipv6_hdr *,
		m->l2_len);

	ret = 0;
	if (fl3 == RTE_MBUF_F_RX_IP_CKSUM_UNKNOWN && l3h4->hdr_checksum != 0) {
		csum = _ipv4x_cksum(l3h4, m->l3_len);
		ret = (csum != UINT16_MAX);
	}

	if (ret == 0 && fl4 == RTE_MBUF_F_RX_L4_CKSUM_UNKNOWN) {

		/*
		 * for IPv4 it is allowed to have zero UDP cksum,
		 * for IPv6 valid UDP cksum is mandatory.
		 */
		if (type == TLE_V4) {
			l4h = (const struct rte_udp_hdr *)((uintptr_t)l3h4 +
				m->l3_len);
			csum = (proto == IPPROTO_UDP && l4h->dgram_cksum == 0) ?
				UINT16_MAX : _ipv4_udptcp_mbuf_cksum(m,
				m->l2_len + m->l3_len, l3h4);
		} else
			csum = _ipv6_udptcp_mbuf_cksum(m,
				m->l2_len + m->l3_len, l3h6);

		ret = (csum != UINT16_MAX);
	}

	return ret;
}

/*
 * Analog of read-write locks, very much in favour of read side.
 * Assumes, that there are no more then INT32_MAX concurrent readers.
 * Consider to move into DPDK librte_eal.
 */

static inline int
rwl_try_acquire(rte_atomic32_t *p)
{
	return rte_atomic32_add_return(p, 1);
}

static inline void
rwl_release(rte_atomic32_t *p)
{
	rte_atomic32_sub(p, 1);
}

static inline int
rwl_acquire(rte_atomic32_t *p)
{
	int32_t rc;

	rc = rwl_try_acquire(p);
	if (rc < 0)
		rwl_release(p);
	return rc;
}

static inline void
rwl_down(rte_atomic32_t *p)
{
	 while (rte_atomic32_cmpset((volatile uint32_t *)p, 0, INT32_MIN) == 0)
		rte_pause();
}

static inline void
rwl_up(rte_atomic32_t *p)
{
	rte_atomic32_sub(p, INT32_MIN);
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
			j = i + 1;
		}
	}

	return nb_pkt;
}

static inline void
free_mbufs(struct rte_mbuf *mb[], uint32_t num)
{
	uint32_t i;

	for (i = 0; i != num; i++)
		rte_pktmbuf_free(mb[i]);
}

/* empty ring and free queued mbufs */
static inline void
empty_mbuf_ring(struct rte_ring *r)
{
	uint32_t n;
	struct rte_mbuf *mb[MAX_PKT_BURST];

	do {
		n = _rte_ring_dequeue_burst(r, (void **)mb, RTE_DIM(mb));
		free_mbufs(mb, n);
	} while (n != 0);
}

static inline uint32_t
_mbus_to_iovec(struct iovec *iv, struct rte_mbuf *mb[], uint32_t num)
{
	uint32_t i, ns;
	uint32_t len, slen, tlen;
	struct rte_mbuf *m, *next;
	const void *src;

	for (i = 0; i != num; i++) {

		m = mb[i];
		tlen = 0;
		ns = 0;

		do {
			slen = m->data_len;
			src = rte_pktmbuf_mtod(m, const void *);
			len = RTE_MIN(iv->iov_len - tlen, slen);
			rte_memcpy((uint8_t *)iv->iov_base + tlen, src, len);
			slen -= len;
			tlen += len;
			if (slen != 0)
				break;
			ns++;
			next = m->next;
			rte_pktmbuf_free_seg(m);
 			m = next;
		 } while (m != NULL);

		iv->iov_base = (uint8_t *)iv->iov_base + tlen;
		iv->iov_len -= tlen;

		/* partly consumed mbuf */
		if (m != NULL) {
			m->pkt_len = mb[i]->pkt_len - tlen;
			m->data_len = slen;
			m->data_off += len;
			m->nb_segs = mb[i]->nb_segs - ns;
			mb[i] = m;
			break;
		}
	}

	return i;
}

static inline uint32_t
_iovec_to_mbsegs(struct iovec *iv, uint32_t seglen, struct rte_mbuf *mb[],
	uint32_t num)
{
	uint32_t i;
	uint32_t len, slen, tlen;
	struct rte_mbuf *m;
	void *dst;

	tlen = 0;
	for (i = 0; i != num; i++) {

		m = mb[i];
		slen = rte_pktmbuf_tailroom(m);
		slen = RTE_MIN(slen, seglen - m->data_len);
		len = RTE_MIN(iv->iov_len - tlen, slen);
		dst = rte_pktmbuf_append(m, len);
		rte_memcpy(dst, (uint8_t *)iv->iov_base + tlen, len);
		tlen += len;
		if (len != slen)
			break;
	}

	iv->iov_base = (uint8_t *)iv->iov_base + tlen;
	iv->iov_len -= tlen;

	return i;
}

/**
 * Remove len bytes at the beginning of an mbuf.
 *
 * It's an enhancement version of rte_pktmbuf_abj which not support
 * adjusting length greater than the length of the first segment.
 *
 * Returns a pointer to the new mbuf. If the
 * length is greater than the total length of the mbuf, then the
 * function will fail and return NULL, without modifying the mbuf.
 *
 * @param m
 *   The packet mbuf.
 * @param len
 *   The amount of data to remove (in bytes).
 * @return
 *   A pointer to the new start of the data.
 */
static inline struct rte_mbuf *
_rte_pktmbuf_adj(struct rte_mbuf *m, uint32_t len)
{
	struct rte_mbuf *next;
	uint32_t remain, plen;
	uint16_t segs;

	if (unlikely(len > m->pkt_len))
		return NULL;

	plen = m->pkt_len;
	remain = len;
	segs = m->nb_segs;
	/* don't free last segment */
	while (remain >= m->data_len && m->next) {
		next = m->next;
		remain -= m->data_len;
		segs--;
		rte_pktmbuf_free_seg(m);
		m = next;
	}

	if (remain) {
		m->data_len = (uint16_t)(m->data_len - remain);
		m->data_off = (uint16_t)(m->data_off + remain);
	}

	m->pkt_len = plen - len;
	m->nb_segs = segs;
	return m;
}

/**
 * Remove len bytes of data at the end of the mbuf.
 *
 * It's an enhancement version of rte_pktmbuf_trim, which not support
 * removing length greater than the length of the last segment.
 *
 * @param m
 *   The packet mbuf.
 * @param len
 *   The amount of data to remove (in bytes).
 * @return
 *   - 0: On success.
 *   - -1: On error.
 */
static inline int
_rte_pktmbuf_trim(struct rte_mbuf *m, uint32_t len)
{
	struct rte_mbuf *last, *next, *tmp;
	uint32_t remain;
	uint16_t segs;

	if (unlikely(len > m->pkt_len))
		return -1;

	tmp = m;
	/* find the last segment will remain after trim */
	remain = m->pkt_len - len;
	while (remain > tmp->data_len) {
		remain -= tmp->data_len;
		tmp = tmp->next;
	}

	/* trim the remained last segment */
	tmp->data_len = remain;

	/* remove trimmed segments */
	segs = m->nb_segs;
	last = tmp;
	for (tmp = tmp->next; tmp != NULL; tmp = next) {
		next = tmp->next;
		rte_pktmbuf_free_seg(tmp);
		segs--;
	}

	last->next = NULL;
	m->pkt_len -= len;
	m->nb_segs = segs;

	return 0;
}

#ifdef __cplusplus
}
#endif

#endif /* _MISC_H_ */

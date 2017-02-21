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

#ifndef _MISC_H_
#define _MISC_H_

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
_ipv4x_phdr_cksum(const struct ipv4_hdr *ipv4_hdr, size_t ipv4h_len,
	uint64_t ol_flags)
{
	uint32_t s0, s1;

	s0 = ipv4_hdr->src_addr;
	s1 = ipv4_hdr->dst_addr;
	CKSUM_ADD_CARRY(s0, s1);

	if (ol_flags & PKT_TX_TCP_SEG)
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
	const struct ipv4_hdr *ipv4_hdr)
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
	const struct ipv6_hdr *ipv6_hdr)
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

static inline int
check_pkt_csum(const struct rte_mbuf *m, uint64_t ol_flags, uint32_t type,
	uint32_t proto)
{
	const struct ipv4_hdr *l3h4;
	const struct ipv6_hdr *l3h6;
	const struct udp_hdr *l4h;
	int32_t ret;
	uint16_t csum;

	ret = 0;
	l3h4 = rte_pktmbuf_mtod_offset(m, const struct ipv4_hdr *, m->l2_len);
	l3h6 = rte_pktmbuf_mtod_offset(m, const struct ipv6_hdr *, m->l2_len);

	if ((ol_flags & PKT_RX_IP_CKSUM_BAD) != 0) {
		csum = _ipv4x_cksum(l3h4, m->l3_len);
		ret = (csum != UINT16_MAX);
	}

	if (ret == 0 && (ol_flags & PKT_RX_L4_CKSUM_BAD) != 0) {

		/*
		 * for IPv4 it is allowed to have zero UDP cksum,
		 * for IPv6 valid UDP cksum is mandatory.
		 */
		if (type == TLE_V4) {
			l4h = (const struct udp_hdr *)((uintptr_t)l3h4 +
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

/* empty ring and free queued mbufs */
static inline void
empty_mbuf_ring(struct rte_ring *r)
{
	uint32_t i, n;
	struct rte_mbuf *mb[MAX_PKT_BURST];

	do {
		n = rte_ring_dequeue_burst(r, (void **)mb, RTE_DIM(mb));
		for (i = 0; i != n; i++)
			rte_pktmbuf_free(mb[i]);
	} while (n != 0);
}

#ifdef __cplusplus
}
#endif

#endif /* _MISC_H_ */

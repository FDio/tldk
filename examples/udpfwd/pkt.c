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

#include "netbe.h"
#include <netinet/ip6.h>

static inline uint64_t
_mbuf_tx_offload(uint64_t il2, uint64_t il3, uint64_t il4, uint64_t tso,
	uint64_t ol3, uint64_t ol2)
{
	return il2 | il3 << 7 | il4 << 16 | tso << 24 | ol3 << 40 | ol2 << 49;
}

static inline void
fill_pkt_hdr_len(struct rte_mbuf *m, uint32_t l2, uint32_t l3, uint32_t l4)
{
	m->tx_offload = _mbuf_tx_offload(l2, l3, l4, 0, 0, 0);
}

static inline int
is_ipv4_frag(const struct ipv4_hdr *iph)
{
	const uint16_t mask = rte_cpu_to_be_16(~IPV4_HDR_DF_FLAG);

	return ((mask & iph->fragment_offset) != 0);
}

static inline uint32_t
get_tcp_header_size(struct rte_mbuf *m, uint32_t l2_len, uint32_t l3_len)
{
	const struct tcp_hdr *tcp;
	tcp = rte_pktmbuf_mtod_offset(m, struct tcp_hdr *, l2_len + l3_len);
	return (tcp->data_off >> 4) * 4;
}

static inline void
fill_ipv4_hdr_len(struct rte_mbuf *m, uint32_t l2, uint32_t proto,
	uint32_t frag, uint32_t l4_len)
{
	const struct ipv4_hdr *iph;
	int32_t dlen, len;

	dlen = rte_pktmbuf_data_len(m);
	dlen -= l2 + l4_len;

	iph = rte_pktmbuf_mtod_offset(m, const struct ipv4_hdr *, l2);
	len = (iph->version_ihl & IPV4_HDR_IHL_MASK) * IPV4_IHL_MULTIPLIER;

	if (frag != 0 && is_ipv4_frag(iph)) {
		m->packet_type &= ~RTE_PTYPE_L4_MASK;
		m->packet_type |= RTE_PTYPE_L4_FRAG;
	}

	if (len > dlen || (proto <= IPPROTO_MAX && iph->next_proto_id != proto))
		m->packet_type = RTE_PTYPE_UNKNOWN;
	else
		fill_pkt_hdr_len(m, l2, len, l4_len);
}

static inline int
ipv6x_hdr(uint32_t proto)
{
	return (proto == IPPROTO_HOPOPTS ||
		proto == IPPROTO_ROUTING ||
		proto == IPPROTO_FRAGMENT ||
		proto == IPPROTO_AH ||
		proto == IPPROTO_NONE ||
		proto == IPPROTO_DSTOPTS);
}

static inline void
fill_ipv6x_hdr_len(struct rte_mbuf *m, uint32_t l2, uint32_t nproto,
	uint32_t fproto, uint32_t l4_len)
{
	const struct ip6_ext *ipx;
	int32_t dlen, len, ofs;

	len = sizeof(struct ipv6_hdr);

	dlen = rte_pktmbuf_data_len(m);
	dlen -= l2 + l4_len;

	ofs = l2 + len;
	ipx = rte_pktmbuf_mtod_offset(m, const struct ip6_ext *, ofs);

	while (ofs > 0 && len < dlen) {

		switch (nproto) {
		case IPPROTO_HOPOPTS:
		case IPPROTO_ROUTING:
		case IPPROTO_DSTOPTS:
			ofs = (ipx->ip6e_len + 1) << 3;
			break;
		case IPPROTO_AH:
			ofs = (ipx->ip6e_len + 2) << 2;
			break;
		case IPPROTO_FRAGMENT:
			/*
			 * tso_segsz is not used by RX, so suse it as temporary
			 * buffer to store the fragment offset.
			 */
			m->tso_segsz = ofs;
			ofs = sizeof(struct ip6_frag);
			m->packet_type &= ~RTE_PTYPE_L4_MASK;
			m->packet_type |= RTE_PTYPE_L4_FRAG;
			break;
		default:
			ofs = 0;
		}

		if (ofs > 0) {
			nproto = ipx->ip6e_nxt;
			len += ofs;
			ipx += ofs / sizeof(*ipx);
		}
	}

	/* unrecognized or invalid packet. */
	if ((ofs == 0 && nproto != fproto) || len > dlen)
		m->packet_type = RTE_PTYPE_UNKNOWN;
	else
		fill_pkt_hdr_len(m, l2, len, l4_len);
}

static inline void
fill_ipv6_hdr_len(struct rte_mbuf *m, uint32_t l2, uint32_t fproto,
	uint32_t l4_len)
{
	const struct ipv6_hdr *iph;

	iph = rte_pktmbuf_mtod_offset(m, const struct ipv6_hdr *,
		sizeof(struct ether_hdr));

	if (iph->proto == fproto)
		fill_pkt_hdr_len(m, l2, sizeof(struct ipv6_hdr), l4_len);
	else if (ipv6x_hdr(iph->proto) != 0)
		fill_ipv6x_hdr_len(m, l2, iph->proto, fproto, l4_len);
}

static inline void
fill_eth_hdr_len(struct rte_mbuf *m, uint32_t *proto)
{
	uint32_t dlen, l2_len;
	uint16_t etp;
	const struct ether_hdr *eth;
	const struct ipv4_hdr *ip4h;
	const struct ipv6_hdr *ip6h;
	uint32_t l4_len;

	dlen = rte_pktmbuf_data_len(m);

	/* check that first segment is at least 42B long. */
	if (dlen < sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +
			sizeof(struct udp_hdr)) {
		m->packet_type = RTE_PTYPE_UNKNOWN;
		return;
	}

	l2_len = sizeof(*eth);

	eth = rte_pktmbuf_mtod(m, const struct ether_hdr *);
	etp = eth->ether_type;
	if (etp == rte_be_to_cpu_16(ETHER_TYPE_VLAN))
		l2_len += sizeof(struct vlan_hdr);

	if (etp == rte_be_to_cpu_16(ETHER_TYPE_IPv4)) {
		ip4h = rte_pktmbuf_mtod_offset(m, const struct ipv4_hdr *, l2_len);
		if (ip4h->next_proto_id == IPPROTO_TCP) {
			l4_len = get_tcp_header_size(m, l2_len, sizeof(struct ipv4_hdr));
			m->packet_type = RTE_PTYPE_L4_TCP |
				RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_L2_ETHER;
			fill_ipv4_hdr_len(m, l2_len, IPPROTO_TCP, 1, l4_len);
			*proto = IPPROTO_TCP;
		} else {
			m->packet_type = RTE_PTYPE_L4_UDP |
				RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_L2_ETHER;
			fill_ipv4_hdr_len(m, l2_len, IPPROTO_UDP, 1, sizeof(struct udp_hdr));
			*proto = IPPROTO_UDP;
		}
	} else if (etp == rte_be_to_cpu_16(ETHER_TYPE_IPv6) &&
			dlen >= l2_len + sizeof(struct ipv6_hdr) +
			sizeof(struct udp_hdr)) {
		ip6h = rte_pktmbuf_mtod_offset(m, const struct ipv6_hdr *, l2_len);
		if (ip6h->proto == IPPROTO_TCP) {
			l4_len = get_tcp_header_size(m, l2_len, sizeof(struct ipv6_hdr));
			m->packet_type = RTE_PTYPE_L4_TCP |
				RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_L2_ETHER;
			fill_ipv6_hdr_len(m, l2_len, IPPROTO_TCP, l4_len);
			*proto = IPPROTO_TCP;
		} else {
			m->packet_type = RTE_PTYPE_L4_UDP |
				RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_L2_ETHER;
			fill_ipv6_hdr_len(m, l2_len, IPPROTO_UDP, sizeof(struct udp_hdr));
			*proto = IPPROTO_UDP;
		}
	} else
		m->packet_type = RTE_PTYPE_UNKNOWN;

}

static inline uint16_t
ipv4x_cksum(const void *iph, size_t len)
{
	uint16_t cksum;

	cksum = rte_raw_cksum(iph, len);
	return (cksum == 0xffff) ? cksum : ~cksum;
}

static inline void
fix_reassembled(struct rte_mbuf *m, int32_t hwcsum, uint32_t proto)
{
	struct ipv4_hdr *iph;

	/* update packet type. */
	m->packet_type &= ~RTE_PTYPE_L4_MASK;

	if (proto == IPPROTO_TCP)
		m->packet_type |= RTE_PTYPE_L4_TCP;
	else
		m->packet_type |= RTE_PTYPE_L4_UDP;

	/* fix reassemble setting TX flags. */
	m->ol_flags &= ~PKT_TX_IP_CKSUM;

	/* fix l3_len after reassemble. */
	if (RTE_ETH_IS_IPV6_HDR(m->packet_type))
		m->l3_len = m->l3_len - sizeof(struct ipv6_extension_fragment);

	/* recalculate ipv4 cksum after reassemble. */
	else if (hwcsum == 0 && RTE_ETH_IS_IPV4_HDR(m->packet_type)) {
		iph = rte_pktmbuf_mtod_offset(m, struct ipv4_hdr *, m->l2_len);
		iph->hdr_checksum = ipv4x_cksum(iph, m->l3_len);
	}
}

static struct rte_mbuf *
reassemble(struct rte_mbuf *m, struct netbe_lcore *lc, uint64_t tms,
	uint8_t port, uint32_t proto)
{
	uint32_t l3cs;
	struct rte_ip_frag_tbl *tbl;
	struct rte_ip_frag_death_row *dr;

	tbl = lc->ftbl;
	dr = &lc->death_row;
	l3cs = lc->prtq[port].port.rx_offload & DEV_RX_OFFLOAD_IPV4_CKSUM;

	if (RTE_ETH_IS_IPV4_HDR(m->packet_type)) {

		struct ipv4_hdr *iph;

		iph = rte_pktmbuf_mtod_offset(m, struct ipv4_hdr *, m->l2_len);

		/* process this fragment. */
		m = rte_ipv4_frag_reassemble_packet(tbl, dr, m, tms, iph);

	} else if (RTE_ETH_IS_IPV6_HDR(m->packet_type)) {

		struct ipv6_hdr *iph;
		struct ipv6_extension_fragment *fhdr;

		iph = rte_pktmbuf_mtod_offset(m, struct ipv6_hdr *, m->l2_len);

		/*
		 * we store fragment header offset in tso_segsz before
		 * temporary, just to avoid another scan of ipv6 header.
		 */
		fhdr = rte_pktmbuf_mtod_offset(m,
			struct ipv6_extension_fragment *, m->tso_segsz);
		m->tso_segsz = 0;

		/* process this fragment. */
		m = rte_ipv6_frag_reassemble_packet(tbl, dr, m, tms, iph, fhdr);

	} else {
		rte_pktmbuf_free(m);
		m = NULL;
	}

	/* got reassembled packet. */
	if (m != NULL)
		fix_reassembled(m, l3cs, proto);

	return m;
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

/*
 * if it is a fragment, try to reassemble it,
 * if by some reason it can't be done, then
 * set pkt[] entry to NULL.
 */
#define DO_REASSEMBLE(proto) \
do { \
	if ((pkt[j]->packet_type & RTE_PTYPE_L4_MASK) == \
			RTE_PTYPE_L4_FRAG) { \
		cts = (cts == 0) ? rte_rdtsc() : cts; \
		pkt[j] = reassemble(pkt[j], lc, cts, port, (proto)); \
		x += (pkt[j] == NULL); \
	} \
} while (0)

/*
 * HW can recognize L2/L3 with/without extensions/L4 (ixgbe/igb/fm10k)
 */
static uint16_t __rte_unused
type0_tcp_rx_callback(uint8_t port, __rte_unused uint16_t queue,
	struct rte_mbuf *pkt[], uint16_t nb_pkts,
	__rte_unused uint16_t max_pkts, void *user_param)
{
	uint32_t j, tp, x;
	uint64_t cts;
	struct netbe_lcore *lc;
	uint32_t l4_len, l2_len, eth_len;
	const struct ether_hdr *eth;

	lc = user_param;
	cts = 0;
	eth_len = sizeof(*eth);

	x = 0;
	for (j = 0; j != nb_pkts; j++) {

		NETBE_PKT_DUMP(pkt[j]);

		l2_len = eth_len;
		eth = rte_pktmbuf_mtod(pkt[j], const struct ether_hdr *);
		if (eth->ether_type == rte_be_to_cpu_16(ETHER_TYPE_VLAN))
			l2_len += sizeof(struct vlan_hdr);

		tp = pkt[j]->packet_type & (RTE_PTYPE_L4_MASK |
			RTE_PTYPE_L3_MASK | RTE_PTYPE_L2_MASK);

		switch (tp) {
		/* non fragmented tcp packets. */
		case (RTE_PTYPE_L4_TCP | RTE_PTYPE_L3_IPV4 |
				RTE_PTYPE_L2_ETHER):
			l4_len = get_tcp_header_size(pkt[j], l2_len,
				sizeof(struct ipv4_hdr));
			fill_pkt_hdr_len(pkt[j], l2_len, sizeof(struct ipv4_hdr), l4_len);
			break;
		case (RTE_PTYPE_L4_TCP | RTE_PTYPE_L3_IPV6 |
				RTE_PTYPE_L2_ETHER):
			l4_len = get_tcp_header_size(pkt[j], l2_len,
				sizeof(struct ipv6_hdr));
			fill_pkt_hdr_len(pkt[j], l2_len, sizeof(struct ipv6_hdr), l4_len);
			break;
		case (RTE_PTYPE_L4_TCP | RTE_PTYPE_L3_IPV4_EXT |
				RTE_PTYPE_L2_ETHER):
			l4_len = get_tcp_header_size(pkt[j], l2_len,
				sizeof(struct ipv4_hdr));
			fill_ipv4_hdr_len(pkt[j], l2_len, UINT32_MAX, 0, l4_len);
			break;
		case (RTE_PTYPE_L4_TCP | RTE_PTYPE_L3_IPV6_EXT |
				RTE_PTYPE_L2_ETHER):
			l4_len = get_tcp_header_size(pkt[j], l2_len,
				sizeof(struct ipv6_hdr));
			fill_ipv6_hdr_len(pkt[j], l2_len, IPPROTO_TCP, l4_len);
			break;
		/* possibly fragmented tcp packets. */
		case (RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L2_ETHER):
		case (RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_L2_ETHER):
			l4_len = get_tcp_header_size(pkt[j], l2_len,
				sizeof(struct ipv4_hdr));
			fill_ipv4_hdr_len(pkt[j], l2_len, IPPROTO_TCP, 1, l4_len);
			break;
		case (RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L2_ETHER):
		case (RTE_PTYPE_L3_IPV6_EXT | RTE_PTYPE_L2_ETHER):
			l4_len = get_tcp_header_size(pkt[j], l2_len,
				sizeof(struct ipv6_hdr));
			fill_ipv6_hdr_len(pkt[j], l2_len, IPPROTO_TCP, l4_len);
			break;
		default:
			/* treat packet types as invalid. */
			pkt[j]->packet_type = RTE_PTYPE_UNKNOWN;
			break;
		}

		DO_REASSEMBLE(IPPROTO_TCP);
	}

	/* reassemble was invoked, cleanup its death-row. */
	if (cts != 0)
		rte_ip_frag_free_death_row(&lc->death_row, 0);

	if (x == 0)
		return nb_pkts;

	NETBE_TRACE("%s(port=%u, queue=%u, nb_pkts=%u): "
		"%u non-reassembled fragments;\n",
		__func__, port, queue, nb_pkts, x);

	return compress_pkt_list(pkt, nb_pkts, x);
}

/*
 * HW can recognize L2/L3 with/without extensions/L4 (ixgbe/igb/fm10k)
 */
static uint16_t __rte_unused
type0_udp_rx_callback(uint8_t port, __rte_unused uint16_t queue,
	struct rte_mbuf *pkt[], uint16_t nb_pkts,
	__rte_unused uint16_t max_pkts, void *user_param)
{
	uint32_t j, tp, x;
	uint64_t cts;
	struct netbe_lcore *lc;
	uint32_t l2_len, eth_len;
	const struct ether_hdr *eth;

	lc = user_param;
	cts = 0;
	eth_len = sizeof(*eth);

	x = 0;
	for (j = 0; j != nb_pkts; j++) {

		NETBE_PKT_DUMP(pkt[j]);

		l2_len = eth_len;
		eth = rte_pktmbuf_mtod(pkt[j], const struct ether_hdr *);
		if (eth->ether_type == rte_be_to_cpu_16(ETHER_TYPE_VLAN))
			l2_len += sizeof(struct vlan_hdr);

		tp = pkt[j]->packet_type & (RTE_PTYPE_L4_MASK |
			RTE_PTYPE_L3_MASK | RTE_PTYPE_L2_MASK);

		switch (tp) {
		/* non fragmented udp packets. */
		case (RTE_PTYPE_L4_UDP | RTE_PTYPE_L3_IPV4 |
				RTE_PTYPE_L2_ETHER):
			fill_pkt_hdr_len(pkt[j], l2_len,
				sizeof(struct ipv4_hdr), sizeof(struct udp_hdr));
			break;
		case (RTE_PTYPE_L4_UDP | RTE_PTYPE_L3_IPV6 |
				RTE_PTYPE_L2_ETHER):
			fill_pkt_hdr_len(pkt[j], l2_len,
				sizeof(struct ipv6_hdr), sizeof(struct udp_hdr));
			break;
		case (RTE_PTYPE_L4_UDP | RTE_PTYPE_L3_IPV4_EXT |
				RTE_PTYPE_L2_ETHER):
			fill_ipv4_hdr_len(pkt[j], l2_len,
				UINT32_MAX, 0, sizeof(struct udp_hdr));
			break;
		case (RTE_PTYPE_L4_UDP | RTE_PTYPE_L3_IPV6_EXT |
				RTE_PTYPE_L2_ETHER):
			fill_ipv6_hdr_len(pkt[j], l2_len,
				IPPROTO_UDP, sizeof(struct udp_hdr));
			break;
		/* possibly fragmented udp packets. */
		case (RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L2_ETHER):
		case (RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_L2_ETHER):
			fill_ipv4_hdr_len(pkt[j], l2_len,
				IPPROTO_UDP, 1, sizeof(struct udp_hdr));
			break;
		case (RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L2_ETHER):
		case (RTE_PTYPE_L3_IPV6_EXT | RTE_PTYPE_L2_ETHER):
			fill_ipv6_hdr_len(pkt[j], l2_len,
				IPPROTO_UDP, sizeof(struct udp_hdr));
			break;
		default:
			/* treat packet types as invalid. */
			pkt[j]->packet_type = RTE_PTYPE_UNKNOWN;
			break;
		}

		DO_REASSEMBLE(IPPROTO_UDP);
	}

	/* reassemble was invoked, cleanup its death-row. */
	if (cts != 0)
		rte_ip_frag_free_death_row(&lc->death_row, 0);

	if (x == 0)
		return nb_pkts;

	NETBE_TRACE("%s(port=%u, queue=%u, nb_pkts=%u): "
		"%u non-reassembled fragments;\n",
		__func__, port, queue, nb_pkts, x);

	return compress_pkt_list(pkt, nb_pkts, x);
}

/*
 * HW can recognize L2/L3/L4 and fragments (i40e).
 */
static uint16_t __rte_unused
type1_tcp_rx_callback(uint8_t port, __rte_unused uint16_t queue,
	struct rte_mbuf *pkt[], uint16_t nb_pkts,
	__rte_unused uint16_t max_pkts, void *user_param)
{
	uint32_t j, tp, x;
	uint64_t cts;
	struct netbe_lcore *lc;
	uint32_t l4_len, l2_len, eth_len;
	const struct ether_hdr *eth;

	lc = user_param;
	cts = 0;
	eth_len = sizeof(*eth);

	x = 0;
	for (j = 0; j != nb_pkts; j++) {

		NETBE_PKT_DUMP(pkt[j]);

		l2_len = eth_len;
		eth = rte_pktmbuf_mtod(pkt[j], const struct ether_hdr *);
		if (eth->ether_type == rte_be_to_cpu_16(ETHER_TYPE_VLAN))
			l2_len += sizeof(struct vlan_hdr);

		tp = pkt[j]->packet_type & (RTE_PTYPE_L4_MASK |
			RTE_PTYPE_L3_MASK | RTE_PTYPE_L2_MASK);

		switch (tp) {
		case (RTE_PTYPE_L4_TCP | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_L2_ETHER):
			l4_len = get_tcp_header_size(pkt[j], l2_len,
				sizeof(struct ipv4_hdr));
			fill_ipv4_hdr_len(pkt[j], l2_len, UINT32_MAX, 0, l4_len);
			break;
		case (RTE_PTYPE_L4_TCP | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_L2_ETHER):
			l4_len = get_tcp_header_size(pkt[j], l2_len,
				sizeof(struct ipv6_hdr));
			fill_ipv6_hdr_len(pkt[j], l2_len, IPPROTO_TCP, l4_len);
			break;
		case (RTE_PTYPE_L4_FRAG | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_L2_ETHER):
			l4_len = get_tcp_header_size(pkt[j], l2_len,
				sizeof(struct ipv4_hdr));
			fill_ipv4_hdr_len(pkt[j], l2_len, IPPROTO_TCP, 0, l4_len);
			break;
		case (RTE_PTYPE_L4_FRAG | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_L2_ETHER):
			l4_len = get_tcp_header_size(pkt[j], l2_len,
				sizeof(struct ipv6_hdr));
			fill_ipv6_hdr_len(pkt[j], l2_len, IPPROTO_TCP, l4_len);
			break;
		default:
			/* treat packet types as invalid. */
			pkt[j]->packet_type = RTE_PTYPE_UNKNOWN;
			break;
		}

		DO_REASSEMBLE(IPPROTO_TCP);
	}

	/* reassemble was invoked, cleanup its death-row. */
	if (cts != 0)
		rte_ip_frag_free_death_row(&lc->death_row, 0);

	if (x == 0)
		return nb_pkts;

	NETBE_TRACE("%s(port=%u, queue=%u, nb_pkts=%u): "
		"%u non-reassembled fragments;\n",
		__func__, port, queue, nb_pkts, x);

	return compress_pkt_list(pkt, nb_pkts, x);
}

/*
 * HW can recognize L2/L3/L4 and fragments (i40e).
 */
static uint16_t __rte_unused
type1_udp_rx_callback(uint8_t port, __rte_unused uint16_t queue,
	struct rte_mbuf *pkt[], uint16_t nb_pkts,
	__rte_unused uint16_t max_pkts, void *user_param)
{
	uint32_t j, tp, x;
	uint64_t cts;
	struct netbe_lcore *lc;
	uint32_t l2_len, eth_len;
	const struct ether_hdr *eth;

	lc = user_param;
	cts = 0;
	eth_len = sizeof(*eth);

	x = 0;
	for (j = 0; j != nb_pkts; j++) {

		NETBE_PKT_DUMP(pkt[j]);

		l2_len = eth_len;
		eth = rte_pktmbuf_mtod(pkt[j], const struct ether_hdr *);
		if (eth->ether_type == rte_be_to_cpu_16(ETHER_TYPE_VLAN))
			l2_len += sizeof(struct vlan_hdr);

		tp = pkt[j]->packet_type & (RTE_PTYPE_L4_MASK |
			RTE_PTYPE_L3_MASK | RTE_PTYPE_L2_MASK);

		switch (tp) {
		case (RTE_PTYPE_L4_UDP | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_L2_ETHER):
			fill_ipv4_hdr_len(pkt[j], l2_len,
				UINT32_MAX, 0, sizeof(struct udp_hdr));
			break;
		case (RTE_PTYPE_L4_UDP | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_L2_ETHER):
			fill_ipv6_hdr_len(pkt[j], l2_len,
				IPPROTO_UDP, sizeof(struct udp_hdr));
			break;
		case (RTE_PTYPE_L4_FRAG | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_L2_ETHER):
			fill_ipv4_hdr_len(pkt[j], l2_len,
				IPPROTO_UDP, 0, sizeof(struct udp_hdr));
			break;
		case (RTE_PTYPE_L4_FRAG | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_L2_ETHER):
			fill_ipv6_hdr_len(pkt[j], l2_len,
				IPPROTO_UDP, sizeof(struct udp_hdr));
			break;
		default:
			/* treat packet types as invalid. */
			pkt[j]->packet_type = RTE_PTYPE_UNKNOWN;
			break;
		}

		DO_REASSEMBLE(IPPROTO_UDP);
	}

	/* reassemble was invoked, cleanup its death-row. */
	if (cts != 0)
		rte_ip_frag_free_death_row(&lc->death_row, 0);

	if (x == 0)
		return nb_pkts;

	NETBE_TRACE("%s(port=%u, queue=%u, nb_pkts=%u): "
		"%u non-reassembled fragments;\n",
		__func__, port, queue, nb_pkts, x);

	return compress_pkt_list(pkt, nb_pkts, x);
}

/*
 * generic, assumes HW doesn't recognize any packet type.
 */
static uint16_t
typen_rx_callback(uint8_t port, __rte_unused uint16_t queue,
	struct rte_mbuf *pkt[], uint16_t nb_pkts,
	__rte_unused uint16_t max_pkts, void *user_param)
{
	uint32_t j, x;
	uint64_t cts;
	struct netbe_lcore *lc;
	uint32_t proto;

	lc = user_param;
	cts = 0;

	x = 0;
	proto = IPPROTO_UDP;
	for (j = 0; j != nb_pkts; j++) {

		NETBE_PKT_DUMP(pkt[j]);
		fill_eth_hdr_len(pkt[j], &proto);

		DO_REASSEMBLE(proto);
	}

	/* reassemble was invoked, cleanup its death-row. */
	if (cts != 0)
		rte_ip_frag_free_death_row(&lc->death_row, 0);

	if (x == 0)
		return nb_pkts;

	NETBE_TRACE("%s(port=%u, queue=%u, nb_pkts=%u): "
		"%u non-reassembled fragments;\n",
		__func__, port, queue, nb_pkts, x);

	return compress_pkt_list(pkt, nb_pkts, x);
}

#include "pkt_dpdk_legacy.h"

/*
 * Copyright (c) 2018 Ant Financial Services Group.
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

#include <rte_ethdev.h>
#include <rte_arp.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include <netinet/in.h>
#include <netinet/ip6.h>

#include "log.h"
#include "ctx.h"
#include "internal.h"

struct ptype2cb {
	uint32_t mask;
	const char *name;
	rte_rx_callback_fn fn;
};

enum {
	ETHER_ARP_PTYPE = 0x1,
	IPV4_PTYPE = 0x2,
	IPV4_EXT_PTYPE = 0x4,
	IPV6_PTYPE = 0x8,
	IPV6_EXT_PTYPE = 0x10,
	TCP_PTYPE = 0x20,
	UDP_PTYPE = 0x40,
	ICMP_PTYPE = 0x80,
};

static inline uint64_t
_mbuf_tx_offload(uint64_t il2, uint64_t il3, uint64_t il4, uint64_t tso,
	uint64_t ol3, uint64_t ol2)
{
	return il2 | il3 << 7 | il4 << 16 | tso << 24 | ol3 << 40 | ol2 << 49;
}

static inline int32_t
fill_pkt_hdr_len(struct rte_mbuf *m, uint32_t l2, uint32_t l3, uint32_t l4)
{
	if (l2 + l3 + l4 > m->pkt_len)
		return -1;
	m->tx_offload = _mbuf_tx_offload(l2, l3, l4, 0, 0, 0);
	return 0;
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

static inline int32_t
adjust_ipv4_pktlen(struct rte_mbuf *m, uint32_t l2_len)
{
	uint32_t plen, trim;
	const struct ipv4_hdr *iph;

	iph = rte_pktmbuf_mtod_offset(m, const struct ipv4_hdr *, l2_len);
	plen = rte_be_to_cpu_16(iph->total_length) + l2_len;
	if (plen < m->pkt_len) {
		trim = m->pkt_len - plen;
		rte_pktmbuf_trim(m, trim);
	} else if (plen > m->pkt_len)
		return -1;

	return 0;
}

static inline int32_t
adjust_ipv6_pktlen(struct rte_mbuf *m, uint32_t l2_len)
{
	uint32_t plen, trim;
	const struct ipv6_hdr *iph;

	iph = rte_pktmbuf_mtod_offset(m, const struct ipv6_hdr *, l2_len);
	plen = rte_be_to_cpu_16(iph->payload_len) + sizeof(*iph) + l2_len;
	if (plen < m->pkt_len) {
		trim = m->pkt_len - plen;
		rte_pktmbuf_trim(m, trim);
	} else if (plen > m->pkt_len)
		return -1;

	return 0;
}

static inline uint32_t
get_ipv4_hdr_len(struct rte_mbuf *m, uint32_t l2, uint32_t proto, uint32_t frag)
{
	const struct ipv4_hdr *iph;
	int32_t dlen, len;

	dlen = rte_pktmbuf_data_len(m);
	dlen -= l2;

	iph = rte_pktmbuf_mtod_offset(m, const struct ipv4_hdr *, l2);
	len = (iph->version_ihl & IPV4_HDR_IHL_MASK) * IPV4_IHL_MULTIPLIER;

	if (frag != 0 && is_ipv4_frag(iph)) {
		m->packet_type &= ~RTE_PTYPE_L4_MASK;
		m->packet_type |= RTE_PTYPE_L4_FRAG;
	}

	if (len > dlen || (proto <= IPPROTO_MAX && iph->next_proto_id != proto))
		m->packet_type = RTE_PTYPE_UNKNOWN;

	return len;
}

static inline uint32_t
get_ipv6x_hdr_len(struct rte_mbuf *m, uint32_t l2, uint32_t *fproto)
{
	const struct ipv6_hdr *ip6h;
	const struct ip6_ext *ipx;
	uint32_t nproto;
	int32_t dlen, len, ofs;

	ip6h = rte_pktmbuf_mtod_offset(m, struct ipv6_hdr*, l2);
	nproto = ip6h->proto;
	len = sizeof(struct ipv6_hdr);

	dlen = rte_pktmbuf_data_len(m);
	dlen -= l2;

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
			 * tso_segsz is not used by RX, so use it as temporary
			 * buffer to store the fragment offset.
			 */
			m->tso_segsz = l2 + len;
			ofs = sizeof(struct ip6_frag);
			m->packet_type &= ~RTE_PTYPE_L4_MASK;
			m->packet_type |= RTE_PTYPE_L4_FRAG;
			break;
		case IPPROTO_TCP:
		case IPPROTO_UDP:
		case IPPROTO_ICMPV6:
			ofs = 0;
			if (*fproto == 0)
				*fproto = nproto;
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
	if (*fproto == 0 || len > dlen)
		m->packet_type = RTE_PTYPE_UNKNOWN;

	return len;
}

static inline uint32_t
get_ipv6_hdr_len(struct rte_mbuf *m, uint32_t l2, uint32_t fproto)
{
	const struct ipv6_hdr *iph;

	iph = rte_pktmbuf_mtod_offset(m, const struct ipv6_hdr *,
				      sizeof(struct ether_hdr));

	if (iph->proto == fproto)
		return sizeof(struct ipv6_hdr);
	else
		return get_ipv6x_hdr_len(m, l2, &fproto);
}

static inline struct rte_mbuf*
process_ipv4_frag(struct rte_mbuf *m, struct glue_ctx *ctx,
		  uint32_t l2_len, uint32_t l3_len)
{
	struct ipv4_hdr* iph;

	m->l2_len = l2_len;
	m->l3_len = l3_len;
	/* fixme: ip checksum should be checked here.
	 * After reassemble, the ip checksum would be invalid.
	 */
	m = rte_ipv4_frag_reassemble_packet(ctx->frag_tbl,
					    &ctx->frag_dr, m, rte_rdtsc(),
					    rte_pktmbuf_mtod_offset(m, struct ipv4_hdr*, m->l2_len));
	rte_ip_frag_free_death_row(&ctx->frag_dr, 3);
	if (m == NULL)
		return NULL;
	iph = rte_pktmbuf_mtod_offset(m, struct ipv4_hdr*, m->l2_len);
	switch (iph->next_proto_id) {
	case IPPROTO_TCP:
		m->packet_type &= ~RTE_PTYPE_L4_MASK;
		m->packet_type |= RTE_PTYPE_L4_TCP;
		break;
	case IPPROTO_UDP:
		m->packet_type &= ~RTE_PTYPE_L4_MASK;
		m->packet_type |= RTE_PTYPE_L4_UDP;
		break;
	}
	return m;
}

static inline struct rte_mbuf*
process_ipv6_frag(struct rte_mbuf *m, struct glue_ctx *ctx,
		  uint32_t l2_len, uint32_t l3_len)
{
	struct ipv6_hdr* ip6h;

	m->l2_len = l2_len;
	m->l3_len = l3_len;
	m = rte_ipv6_frag_reassemble_packet(ctx->frag_tbl,
			&ctx->frag_dr, m, rte_rdtsc(),
			rte_pktmbuf_mtod_offset(m, struct ipv6_hdr*, l2_len),
			rte_pktmbuf_mtod_offset(m, struct ipv6_extension_fragment*,
						m->tso_segsz));
	rte_ip_frag_free_death_row(&ctx->frag_dr, 3);
	if (m == NULL)
		return NULL;
	ip6h = rte_pktmbuf_mtod_offset(m, struct ipv6_hdr*, m->l2_len);
	switch (ip6h->proto) {
	case IPPROTO_TCP:
		m->packet_type &= ~RTE_PTYPE_L4_MASK;
		m->packet_type |= RTE_PTYPE_L4_TCP;
		break;
	case IPPROTO_UDP:
		m->packet_type &= ~RTE_PTYPE_L4_MASK;
		m->packet_type |= RTE_PTYPE_L4_UDP;
		break;
	}
	return m;
}

static inline struct rte_mbuf *
fill_ptypes_and_hdr_len(struct glue_ctx *ctx, struct rte_mbuf *m)
{
	uint32_t dlen, l2_len, l3_len, l4_len, proto;
	const struct ether_hdr *eth;
	uint32_t ptypes;
	uint16_t etp;
	int32_t error = 0;

	dlen = rte_pktmbuf_data_len(m);

	/* L2 */
	l2_len = sizeof(*eth);

	eth = rte_pktmbuf_mtod(m, const struct ether_hdr *);
	etp = eth->ether_type;
	while (etp == rte_be_to_cpu_16(ETHER_TYPE_VLAN)) {
		etp = rte_pktmbuf_mtod_offset(m, struct vlan_hdr*, l2_len)->eth_proto;
		l2_len += sizeof(struct vlan_hdr);
	}

	if (etp == rte_be_to_cpu_16(ETHER_TYPE_ARP))
		return arp_recv(ctx, m, l2_len);

	if (etp == rte_be_to_cpu_16(ETHER_TYPE_IPv4)) {
		const struct ipv4_hdr *hdr;

		/* L3 */
		hdr = rte_pktmbuf_mtod_offset(m, const struct ipv4_hdr *, l2_len);
		error = adjust_ipv4_pktlen(m, l2_len);
		if (error) {
			rte_pktmbuf_free(m);
			return NULL;
		}
		l3_len = get_ipv4_hdr_len(m, l2_len, IPPROTO_MAX + 1, 1);

		if ((m->packet_type & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_FRAG) {
			m = process_ipv4_frag(m, ctx, l2_len, l3_len);
			if (m == NULL)
				return NULL;
			hdr = rte_pktmbuf_mtod_offset(m, const struct ipv4_hdr*,
					 	      m->l2_len);
			l3_len = get_ipv4_hdr_len(m, m->l2_len,
						  IPPROTO_MAX + 1, 0);
		}

		/* L4 */
		switch (hdr->next_proto_id) {
		case IPPROTO_ICMP:
			return icmp_recv(ctx, m, l2_len, l3_len);
		case IPPROTO_TCP:
			ptypes = RTE_PTYPE_L4_TCP |
				 RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_L2_ETHER;
			l4_len = get_tcp_header_size(m, l2_len, l3_len);
			break;
		case IPPROTO_UDP:
			ptypes = RTE_PTYPE_L4_UDP |
				 RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_L2_ETHER;
			l4_len = sizeof(struct udp_hdr);
			break;
		default:
			GLUE_LOG(ERR, "drop ipv4 pkt of unknow L4: (%d)",
				 hdr->next_proto_id);
			rte_pktmbuf_free(m);
			return NULL;
		}

	} else if (etp == rte_be_to_cpu_16(ETHER_TYPE_IPv6) &&
		   dlen >= l2_len + sizeof(struct ipv6_hdr) + sizeof(struct udp_hdr)) {
		/* L3 */
		error = adjust_ipv6_pktlen(m, l2_len);
		if (error) {
			rte_pktmbuf_free(m);
			return NULL;
		}
		proto = 0;
		l3_len = get_ipv6x_hdr_len(m, l2_len, &proto);

		if ((m->packet_type & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_FRAG) {
			m = process_ipv6_frag(m, ctx, l2_len, l3_len);
			if (m == NULL)
				return NULL;
			l3_len = get_ipv6x_hdr_len(m, m->l2_len, &proto);
		}

		/* L4 */
		switch (proto) {
		case IPPROTO_TCP:
			ptypes = RTE_PTYPE_L4_TCP |
				 RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L2_ETHER;
			l4_len = get_tcp_header_size(m, l2_len, l3_len);
			break;
		case IPPROTO_UDP:
			ptypes = RTE_PTYPE_L4_UDP |
				 RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L2_ETHER;
			l4_len = sizeof(struct udp_hdr);
			break;
		case IPPROTO_ICMPV6:
			return icmp6_recv(ctx, m, l2_len, l3_len);
		default:
			GLUE_DEBUG("drop ipv6 pkt of unknown L4: (%x)", proto);
			rte_pktmbuf_free(m);
			return NULL;
		}
	} else {
		GLUE_DEBUG("Drop unknown L3 packet: %x", etp);
		rte_pktmbuf_free(m);
		return NULL;
	}

	m->packet_type = ptypes;
	error = fill_pkt_hdr_len(m, l2_len, l3_len, l4_len);
	if (error) {
		rte_pktmbuf_free(m);
		return NULL;
	}

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

static inline struct rte_mbuf *
common_fill_hdr_len(struct rte_mbuf *m, uint32_t tp, struct glue_ctx *ctx)
{
	uint32_t l4_len, l3_len, l2_len = sizeof(struct ether_hdr);
	int32_t error = 0;

	switch (tp) {
	/* possibly fragmented packets. */
	case (RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L2_ETHER):
	case (RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_L2_ETHER):
		l3_len = get_ipv4_hdr_len(m, l2_len, IPPROTO_MAX + 1, 1);
		if ((m->packet_type & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_FRAG) {
			m = process_ipv4_frag(m, ctx, l2_len, l3_len);
			if (m == NULL)
				return NULL;
			tp = m->packet_type & (RTE_PTYPE_L2_MASK |
					       RTE_PTYPE_L3_MASK |
					       RTE_PTYPE_L4_MASK);
		}
		break;
	case (RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L2_ETHER):
	case (RTE_PTYPE_L3_IPV6_EXT | RTE_PTYPE_L2_ETHER):
		l3_len = get_ipv6_hdr_len(m, l2_len, IPPROTO_MAX + 1);
		if ((m->packet_type & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_FRAG) {
			m = process_ipv6_frag(m, ctx, l2_len, l3_len);
			if (m == NULL)
				return NULL;
			tp = m->packet_type & (RTE_PTYPE_L2_MASK |
					       RTE_PTYPE_L3_MASK |
					       RTE_PTYPE_L4_MASK);
		}
		break;
	}

	switch (tp) {
	/* non fragmented tcp packets. */
	case (RTE_PTYPE_L4_TCP | RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L2_ETHER):
		l3_len = sizeof(struct ipv4_hdr);
		l4_len = get_tcp_header_size(m, l2_len, l3_len);
		error = adjust_ipv4_pktlen(m, l2_len);
		break;
	case (RTE_PTYPE_L4_TCP | RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L2_ETHER):
		l3_len = sizeof(struct ipv6_hdr);
		l4_len = get_tcp_header_size(m, l2_len, l3_len);
		error = adjust_ipv6_pktlen(m, l2_len);
		break;
	case (RTE_PTYPE_L4_TCP | RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_L2_ETHER):
		l3_len = get_ipv4_hdr_len(m, l2_len,
					  IPPROTO_TCP, 0);
		l4_len = get_tcp_header_size(m, l2_len, l3_len);
		error = adjust_ipv4_pktlen(m, l2_len);
		break;
	case (RTE_PTYPE_L4_TCP | RTE_PTYPE_L3_IPV6_EXT | RTE_PTYPE_L2_ETHER):
		l3_len = get_ipv6_hdr_len(m, l2_len, IPPROTO_TCP);
		l4_len = get_tcp_header_size(m, l2_len, l3_len);
		error = adjust_ipv6_pktlen(m, l2_len);
		break;

	/* non fragmented udp packets. */
	case (RTE_PTYPE_L4_UDP | RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L2_ETHER):
		l3_len = sizeof(struct ipv4_hdr);
		l4_len = sizeof(struct udp_hdr);
		error = adjust_ipv4_pktlen(m, l2_len);
		break;
	case (RTE_PTYPE_L4_UDP | RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L2_ETHER):
		l3_len = sizeof(struct ipv6_hdr);
		l4_len = sizeof(struct udp_hdr);
		error = adjust_ipv6_pktlen(m, l2_len);
		break;
	case (RTE_PTYPE_L4_UDP | RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_L2_ETHER):
		l3_len = get_ipv4_hdr_len(m, l2_len,
					  IPPROTO_UDP, 0);
		l4_len = sizeof(struct udp_hdr);
		error = adjust_ipv4_pktlen(m, l2_len);
		break;
	case (RTE_PTYPE_L4_UDP | RTE_PTYPE_L3_IPV6_EXT | RTE_PTYPE_L2_ETHER):
		l3_len = get_ipv6_hdr_len(m, l2_len, IPPROTO_UDP);
		l4_len = sizeof(struct udp_hdr);
		error = adjust_ipv6_pktlen(m, l2_len);
		break;
	default:
		GLUE_LOG(ERR, "drop unknown pkt");
		rte_pktmbuf_free(m);
		return NULL;
	}

	if (error) {
		rte_pktmbuf_free(m);
		return NULL;
	}
	error = fill_pkt_hdr_len(m, l2_len, l3_len, l4_len);
	if (error) {
		rte_pktmbuf_free(m);
		return NULL;
	}
	return m;
}


/*
 * HW can recognize L2-arp/L3 with/without extensions/L4 (i40e)
 */
static uint16_t
type0_rx_callback(uint16_t port,
		  uint16_t queue,
		  struct rte_mbuf *pkt[],
		  uint16_t nb_pkts,
		  uint16_t max_pkts,
		  void *user_param)
{
	uint32_t j, tp, l2_len, l3_len;
	struct glue_ctx *ctx;
	uint16_t nb_zero = 0;

	RTE_SET_USED(port);
	RTE_SET_USED(queue);
	RTE_SET_USED(max_pkts);

	ctx = user_param;

	for (j = 0; j != nb_pkts; j++) {
		tp = pkt[j]->packet_type & (RTE_PTYPE_L4_MASK |
		     RTE_PTYPE_L3_MASK | RTE_PTYPE_L2_MASK);

		switch (tp) {
		case (RTE_PTYPE_L2_ETHER_ARP):
			arp_recv(ctx, pkt[j], sizeof(struct ether_hdr));
			pkt[j] = NULL;
			nb_zero++;
			break;
		case (RTE_PTYPE_L4_ICMP | RTE_PTYPE_L3_IPV4 |
		      RTE_PTYPE_L2_ETHER):
		case (RTE_PTYPE_L4_ICMP | RTE_PTYPE_L3_IPV4_EXT |
		      RTE_PTYPE_L2_ETHER):
			l2_len = sizeof(struct ether_hdr);
			l3_len = get_ipv4_hdr_len(pkt[j], l2_len, IPPROTO_ICMP, 0);
			icmp_recv(ctx, pkt[j], l2_len, l3_len);
			pkt[j] = NULL;
			nb_zero++;
			break;
		case (RTE_PTYPE_L4_ICMP | RTE_PTYPE_L3_IPV6 |
		      RTE_PTYPE_L2_ETHER):
		case (RTE_PTYPE_L4_ICMP | RTE_PTYPE_L3_IPV6_EXT |
		      RTE_PTYPE_L2_ETHER):
			l2_len = sizeof(struct ether_hdr);
			l3_len = get_ipv6_hdr_len(pkt[j], l2_len, IPPROTO_ICMPV6);
			icmp6_recv(ctx, pkt[j], l2_len, l3_len);
			pkt[j] = NULL;
			nb_zero++;
			break;
		default:
			if (common_fill_hdr_len(pkt[j], tp, ctx) == NULL) {
				pkt[j] = NULL;
				nb_zero++;
			}
			break;
		}
	}

	if (nb_zero == 0)
		return nb_pkts;

	return compress_pkt_list(pkt, nb_pkts, nb_zero);
}

/*
 * HW can recognize L2/L3/L4 and fragments; but cannot recognize ARP
 * nor ICMP (ixgbe).
 */
static uint16_t
type1_rx_callback(uint16_t port,
		  uint16_t queue,
		  struct rte_mbuf *pkt[],
		  uint16_t nb_pkts,
		  uint16_t max_pkts,
		  void *user_param)
{
	uint32_t j, tp, l2_len, l3_len;
	struct glue_ctx *ctx;
	uint16_t nb_zero = 0;
	const struct ether_hdr *eth;
	const struct ipv4_hdr *ip4;
	const struct ipv6_hdr *ip6;
	uint16_t etp;

	RTE_SET_USED(port);
	RTE_SET_USED(queue);
	RTE_SET_USED(max_pkts);

	ctx = user_param;

	for (j = 0; j != nb_pkts; j++) {
		tp = pkt[j]->packet_type & (RTE_PTYPE_L4_MASK | RTE_PTYPE_L3_MASK |
					    RTE_PTYPE_L2_MASK);

		switch (tp) {
		case RTE_PTYPE_L2_ETHER:
			eth = rte_pktmbuf_mtod(pkt[j], const struct ether_hdr *);
			etp = eth->ether_type;
			if (etp == rte_be_to_cpu_16(ETHER_TYPE_ARP))
				arp_recv(ctx, pkt[j], sizeof(*eth));
			pkt[j] = NULL;
			nb_zero++;
			break;
		case (RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L2_ETHER):
		case (RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_L2_ETHER):
			ip4 = rte_pktmbuf_mtod_offset(pkt[j],
						      const struct ipv4_hdr *,
						      sizeof(*eth));
			if (ip4->next_proto_id == IPPROTO_ICMP) {
				l2_len = sizeof(struct ether_hdr);
				l3_len = get_ipv4_hdr_len(pkt[j], l2_len,
							  IPPROTO_ICMP, 0);
				icmp_recv(ctx, pkt[j], l2_len, l3_len);
			} else
				rte_pktmbuf_free(pkt[j]);

			pkt[j] = NULL;
			nb_zero++;
			break;
		case (RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L2_ETHER):
		case (RTE_PTYPE_L3_IPV6_EXT | RTE_PTYPE_L2_ETHER):
			ip6 = rte_pktmbuf_mtod_offset(pkt[j],
						      const struct ipv6_hdr *,
						      sizeof(*eth));
			if (ip6->proto == IPPROTO_ICMPV6) {
				l2_len = sizeof(struct ether_hdr);
				l3_len = get_ipv6_hdr_len(pkt[j], l2_len,
							  IPPROTO_ICMPV6);
				icmp6_recv(ctx, pkt[j], l2_len, l3_len);
			} else
				rte_pktmbuf_free(pkt[j]);

			pkt[j] = NULL;
			nb_zero++;
			break;
		default:
			if (common_fill_hdr_len(pkt[j], tp, ctx) == NULL) {
				pkt[j] = NULL;
				nb_zero++;
			}
			break;
		}
	}

	if (nb_zero == 0)
		return nb_pkts;

	return compress_pkt_list(pkt, nb_pkts, nb_zero);
}

/*
 * generic, assumes HW doesn't recognize any packet type.
 */
uint16_t
typen_rx_callback(uint16_t port,
		  uint16_t queue,
		  struct rte_mbuf *pkt[],
		  uint16_t nb_pkts,
		  uint16_t max_pkts,
		  void *user_param)
{
	uint32_t j;
	uint16_t nb_zero;
	struct glue_ctx *ctx;

	RTE_SET_USED(port);
	RTE_SET_USED(queue);
	RTE_SET_USED(max_pkts);

	ctx = user_param;

	nb_zero = 0;
	for (j = 0; j != nb_pkts; j++) {
		/* fix me: now we avoid checking ip checksum */
		pkt[j]->ol_flags &= (~PKT_RX_IP_CKSUM_BAD);
		pkt[j]->packet_type = 0;
		pkt[j] = fill_ptypes_and_hdr_len(ctx, pkt[j]);
		nb_zero += (pkt[j] == NULL);
	}

	if (nb_zero == 0)
		return nb_pkts;

	return compress_pkt_list(pkt, nb_pkts, nb_zero);
}

static uint32_t
get_ptypes(uint16_t port_id)
{
	uint32_t smask;
	int32_t i, rc;
	const uint32_t pmask =
		RTE_PTYPE_L2_MASK | RTE_PTYPE_L3_MASK | RTE_PTYPE_L4_MASK;

	smask = 0;
	rc = rte_eth_dev_get_supported_ptypes(port_id, pmask, NULL, 0);
	if (rc < 0) {
		RTE_LOG(ERR, USER1,
			"%s(port=%u) failed to get supported ptypes;\n",
			__func__, port_id);
		return smask;
	}

	uint32_t ptype[rc];
	rc = rte_eth_dev_get_supported_ptypes(port_id, pmask, ptype, rc);

	for (i = 0; i != rc; i++) {
		switch (ptype[i]) {
		case RTE_PTYPE_L2_ETHER_ARP:
			smask |= ETHER_ARP_PTYPE;
			break;
		case RTE_PTYPE_L3_IPV4:
		case RTE_PTYPE_L3_IPV4_EXT_UNKNOWN:
			smask |= IPV4_PTYPE;
			break;
		case RTE_PTYPE_L3_IPV4_EXT:
			smask |= IPV4_EXT_PTYPE;
			break;
		case RTE_PTYPE_L3_IPV6:
		case RTE_PTYPE_L3_IPV6_EXT_UNKNOWN:
			smask |= IPV6_PTYPE;
			break;
		case RTE_PTYPE_L3_IPV6_EXT:
			smask |= IPV6_EXT_PTYPE;
			break;
		case RTE_PTYPE_L4_TCP:
			smask |= TCP_PTYPE;
			break;
		case RTE_PTYPE_L4_UDP:
			smask |= UDP_PTYPE;
			break;
		case RTE_PTYPE_L4_ICMP:
			smask |= ICMP_PTYPE;
			break;
		}
	}

	return smask;
}

/* In rx callbacks, we need to check and make sure below things are done,
 * either by hw or by sw:
 * 1. filter out arp packets, and handle arp packets properly
 *    - for arp request packet, reply arp if it's requesting myself.
 * 2. fill l2, l3, l4 header length
 *
 * 3. GSO/GRO setup (TODO)
 *
 */
int
setup_rx_cb(uint16_t port_id, uint16_t qid)
{
	int32_t rc;
	uint32_t i, n, smask;
	const void *cb;
	struct glue_ctx *ctx;
	const struct ptype2cb *ptype2cb;

	static const struct ptype2cb tcp_arp_ptype2cb[] = {
		{ /* i40e */
			.mask = ETHER_ARP_PTYPE |
				ICMP_PTYPE |
				IPV4_PTYPE | IPV4_EXT_PTYPE |
				IPV6_PTYPE | IPV6_EXT_PTYPE |
				TCP_PTYPE | UDP_PTYPE,
			.name = "HW l2-arp/l3x/l4-tcp ptype",
			.fn = type0_rx_callback,
		},
		{ /* ixgbe does not support ARP ptype */
			.mask = IPV4_PTYPE | IPV4_EXT_PTYPE |
				IPV6_PTYPE | IPV6_EXT_PTYPE |
				TCP_PTYPE | UDP_PTYPE,
			.name = "HW l3x/l4-tcp ptype",
			.fn = type1_rx_callback,
		},
		{ /* virtio */
			.mask = 0,
			.name = "HW does not support any ptype",
			.fn = typen_rx_callback,
		},
	};

	ctx = glue_ctx_lookup(port_id, qid);
	if (ctx == NULL) {
		GLUE_LOG(ERR, "no ctx fount by port(%d) and queue (%d)",
			 port_id, qid);
		return -EINVAL;
	}

	smask = get_ptypes(port_id);

	ptype2cb = tcp_arp_ptype2cb;
	n = RTE_DIM(tcp_arp_ptype2cb);

	for (i = 0; i != n; i++) {
		if ((smask & ptype2cb[i].mask) == ptype2cb[i].mask) {
			cb = rte_eth_add_rx_callback(port_id, qid,
				 		     ptype2cb[i].fn, ctx);
			rc = -rte_errno;
			GLUE_LOG(ERR, "%s(port=%u), setup RX callback \"%s\";",
				 __func__, port_id,  ptype2cb[i].name);
			return ((cb == NULL) ? rc : 0);
		}
	}

	GLUE_LOG(ERR, "%s(port=%u) failed to find an appropriate callback",
		 __func__, port_id);
	return -ENOENT;
}

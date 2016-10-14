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

#include "test_common.h"

int port_init(uint8_t port, struct rte_mempool *mbuf_pool)
{

	struct rte_eth_conf port_conf;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t q;
	int retval;
	int socket_id;

	if (port >= rte_eth_dev_count())
		return -1;

	socket_id = rte_eth_dev_socket_id(port);

	memset(&port_conf, 0, sizeof(struct rte_eth_conf));
	port_conf.rxmode.max_rx_pkt_len = ETHER_MAX_LEN;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
				socket_id, NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
				socket_id, NULL);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Enable RX in promiscuous mode for the Ethernet device. */
	rte_eth_promiscuous_enable(port);

	return 0;
}


/* TODO: Shameless rip of examples/udpfwd/pkt.c below. Sorry...
 * Would like to move these funcions to separate lib so all
 * future created apps could re-use that code. */

void
fill_pkt_hdr_len(struct rte_mbuf *m, uint32_t l2, uint32_t l3, uint32_t l4)
{
	m->l2_len = l2;
	m->l3_len = l3;
	m->l4_len = l4;
	m->tso_segsz = 0;
	m->outer_l2_len = 0;
	m->outer_l3_len = 0;
}

int
is_ipv4_frag(const struct ipv4_hdr *iph)
{
	const uint16_t mask = rte_cpu_to_be_16(~IPV4_HDR_DF_FLAG);

	return ((mask & iph->fragment_offset) != 0);
}

void
fill_ipv4_hdr_len(struct rte_mbuf *m, uint32_t l2, uint32_t proto,
	uint32_t frag)
{
	const struct ipv4_hdr *iph;
	int32_t dlen, len;

	dlen = rte_pktmbuf_data_len(m);
	dlen -= l2 + sizeof(struct udp_hdr);

	iph = rte_pktmbuf_mtod_offset(m, const struct ipv4_hdr *, l2);
	len = (iph->version_ihl & IPV4_HDR_IHL_MASK) * IPV4_IHL_MULTIPLIER;

	if (frag != 0 && is_ipv4_frag(iph)) {
		m->packet_type &= ~RTE_PTYPE_L4_MASK;
		m->packet_type |= RTE_PTYPE_L4_FRAG;
	}

	if (len > dlen || (proto <= IPPROTO_MAX && iph->next_proto_id != proto))
		m->packet_type = RTE_PTYPE_UNKNOWN;
	else
		fill_pkt_hdr_len(m, l2, len, sizeof(struct udp_hdr));
}

int
ipv6x_hdr(uint32_t proto)
{
	return (proto == IPPROTO_HOPOPTS ||
		proto == IPPROTO_ROUTING ||
		proto == IPPROTO_FRAGMENT ||
		proto == IPPROTO_AH ||
		proto == IPPROTO_NONE ||
		proto == IPPROTO_DSTOPTS);
}

uint16_t
ipv4x_cksum(const void *iph, size_t len)
{
        uint16_t cksum;

        cksum = rte_raw_cksum(iph, len);
        return (cksum == 0xffff) ? cksum : ~cksum;
}

void
fill_ipv6x_hdr_len(struct rte_mbuf *m, uint32_t l2, uint32_t nproto,
	uint32_t fproto)
{
	const struct ip6_ext *ipx;
	int32_t dlen, len, ofs;

	len = sizeof(struct ipv6_hdr);

	dlen = rte_pktmbuf_data_len(m);
	dlen -= l2 + sizeof(struct udp_hdr);

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

	/* undercognised or invalid packet. */
	if ((ofs == 0 && nproto != fproto) || len > dlen)
		m->packet_type = RTE_PTYPE_UNKNOWN;
	else
		fill_pkt_hdr_len(m, l2, len, sizeof(struct udp_hdr));
}

void
fill_ipv6_hdr_len(struct rte_mbuf *m, uint32_t l2, uint32_t fproto)
{
	const struct ipv6_hdr *iph;

	iph = rte_pktmbuf_mtod_offset(m, const struct ipv6_hdr *,
		sizeof(struct ether_hdr));

	if (iph->proto == fproto)
		fill_pkt_hdr_len(m, l2, sizeof(struct ipv6_hdr),
			sizeof(struct udp_hdr));
	else if (ipv6x_hdr(iph->proto) != 0)
		fill_ipv6x_hdr_len(m, l2, iph->proto, fproto);
}

void
fill_eth_hdr_len(struct rte_mbuf *m)
{
	uint32_t dlen, l2;
	uint16_t etp;
	const struct ether_hdr *eth;

	dlen = rte_pktmbuf_data_len(m);

	/* check that first segment is at least 42B long. */
	if (dlen < sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +
			sizeof(struct udp_hdr)) {
		m->packet_type = RTE_PTYPE_UNKNOWN;
		return;
	}

	l2 = sizeof(*eth);

	eth = rte_pktmbuf_mtod(m, const struct ether_hdr *);
	etp = eth->ether_type;
	if (etp == rte_be_to_cpu_16(ETHER_TYPE_VLAN))
		l2 += sizeof(struct vlan_hdr);

	if (etp == rte_be_to_cpu_16(ETHER_TYPE_IPv4)) {
		m->packet_type = RTE_PTYPE_L4_UDP |
			RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
			RTE_PTYPE_L2_ETHER;
		fill_ipv4_hdr_len(m, l2, IPPROTO_UDP, 1);
	} else if (etp == rte_be_to_cpu_16(ETHER_TYPE_IPv6) &&
			dlen >= l2 + sizeof(struct ipv6_hdr) +
			sizeof(struct udp_hdr)) {
		m->packet_type = RTE_PTYPE_L4_UDP |
			RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
			RTE_PTYPE_L2_ETHER;
			fill_ipv6_hdr_len(m, l2, IPPROTO_UDP);
	} else
		m->packet_type = RTE_PTYPE_UNKNOWN;
}

/*
 * generic, assumes HW doesn't recognise any packet type.
 */
uint16_t
typen_rx_callback(uint8_t port, __rte_unused uint16_t queue,
	struct rte_mbuf *pkt[], uint16_t nb_pkts,
	__rte_unused uint16_t max_pkts, void *user_param)
{
	uint32_t j;

	for (j = 0; j != nb_pkts; j++) {
		fill_eth_hdr_len(pkt[j]);

	}

	return nb_pkts;
}

int
dummy_lookup4(void *opaque, const struct in_addr *addr,
	struct tle_dest *res)
{
	RTE_SET_USED(opaque);
	RTE_SET_USED(addr);
	RTE_SET_USED(res);
	return -ENOENT;
}

int
dummy_lookup6(void *opaque, const struct in6_addr *addr,
	struct tle_dest *res)
{
	RTE_SET_USED(opaque);
	RTE_SET_USED(addr);
	RTE_SET_USED(res);
	return -ENOENT;
}

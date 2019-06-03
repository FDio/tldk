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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/icmp6.h>

#include <rte_ethdev.h>
#include <rte_arp.h>
#include <rte_ip.h>
#include <rte_hash.h>
#include <rte_byteorder.h>

#include "log.h"
#include "ctx.h"
#include "internal.h"
#include "tle_timer.h"
#include "util.h"
#include "../libtle_l4p/net_misc.h"
#include "ndp.h"
#include "gateway.h"

#define ARP_ENTRY_EXPIRE	60000U
#define ARP_REQUEST_EXPIRE	1000U  /* ms */
#define ARP_MAX_REQ_TIMES	5

static inline void
set_multicast_mac_v6(struct ether_addr *addr, const struct in6_addr *ip6_addr)
{
	unaligned_uint16_t *ea_words = (unaligned_uint16_t *)addr;
	ea_words[0] = 0x3333;
	ea_words[1] = ip6_addr->__in6_u.__u6_addr16[6];
	ea_words[2] = ip6_addr->__in6_u.__u6_addr16[7];
}

static inline void
set_multicast_ipv6(uint8_t ipv6[16])
{
	rte_memcpy(ipv6, &tle_ipv6_multi_mask, IPV6_MULTI_MASK_LEN);
}

static inline void
set_broadcast_addr(struct ether_addr *addr)
{
	unaligned_uint16_t *ea_words = (unaligned_uint16_t *)addr;
	ea_words[0] = 0xFFFF;
	ea_words[1] = 0xFFFF;
	ea_words[2] = 0xFFFF;
}

static void
print_arp_entry(const struct in_addr *ip, const struct ether_addr *mac,
		const char* action)
{
	char str_ip[16];
	char str_mac[32];

	ether_format_addr(str_mac, sizeof(str_mac), mac);
	inet_ntop(AF_INET, &ip->s_addr, str_ip, sizeof(str_ip));
	GLUE_LOG(DEBUG, "%s ARP entry: ipv4=%s/%u, mac=%s",
		 action, str_ip, 24, str_mac);
}

static void
print_arp6_entry(const struct in6_addr *ip6, const struct ether_addr *mac,
		 const char* action)
{
	char str_ip[64];
	char str_mac[32];

	ether_format_addr(str_mac, sizeof(str_mac), mac);
	inet_ntop(AF_INET6, ip6, str_ip, sizeof(str_ip));
	GLUE_LOG(DEBUG, "%s ARP6 entry: ipv6=%s, mac=%s",
		 action, str_ip, str_mac);
}

void
ipv6_dst_add(struct glue_ctx *ctx, const struct in6_addr *addr,
	     struct ether_addr *e_addr)
{
	struct rte_mbuf *pkt, *pkts[32], *pre;
	uint32_t nb_pkts;
	struct arp_entry* entry;
	struct tle_dest *dst;
	struct ether_hdr *eth;
	struct ipv6_hdr *ip6h;
	uint64_t idx;
	int rc;
	uint8_t check_arp_wait = 1;
	struct in6_addr gate6;

	rc = rte_hash_lookup_data(ctx->arp6_hash, addr, (void**)&idx);
	if (rc >= 0) {
		entry = &ctx->arp6[idx];
		dst = &entry->dst;
		eth = (struct ether_hdr *)dst->hdr;

		if (!is_broadcast_ether_addr(&eth->d_addr)) {
			check_arp_wait = 0;
		}
		/* update arp entry, reset timer */
		ether_addr_copy(e_addr, &eth->d_addr);
		print_arp6_entry(addr, &eth->d_addr, "UPDATE");
		if(entry->timer != NULL)
		{
			tle_timer_stop(ctx->arp_tmw, entry->timer);
		}
		entry->timer = tle_timer_start(ctx->arp_tmw, entry, ARP_ENTRY_EXPIRE);
		entry->inuse = 0;

		if(check_arp_wait == 0)
			return;

		/* arp entry start to work */
		entry->req_time = 0;
		nb_pkts = 0;
		pkt = ctx->arp_wait;
		for (pre = NULL; pkt; pkt = pkt->next_pkt) {
			ip6h = rte_pktmbuf_mtod_offset(pkt, struct ipv6_hdr *, pkt->l2_len);
			if (((ip6h->vtc_flow & 0xffffff00) >> 4) != 6 || memcmp(
				ipv6_gateway_lookup(ctx, (struct in6_addr *)&ip6h->dst_addr, &gate6),
				addr, sizeof(struct in6_addr)) != 0) {
				pre = pkt;
				continue;
			}

			if (pre == NULL)
				ctx->arp_wait = pkt->next_pkt;
			else
				pre->next_pkt = pkt->next_pkt;
			eth = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
			ether_addr_copy(e_addr, &eth->d_addr);
			pkts[nb_pkts++] = pkt;
			if (nb_pkts == 32) {
				rte_eth_tx_burst(ctx->port_id, ctx->queue_id, pkts, nb_pkts);
				TRACE("After ARP learn, send %u pkts", nb_pkts);
				nb_pkts = 0;
			}
		}
		if (nb_pkts &&
		    rte_eth_tx_burst(ctx->port_id, ctx->queue_id, pkts, nb_pkts))
			TRACE("After ARP learn, send %u pkts", nb_pkts);
		return;
	}

	rte_spinlock_lock(&ctx->arp6_lock);
	idx = ctx->arp6_num;
	entry = &ctx->arp6[idx];
	dst = &entry->dst;

	/* no need to set dst->dev */
	dst->mtu = 1500;
	dst->l2_len = sizeof(*eth);
	dst->head_mp = get_mempool_by_socket(0); /* fix me */

	eth = (struct ether_hdr *)dst->hdr;
	ether_addr_copy(&ctx->mac, &eth->s_addr);
	if (e_addr == NULL) {
		set_broadcast_addr(&eth->d_addr);
		entry->timer = tle_timer_start(ctx->arp_tmw, entry, ARP_REQUEST_EXPIRE);
		entry->req_time = 1;
	}
	else {
		ether_addr_copy(e_addr, &eth->d_addr);
		entry->timer = tle_timer_start(ctx->arp_tmw, entry, ARP_ENTRY_EXPIRE);
		entry->inuse = 0;
	}
	eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv6);

	dst->l3_len = sizeof(*ip6h);
	ip6h = (struct ipv6_hdr *)(eth + 1);
	rte_memcpy(ip6h->dst_addr, addr, sizeof(struct in6_addr));
	ip6h->vtc_flow = 6 << 4;
	ip6h->hop_limits = 255;
	ip6h->proto = IPPROTO_TCP;

	rc = rte_hash_add_key_data(ctx->arp6_hash, addr, (void*)idx);
	if (rc < 0)
		rte_panic("Failed to add ARP6 entry");

	print_arp6_entry(addr, &eth->d_addr, "ADD");
	ctx->arp6_num++;
	rte_spinlock_unlock(&ctx->arp6_lock);
}

void
ipv4_dst_add(struct glue_ctx *ctx, const struct in_addr *addr,
		 struct ether_addr *e_addr)
{
	struct rte_mbuf *pkt, *pkts[32], *pre;
	uint32_t nb_pkts;
	struct arp_entry* entry;
	struct tle_dest *dst;
	struct ether_hdr *eth;
	struct ipv4_hdr *ip4h;
	uint64_t idx;
	int rc;
	uint8_t check_arp_wait = 1;
	struct in_addr gate4;

	rc = rte_hash_lookup_data(ctx->arp_hash, addr, (void**)&idx);
	if (rc >= 0) {
		entry = &ctx->arp4[idx];
		dst = &entry->dst;
		eth = (struct ether_hdr *)dst->hdr;

		if (!is_broadcast_ether_addr(&eth->d_addr)) {
			check_arp_wait = 0;
		}
		/* update arp entry, reset timer */
		ether_addr_copy(e_addr, &eth->d_addr);
		print_arp_entry(addr, &eth->d_addr, "UPDATE");
		if(entry->timer != NULL)
		{
			tle_timer_stop(ctx->arp_tmw, entry->timer);
		}
		entry->timer = tle_timer_start(ctx->arp_tmw, entry, ARP_ENTRY_EXPIRE);
		entry->inuse = 0;

		if(check_arp_wait == 0)
			return;

		/* arp entry start to work */
		entry->req_time = 0;
		nb_pkts = 0;
		pkt = ctx->arp_wait;
		for (pre = NULL; pkt; pkt = pkt->next_pkt) {
			ip4h = rte_pktmbuf_mtod_offset(pkt, struct ipv4_hdr *, pkt->l2_len);
			if ((ip4h->version_ihl >> 4) != 4
				|| ipv4_gateway_lookup(ctx, (struct in_addr *)&ip4h->dst_addr, &gate4)
					->s_addr != addr->s_addr) {
				pre = pkt;
				continue;
			}
			if (pre == NULL)
				ctx->arp_wait = pkt->next_pkt;
			else
				pre->next_pkt = pkt->next_pkt;
			eth = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
			ether_addr_copy(e_addr, &eth->d_addr);
			pkts[nb_pkts++] = pkt;
			if (nb_pkts == 32) {
				rte_eth_tx_burst(ctx->port_id, ctx->queue_id, pkts, nb_pkts);
				TRACE("After ARP learn, send %u pkts", nb_pkts);
				nb_pkts = 0;
			}
		}
		if (nb_pkts &&
		    rte_eth_tx_burst(ctx->port_id, ctx->queue_id, pkts, nb_pkts))
			TRACE("After ARP learn, send %u pkts", nb_pkts);
		return;
	}

	rte_spinlock_lock(&ctx->arp_lock);
	idx = ctx->arp4_num;
	entry = &ctx->arp4[idx];
	dst = &entry->dst;

	/* no need to set dst->dev */
	dst->mtu = 1500;
	dst->l2_len = sizeof(*eth);
	dst->head_mp = get_mempool_by_socket(0); /* fix me */

	eth = (struct ether_hdr *)dst->hdr;
	ether_addr_copy(&ctx->mac, &eth->s_addr);
	if (e_addr == NULL) {
		set_broadcast_addr(&eth->d_addr);
		entry->timer = tle_timer_start(ctx->arp_tmw, entry, ARP_REQUEST_EXPIRE);
		entry->req_time = 1;
	}
	else {
		ether_addr_copy(e_addr, &eth->d_addr);
		entry->timer = tle_timer_start(ctx->arp_tmw, entry, ARP_ENTRY_EXPIRE);
		entry->inuse = 0;
	}
	eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

	dst->l3_len = sizeof(*ip4h);
	ip4h = (struct ipv4_hdr *)(eth + 1);
	ip4h->dst_addr = addr->s_addr;
	ip4h->version_ihl = 4 << 4 | sizeof(*ip4h) / IPV4_IHL_MULTIPLIER;
	ip4h->time_to_live = 64;
	ip4h->next_proto_id = IPPROTO_TCP;

	rc = rte_hash_add_key_data(ctx->arp_hash, addr, (void*)idx);
	if (rc < 0)
		rte_panic("Failed to add ARP entry");

	print_arp_entry(addr, &eth->d_addr, "ADD");
	ctx->arp4_num++;
	rte_spinlock_unlock(&ctx->arp_lock);
}

static inline int
arp_ip_exist(struct glue_ctx *ctx, uint32_t *ip)
{
	return rte_hash_lookup(ctx->arp_hash, ip) >= 0;
}

static inline int
arp6_ip_exist(struct glue_ctx *ctx, struct in6_addr* ipv6)
{
	return rte_hash_lookup(ctx->arp6_hash, ipv6) >= 0;
}

struct rte_mbuf *
ndp_recv(struct glue_ctx *ctx, struct rte_mbuf *m, uint32_t l2len, uint32_t l3len)
{
	struct ether_hdr *eth_h;
	struct ipv6_hdr *ipv6_h;
	struct nd_neighbor_solicit *ns_h;
	struct nd_opt_hdr *opth;

	eth_h = rte_pktmbuf_mtod(m, struct ether_hdr *);
	ipv6_h = rte_pktmbuf_mtod_offset(m, struct ipv6_hdr*, l2len);
	ns_h = rte_pktmbuf_mtod_offset(m, struct nd_neighbor_solicit*, l2len + l3len);

	if (ipv6_h->payload_len < sizeof(struct nd_neighbor_solicit))
		goto drop;

	/* We only learn mac when:
	 * 1. Normal NS for my ip, whose TargetAddr is me
	 * 2. Normal NA to my ip, whose DstIpv6 is me
	 * 3. Unsolicited NA, and we already have an entry for that IP
	 */

	/* NS message */
	if (ns_h->nd_ns_hdr.icmp6_type == ND_NEIGHBOR_SOLICIT) {
		/* not support Duplicate Address Detect NS yet */
		if (IN6_IS_ADDR_UNSPECIFIED(ipv6_h->src_addr)) {
			goto drop;
		}

		/* NS message, target is my ipv6 addr */
		if (memcmp(&ns_h->nd_ns_target, &ctx->ipv6,
				sizeof(struct in6_addr)) == 0) {
			opth = (struct nd_opt_hdr*)(ns_h + 1);
			ipv6_dst_add(ctx, (struct in6_addr*)ipv6_h->src_addr,
					(struct ether_addr*)(opth + 1));

			/* response NA message */
			ether_addr_copy(&ctx->mac, &eth_h->s_addr);
			ether_addr_copy((struct ether_addr*)(opth + 1), &eth_h->d_addr);

			rte_memcpy(ipv6_h->dst_addr, ipv6_h->src_addr,
					sizeof(struct in6_addr));
			rte_memcpy(ipv6_h->src_addr, &ctx->ipv6,
					sizeof(struct in6_addr));

			ns_h->nd_ns_hdr.icmp6_type = ND_NEIGHBOR_ADVERT;
			ns_h->nd_ns_hdr.icmp6_dataun.icmp6_un_data8[0] = 0x60;
			ns_h->nd_ns_hdr.icmp6_cksum = 0;

			opth->nd_opt_type = ND_OPT_TARGET_LINKLAYER_ADDR;
			ether_addr_copy(&ctx->mac, (struct ether_addr*)(opth + 1));

			ns_h->nd_ns_hdr.icmp6_cksum = rte_ipv6_udptcp_cksum(ipv6_h, ns_h);

			if (m->pkt_len < ETHER_MIN_LEN)
				rte_pktmbuf_append(m, ETHER_MIN_LEN - m->pkt_len);

			if (rte_eth_tx_burst(ctx->port_id, ctx->queue_id, &m, 1))
				GLUE_LOG(DEBUG, "Send NDP NA reply");

			return NULL;
		}
	} else {
	/* NA message */
		if (memcmp(ipv6_h->dst_addr, &ctx->ipv6, sizeof(struct in6_addr)) == 0 ||
				(memcmp(ipv6_h->dst_addr, &tle_ipv6_all_multi,
						sizeof(struct in6_addr)) == 0 &&
						arp6_ip_exist(ctx, &ns_h->nd_ns_target))) {
			opth = (struct nd_opt_hdr*)(ns_h + 1);
			ipv6_dst_add(ctx, &ns_h->nd_ns_target, (struct ether_addr*)(opth + 1));
		}
	}

drop:
	rte_pktmbuf_free(m);
	return NULL;
}

struct rte_mbuf *
arp_recv(struct glue_ctx *ctx, struct rte_mbuf *m, uint32_t l2len)
{
	struct ether_hdr *eth;
	struct arp_hdr *ahdr;
	struct arp_ipv4 *adata;
	uint32_t tip;

	eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
	ahdr = rte_pktmbuf_mtod_offset(m, struct arp_hdr *, l2len);

	if (ahdr->arp_hrd != rte_be_to_cpu_16(ARP_HRD_ETHER) ||
	    ahdr->arp_pro != rte_be_to_cpu_16(ETHER_TYPE_IPv4))
		goto drop;

	adata = &ahdr->arp_data;
	tip = adata->arp_tip;

	/* We only learn mac when:
	 * 1. tip is me, or
	 * 2. this is a RARP, and we already have an entry for that IP
	 */
	if (tip == ctx->ipv4 ||
	    (tip == INADDR_ANY && arp_ip_exist(ctx, &adata->arp_sip)))
		ipv4_dst_add(ctx, (struct in_addr *)&adata->arp_sip,
			     &adata->arp_sha);

	/* We only do ARP reply when:
	 * 1. tip is me.
	 */
	if (ahdr->arp_op == rte_be_to_cpu_16(ARP_OP_REQUEST) &&
	    tip == ctx->ipv4) {
		eth->d_addr = eth->s_addr;
		eth->s_addr = ctx->mac;
		ahdr->arp_op = rte_cpu_to_be_16(ARP_OP_REPLY);

		adata->arp_tip = adata->arp_sip;
		adata->arp_sip = tip;

		adata->arp_tha = adata->arp_sha;
		adata->arp_sha = ctx->mac;
		if (m->pkt_len < ETHER_MIN_LEN)
			rte_pktmbuf_append(m, ETHER_MIN_LEN - m->pkt_len);
		PKT_DUMP(m);
		if (rte_eth_tx_burst(ctx->port_id, ctx->queue_id, &m, 1))
			TRACE("sent arp reply");
		return NULL;
	}
drop:
	rte_pktmbuf_free(m);
	return NULL;
}

static void
arp6_send_request(struct glue_ctx *ctx, const struct in6_addr *addr)
{
	struct rte_mempool *mp = get_mempool_by_socket(0); /* fix me */
	struct ether_hdr *eth;
	struct ipv6_hdr *ip6h;
	struct nd_neighbor_solicit *nsh;
	struct nd_opt_hdr *opth;
	struct ether_addr *sll_addr;
	struct rte_mbuf *m;
#ifdef ENABLE_TRACE
	char str_ip[64];
#endif

	m = rte_pktmbuf_alloc(mp);
	if (m == NULL)
		rte_panic("Failed to alloc mbuf for ndp ns request");

	eth = (struct ether_hdr *)rte_pktmbuf_append(m, sizeof(*eth));
	ether_addr_copy(&ctx->mac, &eth->s_addr);
	set_multicast_mac_v6(&eth->d_addr, addr);
	eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv6);

	ip6h = (struct ipv6_hdr*)rte_pktmbuf_append(m, sizeof(struct ipv6_hdr));
	ip6h->vtc_flow = 6 << 4;
	ip6h->payload_len = sizeof(struct nd_neighbor_solicit) +
			sizeof(struct nd_opt_hdr) + sizeof(struct ether_addr);
	ip6h->proto = IPPROTO_ICMPV6;
	ip6h->hop_limits = 255;
	rte_memcpy(ip6h->src_addr, &ctx->ipv6, sizeof(struct in6_addr));
	rte_memcpy(ip6h->dst_addr, addr, sizeof(struct in6_addr));
	set_multicast_ipv6(ip6h->dst_addr);

	nsh = (struct nd_neighbor_solicit*)rte_pktmbuf_append(m,
			sizeof(struct nd_neighbor_solicit));
	nsh->nd_ns_hdr.icmp6_type = ND_NEIGHBOR_SOLICIT;
	nsh->nd_ns_hdr.icmp6_code = 0;
	nsh->nd_ns_hdr.icmp6_cksum = 0;
	nsh->nd_ns_hdr.icmp6_dataun.icmp6_un_data32[0] = 0;
	rte_memcpy(&nsh->nd_ns_target, addr, sizeof(struct in6_addr));

	opth = (struct nd_opt_hdr*)rte_pktmbuf_append(m, sizeof(struct nd_opt_hdr));
	opth->nd_opt_type = ND_OPT_SOURCE_LINKLAYER_ADDR;
	opth->nd_opt_len = 1;

	sll_addr = (struct ether_addr*)rte_pktmbuf_append(m, sizeof(struct ether_addr));
	ether_addr_copy(&ctx->mac, sll_addr);

	nsh->nd_ns_hdr.icmp6_cksum = rte_ipv6_udptcp_cksum(ip6h, nsh);

	while (rte_eth_tx_burst(ctx->port_id, ctx->queue_id, &m, 1) == 0);
}

static void
arp_send_request(struct glue_ctx *ctx, const struct in_addr *addr)
{
	struct rte_mempool *mp = get_mempool_by_socket(0); /* fix me */
	struct ether_hdr *eth;
	struct arp_hdr *ahdr;
	struct arp_ipv4 *adata;
	struct rte_mbuf *m;
	uint16_t pad_len, i;
	char *pad;

	m = rte_pktmbuf_alloc(mp);
	if (m == NULL)
		rte_panic("Failed to alloc mbuf for arp request");

	eth = (struct ether_hdr *)rte_pktmbuf_append(m, sizeof(*eth));
	ether_addr_copy(&ctx->mac, &eth->s_addr);
	set_broadcast_addr(&eth->d_addr);
	eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_ARP);

	ahdr = (struct arp_hdr *)rte_pktmbuf_append(m, sizeof(*ahdr));
	ahdr->arp_hrd = rte_be_to_cpu_16(ARP_HRD_ETHER);
	ahdr->arp_pro = rte_be_to_cpu_16(ETHER_TYPE_IPv4);
	ahdr->arp_hln = sizeof(struct ether_addr);
	ahdr->arp_pln = sizeof(*addr);
	ahdr->arp_op = rte_be_to_cpu_16(ARP_OP_REQUEST);
	adata = &ahdr->arp_data;
	ether_addr_copy(&ctx->mac, &adata->arp_sha);
	adata->arp_sip = ctx->ipv4;
	set_broadcast_addr(&adata->arp_tha);
	adata->arp_tip = addr->s_addr;

	pad_len = ETHER_MIN_LEN - sizeof(*eth) - sizeof(*ahdr);
	pad = rte_pktmbuf_append(m, pad_len);
	for (i = 0; i < pad_len; ++i)
		pad[i] = 0;

	while (rte_eth_tx_burst(ctx->port_id, ctx->queue_id, &m, 1) == 0);
}

void
mac_check(struct glue_ctx *ctx, const struct sockaddr* addr)
{
	int rc;
	const struct in_addr* addr4 = NULL;
	struct in_addr gate4;
	const struct in6_addr* addr6 = NULL;
	struct in6_addr gate6;

	if(addr->sa_family == AF_INET) {
		addr4 = ipv4_gateway_lookup(ctx,
				&((const struct sockaddr_in *)addr)->sin_addr, &gate4);
		rc = rte_hash_lookup(ctx->arp_hash, addr4);
	}
	else {
		addr6 = ipv6_gateway_lookup(ctx,
				&((const struct sockaddr_in6 *)addr)->sin6_addr, &gate6);
		rc = rte_hash_lookup(ctx->arp6_hash, addr6);
	}
	if (rc >= 0)
		return;

	if(addr->sa_family == AF_INET) {
		arp_send_request(ctx, addr4);
		//ipv4_dst_add(ctx, addr, NULL);
	} else {
		arp6_send_request(ctx, addr6);
		//ipv6_dst_add(ctx, addr, NULL);
	}
}

static int
arp_inherit(struct glue_ctx *ctx, const struct in_addr *addr)
{
	struct glue_ctx *next = NULL;
	uint64_t idx;
	uint16_t i;
	struct tle_dest *dst;
	struct ether_hdr *eth;
	int rc;

	for (i = 0; i < nb_ctx; i++) {
		next = &ctx_array[i++];
		if (next == NULL || next == ctx)
			continue;

		rc = rte_hash_lookup_data(next->arp_hash, addr, (void**)&idx);
		if (rc < 0)
			continue;

		dst = &next->arp4[idx].dst;
		eth = (struct ether_hdr *)dst->hdr;
		ipv4_dst_add(ctx, addr, &eth->d_addr);
		return 0;
	}

	return -1;
}

static int
arp6_inherit(struct glue_ctx *ctx, const struct in6_addr *addr)
{
	struct glue_ctx *next = NULL;
	uint64_t idx;
	uint16_t i;
	struct tle_dest *dst;
	struct ether_hdr *eth;
	int rc;

	for (i = 0; i < nb_ctx; i++) {
		next = &ctx_array[i++];
		if (next == NULL || next == ctx)
			continue;

		rc = rte_hash_lookup_data(next->arp6_hash, addr, (void**)&idx);
		if (rc < 0)
			continue;

		dst = &next->arp6[idx].dst;
		eth = (struct ether_hdr *)dst->hdr;
		ipv6_dst_add(ctx, addr, &eth->d_addr);
		return 0;
	}

	return -1;
}

static int
arp_ipv6_dst_lookup(struct glue_ctx *ctx, const struct in6_addr *addr,
		    struct tle_dest *res, struct tle_dev *dev)
{
	int32_t rc;
	uint64_t idx;
	struct tle_dest *dst;

	if (is_ipv6_loopback_addr(addr, ctx)) {
		dst = &ctx->lb_dst_v6;
		rte_memcpy(res, dst, dst->l2_len + dst->l3_len +
			   offsetof(struct tle_dest, hdr));
		res->dev = dev;
		return 0;
	}

retry:
	rc = rte_hash_lookup_data(ctx->arp6_hash, addr, (void**)&idx);
	if (rc >= 0) {
		if (!ctx->arp6[idx].inuse)
			ctx->arp6[idx].inuse = 1;
		dst = &ctx->arp6[idx].dst;
		rte_memcpy(res, dst, dst->l2_len + dst->l3_len +
			   offsetof(struct tle_dest, hdr));
		res->dev = dev;
	} else {
		if (arp6_inherit(ctx, addr) < 0)
			ipv6_dst_add(ctx, addr, NULL);
		goto retry;
	}

	return rc;
}

static int
arp_ipv4_dst_lookup(struct glue_ctx *ctx, const struct in_addr *addr,
		    struct tle_dest *res, struct tle_dev *dev)
{
	int32_t rc;
	uint64_t idx;
	struct tle_dest *dst;

	if (is_ipv4_loopback_addr(addr->s_addr, ctx)) {
		dst = &ctx->lb_dst;
		rte_memcpy(res, dst, dst->l2_len + dst->l3_len +
			   offsetof(struct tle_dest, hdr));
		res->dev = dev;
		return 0;
	}

retry:
	rc = rte_hash_lookup_data(ctx->arp_hash, addr, (void**)&idx);
	if (rc >= 0) {
		if (!ctx->arp4[idx].inuse)
			ctx->arp4[idx].inuse = 1;
		dst = &ctx->arp4[idx].dst;
		rte_memcpy(res, dst, dst->l2_len + dst->l3_len +
			   offsetof(struct tle_dest, hdr));
		res->dev = dev;
	} else {
		if (arp_inherit(ctx, addr) < 0)
			ipv4_dst_add(ctx, addr, NULL);
		goto retry;
	}

	return rc;
}

int
arp_ipv4_dst_lookup_tcp(void *data, const struct in_addr *addr,
			struct tle_dest *res)
{
	struct glue_ctx *ctx = data;

	if (is_ipv4_loopback_addr(addr->s_addr, ctx))
		return arp_ipv4_dst_lookup(ctx, addr, res, ctx->lb_tcp_dev);
	else
		return arp_ipv4_dst_lookup(ctx, addr, res, ctx->tcp_dev);
}

int
arp_ipv6_dst_lookup_tcp(void *data, const struct in6_addr *addr,
			struct tle_dest *res)
{
	struct glue_ctx *ctx = data;

	if (is_ipv6_loopback_addr(addr, ctx))
		return arp_ipv6_dst_lookup(ctx, addr, res, ctx->lb_tcp_dev);
	else
		return arp_ipv6_dst_lookup(ctx, addr, res, ctx->tcp_dev);
}

int
arp_ipv4_dst_lookup_udp(void *data, const struct in_addr *addr,
			struct tle_dest *res)
{
	int rc;
	struct glue_ctx *ctx = data;
	struct ipv4_hdr *ip4h;

	if (is_ipv4_loopback_addr(addr->s_addr, ctx))
		rc = arp_ipv4_dst_lookup(ctx, addr, res, ctx->lb_udp_dev);
	else
		rc = arp_ipv4_dst_lookup(ctx, addr, res, ctx->udp_dev);

	if (rc >= 0) {
		/* fix next_proto_id */
		ip4h = (struct ipv4_hdr *)&res->hdr[res->l2_len];
		ip4h->next_proto_id = IPPROTO_UDP;
	}
	return rc;
}

int
arp_ipv6_dst_lookup_udp(void *data, const struct in6_addr *addr,
			struct tle_dest *res)
{
	int rc;
	struct glue_ctx *ctx = data;
	struct ipv6_hdr *ip6h;

	if (is_ipv6_loopback_addr(addr, ctx))
		rc = arp_ipv6_dst_lookup(ctx, addr, res, ctx->lb_udp_dev);
	else
		rc = arp_ipv6_dst_lookup(ctx, addr, res, ctx->udp_dev);

	if (rc >= 0) {
		/* fix next_proto_id */
		ip6h = (struct ipv6_hdr *)&res->hdr[res->l2_len];
		ip6h->proto = IPPROTO_UDP;
	}
	return rc;
}

int
mac_fill(struct glue_ctx *ctx, struct rte_mbuf *m)
{
	int32_t rc;
	uint64_t idx;
	struct arp_entry* entry;
	struct ether_addr *dst, *dst1;
	struct ipv4_hdr *ipv4_hdr;
	struct ipv6_hdr *ipv6_hdr;
	uint8_t ipver;
	const struct in_addr* addr4 = NULL;
	struct in_addr gate4;
	const struct in6_addr* addr6 = NULL;
	struct in6_addr gate6;

	dst = rte_pktmbuf_mtod(m, struct ether_addr *);
	if (!is_broadcast_ether_addr(dst))
		return 0;

	ipv4_hdr = rte_pktmbuf_mtod_offset(m, struct ipv4_hdr *, m->l2_len);
	ipv6_hdr = NULL;
	ipver = ipv4_hdr->version_ihl >> 4;
	if (ipver == 4) {
		addr4 = ipv4_gateway_lookup(ctx,
				(const struct in_addr *)&ipv4_hdr->dst_addr, &gate4);
		rc = rte_hash_lookup_data(ctx->arp_hash, addr4, (void**)&idx);
		if (rc >= 0)
			entry = &ctx->arp4[idx];
	} else {
		ipv6_hdr = (struct ipv6_hdr*)ipv4_hdr;
		addr6 = ipv6_gateway_lookup(ctx,
				(const struct in6_addr *)ipv6_hdr->dst_addr, &gate6);
		rc = rte_hash_lookup_data(ctx->arp6_hash, addr6, (void**)&idx);
		if (rc >= 0)
			entry = &ctx->arp6[idx];
	}
	
	if (rc >= 0) {
		dst1 = (struct ether_addr *)entry->dst.hdr;
		if (!is_broadcast_ether_addr(dst1)) {
			ether_addr_copy(dst1 , dst);
			return 0;
		}

		if (ipver == 4)
			arp_send_request(ctx, addr4);
		else
			arp6_send_request(ctx, addr6);
		entry->req_time++;
		if (entry->timer != NULL) {
			tle_timer_stop(ctx->arp_tmw, entry->timer);
		}
		entry->timer = tle_timer_start(ctx->arp_tmw, entry, ARP_REQUEST_EXPIRE);
	}

	return -1;
}

static inline const struct in_addr *
get_addr_from_entry(struct arp_entry *e)
{
	const struct ipv4_hdr *ipv4;
	const struct in_addr *addr;

	ipv4 = (struct ipv4_hdr *)(e->dst.hdr + e->dst.l2_len);
	addr = (const struct in_addr *)&ipv4->dst_addr;

	return addr;
}

static inline const struct in6_addr *
get_addr6_from_entry(struct arp_entry *e)
{
	const struct ipv6_hdr *ipv6;
	const struct in6_addr *addr;

	ipv6 = (struct ipv6_hdr *)(e->dst.hdr + e->dst.l2_len);
	addr = (const struct in6_addr *)ipv6->dst_addr;

	return addr;
}

static inline void
arp6_entry_del(struct glue_ctx *ctx, struct arp_entry *e)
{
	const struct in6_addr *addr;
	struct ether_addr *eth_addr;
	struct rte_mbuf *pkt, *pre;
	uint32_t idx, last_idx;
	struct ipv6_hdr *ip6h;

	idx = e - ctx->arp6;
	last_idx = ctx->arp6_num - 1;
	if (idx > last_idx) /* entry has been moved, don't timeout this time */
		return;

	addr = get_addr6_from_entry(e);
	eth_addr = (struct ether_addr*)e->dst.hdr;

	print_arp6_entry(addr, eth_addr, "DELETE");
	if (e->req_time > ARP_MAX_REQ_TIMES) {
		/* free pkts waiting for the ARP response */
		pkt = ctx->arp_wait;
		for (pre = NULL; pkt != NULL; pkt = pkt->next_pkt) {
			ip6h = rte_pktmbuf_mtod_offset(pkt, struct ipv6_hdr *,
							pkt->l2_len);
			if (memcmp(addr, ip6h->dst_addr, sizeof(struct in6_addr)) != 0) {
				pre = pkt;
				continue;
			}

			if (pre == NULL)
				ctx->arp_wait = pkt->next_pkt;
			else
				pre->next_pkt = pkt->next_pkt;

			rte_pktmbuf_free(pkt);
		}
	}

	rte_hash_del_key(ctx->arp6_hash, addr);

	/* if it's not the last entry, use last entry to replace current entry */
	if (idx < last_idx) {
		rte_memcpy(e, ctx->arp6 + last_idx, sizeof(*e));
		rte_hash_add_key_data(ctx->arp6_hash, addr, (void*)(uintptr_t)idx);
		tle_timer_stop(ctx->arp_tmw, ctx->arp6[last_idx].timer);
		if (e->req_time > 0) {
			e->timer = tle_timer_start(ctx->arp_tmw, e, ARP_REQUEST_EXPIRE);
		} else {
			e->timer = tle_timer_start(ctx->arp_tmw, e, ARP_ENTRY_EXPIRE);
			e->inuse = 0;
		}
	}

	/* we always delete the last entry to keep it contiguous */
	ctx->arp6[last_idx].timer = NULL;
	ctx->arp6[last_idx].inuse = 0;
	ctx->arp6[last_idx].req_time = 0;
	ctx->arp6_num--;
}

static inline void
arp_entry_del(struct glue_ctx *ctx, struct arp_entry *e)
{
	const struct in_addr *addr;
	struct ether_addr *eth_addr;
	struct rte_mbuf *pkt, *pre;
	uint32_t idx, last_idx;
	struct ipv4_hdr *ip4h;

	idx = e - ctx->arp4;
	last_idx = ctx->arp4_num - 1;
	if (idx > last_idx) /* entry has been moved, don't timeout this time */
		return;

	addr = get_addr_from_entry(e);
	eth_addr = (struct ether_addr*)e->dst.hdr;

	print_arp_entry(addr, eth_addr, "DELETE");
	if (e->req_time > ARP_MAX_REQ_TIMES) {
		/* free pkts waiting for the ARP response */
		pkt = ctx->arp_wait;
		for (pre = NULL; pkt != NULL; pkt = pkt->next_pkt) {
			ip4h = rte_pktmbuf_mtod_offset(pkt, struct ipv4_hdr *,
							pkt->l2_len);
			if (addr->s_addr != ip4h->dst_addr) {
				pre = pkt;
				continue;
			}

			if (pre == NULL)
				ctx->arp_wait = pkt->next_pkt;
			else
				pre->next_pkt = pkt->next_pkt;

			rte_pktmbuf_free(pkt);
		}
	}

	rte_hash_del_key(ctx->arp_hash, addr);

	/* if it's not the last entry, use last entry to replace current entry */
	if (idx < last_idx) {
		rte_memcpy(e, ctx->arp4 + last_idx, sizeof(*e));
		rte_hash_add_key_data(ctx->arp_hash, addr, (void*)(uintptr_t)idx);
		tle_timer_stop(ctx->arp_tmw, ctx->arp4[last_idx].timer);
		if (e->req_time > 0) {
			e->timer = tle_timer_start(ctx->arp_tmw, e, ARP_REQUEST_EXPIRE);
		} else {
			e->timer = tle_timer_start(ctx->arp_tmw, e, ARP_ENTRY_EXPIRE);
			e->inuse = 0;
		}
	}

	/* we always delete the last entry to keep it contiguous */
	ctx->arp4[last_idx].timer = NULL;
	ctx->arp4[last_idx].inuse = 0;
	ctx->arp4[last_idx].req_time = 0;
	ctx->arp4_num--;
}

void
mac_timeout(struct glue_ctx *ctx)
{
#define ARP_PROCESS_MAX	32
	struct arp_entry *entry[ARP_PROCESS_MAX], *e;
	struct tle_timer_wheel *tw;
	uint32_t i, cnt;
	uint8_t *l3h;

	tw = ctx->arp_tmw;
	tle_timer_expire(tw, rte_get_tsc_cycles() >> ctx->cycles_ms_shift);
	cnt = tle_timer_get_expired_bulk(tw, (void**)entry, ARP_PROCESS_MAX);
	if (cnt == 0)
		return;

	rte_spinlock_lock(&ctx->arp_lock);
	for(i = 0; i < cnt; i++) {
		e = entry[i];
		e->timer = NULL;
		l3h = e->dst.hdr + e->dst.l2_len;
		if (e->inuse ||
		    (e->req_time > 0 && e->req_time <= ARP_MAX_REQ_TIMES))
		{
			if (((struct ipv4_hdr*)l3h)->version_ihl >> 4 == 4)
				arp_send_request(ctx, (struct in_addr*)
						(&((struct ipv4_hdr*)l3h)->dst_addr));
			else
				arp6_send_request(ctx, (struct in6_addr*)
						(((struct ipv6_hdr*)l3h)->dst_addr));

			e->timer = tle_timer_start(ctx->arp_tmw, e,
						   ARP_REQUEST_EXPIRE);
			e->inuse = 0;
			e->req_time++;
		} else {
			if (((struct ipv4_hdr*)l3h)->version_ihl >> 4 == 4)
				arp_entry_del(ctx, e);
			else
				arp6_entry_del(ctx, e);
		}
	}
	rte_spinlock_unlock(&ctx->arp_lock);
}

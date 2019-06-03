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
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <rte_malloc.h>
#include <rte_random.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_hash.h>
#include <rte_spinlock.h>

#include "config.h"
#include "ctx.h"
#include "log.h"
#include "util.h"
#include "internal.h"
#include "gateway.h"
#include "tle_timer.h"

RTE_DEFINE_PER_LCORE(struct glue_ctx *, glue_ctx);

int nb_ctx;
struct glue_ctx ctx_array[MAX_NB_CTX];
struct glue_ctx *default_ctx = &ctx_array[0];

static int ipv4_dst_lookup_tcp(void *data,
		const struct in_addr *addr, struct tle_dest *res)
{
	struct in_addr gate;
	addr = ipv4_gateway_lookup(data, addr, &gate);
	return arp_ipv4_dst_lookup_tcp(data, addr, res);
}

static int ipv4_dst_lookup_udp(void *data,
		const struct in_addr *addr, struct tle_dest *res)
{
	struct in_addr gate;
	addr = ipv4_gateway_lookup(data, addr, &gate);
	return arp_ipv4_dst_lookup_udp(data, addr, res);
}

static int ipv6_dst_lookup_tcp(void *data,
		const struct in6_addr *addr, struct tle_dest *res)
{
	struct in6_addr gate;
	addr = ipv6_gateway_lookup(data, addr, &gate);
	return arp_ipv6_dst_lookup_tcp(data, addr, res);
}

static int ipv6_dst_lookup_udp(void *data,
		const struct in6_addr *addr, struct tle_dest *res)
{
	struct in6_addr gate;
	addr = ipv6_gateway_lookup(data, addr, &gate);
	return arp_ipv6_dst_lookup_udp(data, addr, res);
}

static struct tle_ctx *proto_ctx_create(uint32_t socket_id, uint32_t proto, void *data)
{
	struct tle_ctx_param cprm;

	if (proto != TLE_PROTO_TCP && proto != TLE_PROTO_UDP)
		rte_panic("Invalid proto [%u]\n", proto);

	cprm.socket_id = socket_id;
	cprm.proto = proto;
	cprm.max_streams = MAX_STREAMS_PER_CORE;
	cprm.min_streams = MIN_STREAMS_PER_CORE;
	cprm.delta_streams = DELTA_STREAMS;
	cprm.max_stream_rbufs = MAX_RECV_BUFS_PER_STREAM;
	cprm.max_stream_sbufs = MAX_SEND_BUFS_PER_STREAM;
	if (proto == TLE_PROTO_TCP) {
		cprm.lookup4 = ipv4_dst_lookup_tcp;
		cprm.lookup6 = ipv6_dst_lookup_tcp;
	} else {
		cprm.lookup4 = ipv4_dst_lookup_udp;
		cprm.lookup6 = ipv6_dst_lookup_udp;
	}
	cprm.lookup4_data = data;
	cprm.lookup6_data = data;
#ifdef LOOK_ASIDE_BACKEND
	cprm.flags = 0;
#else
	cprm.flags = TLE_CTX_FLAG_ST; /* ctx will be used by single thread*/
#endif
	cprm.send_bulk_size = 0; /* 32 if 0 */
	cprm.hash_alg = TLE_SIPHASH;
	cprm.secret_key.u64[0] = rte_rand();
	cprm.secret_key.u64[1] = rte_rand();
	cprm.icw = 0; /**< congestion window, default is 2*MSS if 0. */
	cprm.timewait = 1;  /* TLE_TCP_TIMEWAIT_DEFAULT */

	return tle_ctx_create(&cprm);
}

static int evq_init(struct glue_ctx *ctx, uint32_t socket_id)
{
	struct tle_evq_param eprm;

	eprm.socket_id = socket_id;
	eprm.max_events = MAX_STREAMS_PER_CORE; 
	ctx->syneq = tle_evq_create(&eprm);
	if (ctx->syneq == NULL)
		rte_panic("Cannot create syneq");
		
	ctx->ereq = tle_evq_create(&eprm);
	if (ctx->ereq == NULL)
		rte_panic("Cannot create ereq");

	ctx->rxeq = tle_evq_create(&eprm);
	if (ctx->rxeq == NULL)
		rte_panic("Cannot create rxeq");

	ctx->txeq = tle_evq_create(&eprm);
	if (ctx->txeq == NULL)
		rte_panic("Cannot create txeq");

	return 0;
}

static void tle_ctx_init(struct glue_ctx *ctx, uint32_t socket_id)
{
	struct tle_dev_param dprm;
	struct rte_eth_dev_info dev_info;
	uint16_t port_id = 0;	/* currently only use one port */

	ctx->tcp_ctx = proto_ctx_create(socket_id, TLE_PROTO_TCP, ctx);
	if (ctx->tcp_ctx == NULL)
		rte_panic("Cannot create tle_ctx for tcp");

	ctx->udp_ctx = proto_ctx_create(socket_id, TLE_PROTO_UDP, ctx);
	if (ctx->udp_ctx == NULL)
		rte_panic("Cannot create tle_ctx for udp");

	memset(&dprm, 0, sizeof(dprm));

	/* offloading check and set */
	rte_eth_dev_info_get(port_id, &dev_info);
	dprm.rx_offload = dev_info.rx_offload_capa & rx_offload;
	dprm.tx_offload = dev_info.tx_offload_capa & tx_offload;

	dprm.local_addr4.s_addr = ctx->ipv4;
	rte_memcpy(&dprm.local_addr6, &ctx->ipv6, sizeof(struct in6_addr));
	dprm.bl4.nb_port = 0;
	dprm.bl4.port = NULL;
	dprm.bl6.nb_port = 0;
	dprm.bl6.port = NULL;

	ctx->tcp_dev = tle_add_dev(ctx->tcp_ctx, &dprm);
	if (ctx->tcp_dev == NULL)
		rte_panic("add tle_dev for tcp failed: %u", rte_errno);

	ctx->udp_dev = tle_add_dev(ctx->udp_ctx, &dprm);
	if (ctx->udp_dev == NULL)
		rte_panic("add tle_dev for udp failed: %u", rte_errno);

	if (ctx == default_ctx) {
		dprm.rx_offload = rx_offload;
		dprm.tx_offload = tx_offload;
		dprm.local_addr4.s_addr = htonl(INADDR_LOOPBACK);
		rte_memcpy(&dprm.local_addr6, &in6addr_loopback,
			   sizeof(struct in6_addr));

		ctx->lb_tcp_dev = tle_add_dev(ctx->tcp_ctx, &dprm);
		if (ctx->lb_tcp_dev == NULL)
			rte_panic("failed to add loopback tcp dev: %u\n",
				  rte_errno);

		ctx->lb_udp_dev = tle_add_dev(ctx->udp_ctx, &dprm);
		if (ctx->lb_udp_dev == NULL)
			rte_panic("failed to add loopback udp dev: %u\n",
				  rte_errno);
	}

	evq_init(ctx, socket_id);
}

static uint32_t
get_ip(void)
{
	struct in_addr addr;
	const char *ip_str = getenv(DPDK_IP);

	if (ip_str == NULL) {
		ip_str = DPDK_IP_DEF;
		GLUE_LOG(INFO, "will use the default IP %s", DPDK_IP_DEF);
	} else
		GLUE_LOG(INFO, "will use the IP %s", ip_str);

	if (inet_aton(ip_str, &addr) == 0)
		rte_panic("Invalid addr from env DPDK_IP: %s", ip_str);

	return addr.s_addr;
}

static uint8_t
get_ip_mask(void)
{
	const char *mask_str = getenv(DPDK_IP_MASK);

	if (mask_str == NULL) {
		mask_str = DPDK_IP_MASK_DEF;
		GLUE_LOG(INFO, "will use the default IP Mask %s", DPDK_IP_MASK_DEF);
	} else
		GLUE_LOG(INFO, "will use the IP Mask %s", mask_str);

	return (uint8_t)atoi(mask_str);
}

static uint32_t
get_ip_gate(void)
{
	struct in_addr addr;
	const char *ip_str = getenv(DPDK_IP_GATEWAY);

	if (ip_str == NULL) {
		ip_str = DPDK_IP_GATEWAY_DEF;
		GLUE_LOG(INFO, "will use the default IP gateway %s", DPDK_IP_GATEWAY_DEF);
	} else
		GLUE_LOG(INFO, "will use the IP gateway %s", ip_str);

	if (inet_aton(ip_str, &addr) == 0)
		rte_panic("Invalid addr from env DPDK_IP_GATEWAY: %s", ip_str);

	return addr.s_addr;
}

static struct in6_addr*
get_ipv6(void)
{
	static struct in6_addr addr;
	const char *ip_str = getenv(DPDK_IPV6);

	if (ip_str == NULL) {
		ip_str = DPDK_IPV6_DEF;
		GLUE_LOG(INFO, "will use the default IP(V6) %s", DPDK_IPV6_DEF);
	} else
		GLUE_LOG(INFO, "will use the IP(V6) %s", ip_str);

	if (inet_pton(AF_INET6, ip_str, &addr) == 0)
		rte_panic("Invalid addr from env DPDK_IPV6: %s", ip_str);

	return &addr;
}

static uint8_t
get_ipv6_mask(void)
{
	const char *mask_str = getenv(DPDK_IPV6_MASK);

	if (mask_str == NULL) {
		mask_str = DPDK_IPV6_MASK_DEF;
		GLUE_LOG(INFO, "will use the default IPV6 Mask %s", DPDK_IPV6_MASK_DEF);
	} else
		GLUE_LOG(INFO, "will use the IPV6 Mask %s", mask_str);

	return (uint8_t)atoi(mask_str);
}

static struct in6_addr*
get_ipv6_gate(void)
{
	static struct in6_addr addr;
	const char *ip_str = getenv(DPDK_IPV6_GATEWAY);

	if (ip_str == NULL) {
		ip_str = DPDK_IPV6_GATEWAY_DEF;
		GLUE_LOG(INFO, "will use the default IP(V6) gateway %s", DPDK_IPV6_GATEWAY_DEF);
	} else
		GLUE_LOG(INFO, "will use the IP(V6) gateway %s", ip_str);

	if (inet_pton(AF_INET6, ip_str, &addr) == 0)
		rte_panic("Invalid addr from env DPDK_IPV6_GATEWAY: %s", ip_str);

	return &addr;
}

static void
loopback_dst_init(struct glue_ctx *ctx)
{
	struct tle_dest *dst;
	struct ether_hdr *eth;
	struct ipv4_hdr *ip4h;
	struct ipv6_hdr *ip6h;

	/* init ipv4 dst */
	dst = &ctx->lb_dst;
	dst->mtu = 65535;

	dst->l2_len = sizeof(*eth);
	dst->head_mp = get_mempool_by_socket(0); /* fix me */
	eth = (struct ether_hdr *)dst->hdr;
	memset(eth, 0, 2 * sizeof(eth->d_addr));
	eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

	dst->l3_len = sizeof(*ip4h);
	ip4h = (struct ipv4_hdr *)(eth + 1);
	ip4h->dst_addr = htonl(INADDR_LOOPBACK);	/* fixme: loopback is not only for 127.0.0.1 */
	ip4h->version_ihl = 4 << 4 | sizeof(*ip4h) / IPV4_IHL_MULTIPLIER;
	ip4h->time_to_live = 64;
	ip4h->next_proto_id = IPPROTO_TCP;

	/* init ipv6 dst */
	dst = &ctx->lb_dst_v6;
	dst->mtu = 65535;

	dst->l2_len = sizeof(*eth);
	dst->head_mp = get_mempool_by_socket(0); /* fix me */
	eth = (struct ether_hdr *)dst->hdr;
	memset(eth, 0, 2 * sizeof(eth->d_addr));
	eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv6);

	dst->l3_len = sizeof(*ip6h);
	ip6h = (struct ipv6_hdr *)(eth + 1);
	rte_memcpy(ip6h->dst_addr, &in6addr_loopback, sizeof(struct in6_addr));
	ip6h->vtc_flow = 6 << 4;
	ip6h->hop_limits = 255;
	ip6h->proto = IPPROTO_TCP;
}

static void
arp_hash_init(struct glue_ctx *ctx, unsigned socket_id)
{
	char str[RTE_HASH_NAMESIZE];
	struct rte_hash_parameters hprm;

	/* init ipv4 arp hash */
	snprintf(str, sizeof(str), "arp_hash_4@ctx%u", ctx->queue_id);
	memset(&hprm, 0, sizeof(hprm));
	hprm.name = str;
	hprm.entries = MAX_ARP_ENTRY * 2;
	hprm.socket_id = socket_id;
	hprm.key_len = sizeof(struct in_addr);
	ctx->arp_hash = rte_hash_create(&hprm);
	if (ctx->arp_hash == NULL) {
		rte_panic("Failed to init hashtable for ARP");
	}

	/* init ipv6 arp hash */
	snprintf(str, sizeof(str), "arp_hash_6@ctx%u", ctx->queue_id);
	memset(&hprm, 0, sizeof(hprm));
	hprm.name = str;
	hprm.entries = MAX_ARP_ENTRY * 2;
	hprm.socket_id = socket_id;
	hprm.key_len = sizeof(struct in6_addr);
	ctx->arp6_hash = rte_hash_create(&hprm);
	if (ctx->arp6_hash == NULL) {
		rte_panic("Failed to init hashtable for ARP6");
	}
}

static void
arp_timer_init(struct glue_ctx *ctx, unsigned socket_id)
{
	struct tle_timer_wheel_args twprm;

	twprm.tick_size = 1000U;
	twprm.max_timer = MAX_ARP_ENTRY + 8;
	twprm.socket_id = socket_id;
	ctx->arp_tmw = tle_timer_create(&twprm, tcp_get_tms(ctx->cycles_ms_shift));
	if (ctx->arp_tmw == NULL) {
		rte_panic("Failed to init timer wheel for ARP");
	}
}

static void
glue_ctx_init(struct glue_ctx *ctx, uint32_t socket_id)
{
	uint64_t ms;

	ctx->arp4 = rte_zmalloc_socket(NULL,
			sizeof(struct arp_entry) * MAX_ARP_ENTRY,
			RTE_CACHE_LINE_SIZE, socket_id);
	ctx->arp6 = rte_zmalloc_socket(NULL,
			sizeof(struct arp_entry) * MAX_ARP_ENTRY,
			RTE_CACHE_LINE_SIZE, socket_id);
	if (!ctx->arp4 || !ctx->arp6)
		rte_panic("Failed to allocate arp table");

	ctx->port_id = 0;
	ctx->queue_id = nb_ctx - 1;
	ctx->ipv4 = get_ip();
	ctx->ipv4_ml = get_ip_mask();
	ctx->ipv4_gw = get_ip_gate();
	rte_memcpy(&ctx->ipv6, get_ipv6(), sizeof(struct in6_addr));
	ctx->ipv6_ml = get_ipv6_mask();
	rte_memcpy(&ctx->ipv6_gw, get_ipv6_gate(), sizeof(struct in6_addr));

	/* caclulate closest shift to convert from cycles to ms (approximate) */
	ms = (rte_get_tsc_hz() + MS_PER_S - 1) / MS_PER_S;
	ctx->cycles_ms_shift = sizeof(ms) * CHAR_BIT - __builtin_clzll(ms) - 1;

	rte_spinlock_init(&ctx->arp_lock);
	rte_spinlock_init(&ctx->arp6_lock);
	arp_hash_init(ctx, socket_id);
	arp_timer_init(ctx, socket_id);
	ctx->arp_wait = NULL;

	ctx->frag_tbl = rte_ip_frag_table_create(FRAG_BUCKET,
			FRAG_ENTRIES_PER_BUCKET, FRAG_BUCKET * FRAG_ENTRIES_PER_BUCKET,
			rte_get_tsc_hz(), socket_id);
	if (ctx->frag_tbl == NULL)
		rte_panic("Failed to create ip defrag table");

	PERCPU_MIB = &ctx->mib;
}

static int ctx_seq;
static rte_spinlock_t ctx_lock = RTE_SPINLOCK_INITIALIZER;

uint8_t
glue_ctx_alloc(void)
{
	uint32_t socket_id;
	struct glue_ctx *ctx;

	/* fix me: we need a fine grainer lock */
	rte_spinlock_lock(&ctx_lock);

	GLUE_LOG(INFO, "allocate ctx: %d", ctx_seq);
	if (ctx_seq == 0) {
		/* Called from constructor init() */
		ctx_seq = 1;
	} else if (ctx_seq == 1) {
		/* Called from first epoll_create() or poll() */
		ctx_seq = 2;
		ctx = default_ctx;
		goto unlock;
	}

	if (nb_ctx >= MAX_NB_CTX)
		rte_panic("Exceed the max number of ctx");

	ctx = &ctx_array[nb_ctx++];
	GLUE_LOG(INFO, "%u ctx allocated, and will init", nb_ctx);

	socket_id = get_socket_id();

	glue_ctx_init(ctx, socket_id);

	/* reconfigure the "physical" port whenever # of ctx changes */
	port_reconfig();

	if (ctx == default_ctx) {
		loopback_dst_init(ctx);

		ctx->lb_port_id = create_loopback(socket_id);
		GLUE_LOG(INFO, "loopback port_id: %u", ctx->lb_port_id);
	}

	rte_eth_macaddr_get(ctx->port_id, &ctx->mac);

	tle_ctx_init(ctx, socket_id);

unlock:
	rte_spinlock_unlock(&ctx_lock);
	return ctx - ctx_array;
}

void
glue_ctx_free(struct glue_ctx *ctx __rte_unused)
{
	if (nb_ctx == 1 && ctx_seq == 2) {
		GLUE_LOG(INFO, "free ctx");
		ctx_seq = 1;
		return;
	}

	rte_panic("close epoll fd on running is not supported\n");
}

struct glue_ctx *
glue_ctx_lookup(uint16_t port_id, uint16_t queue_id)
{
	int i;

	if (port_id == 1) /* loopback */
		return default_ctx;

	for (i = 0; i < nb_ctx; i++) {
		if (ctx_array[i].port_id == port_id && 
		    ctx_array[i].queue_id == queue_id)
			return &ctx_array[i];
	}

	return NULL;
}

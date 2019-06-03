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

#ifndef _TLE_GLUE_SOCK_H_
#define _TLE_GLUE_SOCK_H_

#include <stdbool.h>
#include <pthread.h>

#include <rte_memzone.h>
#include <rte_mempool.h>
#include <rte_ether.h>
#include <rte_ip_frag.h>

#include <tle_ctx.h>
#include <tle_event.h>
#include <tle_stats.h>

#include <sys/queue.h>

#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

struct arp_entry {
	struct tle_dest dst;
	uint8_t inuse;
	uint8_t req_time;
	void* timer;
};

struct glue_ctx {
	struct tle_ctx *tcp_ctx;
	struct tle_dev *tcp_dev;
	struct tle_dev *lb_tcp_dev;
	struct tle_ctx *udp_ctx;
	struct tle_dev *udp_dev;
	struct tle_dev *lb_udp_dev;

	struct tle_evq *syneq;
	struct tle_evq *ereq;
	struct tle_evq *rxeq;
	struct tle_evq *txeq;

	uint16_t port_id;
	uint16_t queue_id;
	uint16_t lb_port_id;

	struct {
		uint8_t ipv4_ml;
		uint8_t ipv6_ml;
	};

	struct ether_addr mac;
	struct rte_mbuf *arp_wait;
	struct tle_timer_wheel *arp_tmw;
	uint32_t cycles_ms_shift;  /* to convert from cycles to ms */

	struct {
		uint32_t ipv4;
		uint32_t ipv4_gw;

		uint32_t arp4_num;
		rte_spinlock_t arp_lock;
		struct arp_entry *arp4;
		struct rte_hash *arp_hash;
	};

	struct {
		struct in6_addr ipv6;
		struct in6_addr ipv6_gw;

		uint32_t arp6_num;
		rte_spinlock_t arp6_lock;
		struct arp_entry *arp6;
		struct rte_hash *arp6_hash;
	};

	struct {
		rte_spinlock_t frag_lock;
		struct rte_ip_frag_tbl *frag_tbl;
		struct rte_ip_frag_death_row frag_dr;
	};

	struct tle_dest lb_dst;
	struct tle_dest lb_dst_v6;

	struct tle_mib mib;
} __rte_cache_aligned;

extern int nb_ctx;
extern struct glue_ctx *default_ctx;
extern struct glue_ctx ctx_array[MAX_NB_CTX];

RTE_DECLARE_PER_LCORE(struct glue_ctx *, glue_ctx);

static inline struct glue_ctx *
get_ctx(void)
{
	if (RTE_PER_LCORE(glue_ctx))
		return RTE_PER_LCORE(glue_ctx);
	return default_ctx;
}

static inline uint8_t
get_cid(void)
{
	return get_ctx() - ctx_array;
}

uint8_t glue_ctx_alloc(void);

struct glue_ctx * glue_ctx_lookup(uint16_t port_id, uint16_t queue_id);

void glue_ctx_free(struct glue_ctx *ctx);

#define DPDK_IP "DPDK_IP"
#define DPDK_IP_DEF "0.0.0.0"
#define DPDK_IP_MASK "DPDK_IP_MASK"
#define DPDK_IP_MASK_DEF "16"
#define DPDK_IP_GATEWAY "DPDK_IP_GATEWAY"
#define DPDK_IP_GATEWAY_DEF "0.0.0.0"
#define DPDK_IPV6 "DPDK_IPV6"
#define DPDK_IPV6_DEF "::"
#define DPDK_IPV6_MASK "DPDK_IPV6_MASK"
#define DPDK_IPV6_MASK_DEF "64"
#define DPDK_IPV6_GATEWAY "DPDK_IPV6_GATEWAY"
#define DPDK_IPV6_GATEWAY_DEF "::"

#ifdef __cplusplus
}
#endif

#endif /* _TLE_GLUE_SOCK_H_ */

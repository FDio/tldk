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

#ifndef TEST_COMMON_H_
#define TEST_COMMON_H_

#include <netinet/in.h>
#include <netinet/ip6.h>

#include <rte_config.h>
#include <rte_common.h>
#include <rte_errno.h>
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_ethdev.h>
#include <rte_kvargs.h>
#include <rte_errno.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>
#include <rte_hash.h>
#include <rte_ip.h>
#include <rte_ip_frag.h>
#include <rte_udp.h>

#define RX_RING_SIZE 128
#define TX_RING_SIZE 128
#define NUM_MBUFS 4095
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

extern struct rte_mempool *mbuf_pool;
extern struct rte_mempool *frag_mp;

extern char binpath[PATH_MAX];

int port_init(uint8_t port, struct rte_mempool *mbuf_pool);

uint64_t
_mbuf_tx_offload(uint64_t il2, uint64_t il3, uint64_t il4, uint64_t tso,
	uint64_t ol3, uint64_t ol2);

void
fill_pkt_hdr_len(struct rte_mbuf *m, uint32_t l2, uint32_t l3, uint32_t l4);

int
is_ipv4_frag(const struct ipv4_hdr *iph);

void
fill_ipv4_hdr_len(struct rte_mbuf *m, uint32_t l2, uint32_t proto,
	uint32_t frag);

int
ipv6x_hdr(uint32_t proto);

uint16_t
ipv4x_cksum(const void *iph, size_t len);

void
fill_ipv6x_hdr_len(struct rte_mbuf *m, uint32_t l2, uint32_t nproto,
	uint32_t fproto);

void
fill_ipv6_hdr_len(struct rte_mbuf *m, uint32_t l2, uint32_t fproto);

void
fix_reassembled(struct rte_mbuf *m, int32_t hwcsum);

uint32_t
compress_pkt_list(struct rte_mbuf *pkt[], uint32_t nb_pkt, uint32_t nb_zero);

void
fill_eth_hdr_len(struct rte_mbuf *m);

uint16_t
typen_rx_callback(uint8_t port, __rte_unused uint16_t queue,
	struct rte_mbuf *pkt[], uint16_t nb_pkts,
	__rte_unused uint16_t max_pkts, void *user_param);

int
dummy_lookup4(void *opaque, const struct in_addr *addr, struct tle_dest *res);

int
dummy_lookup6(void *opaque, const struct in6_addr *addr, struct tle_dest *res);

#endif /* TEST_COMMON_H_ */

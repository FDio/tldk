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

#ifndef __NETBE_H__
#define __NETBE_H__

#include <stdint.h>
#include <stddef.h>
#include <inttypes.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <assert.h>
#include <signal.h>

#include <rte_config.h>
#include <rte_common.h>
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
#include <tle_udp_impl.h>
#include <tle_event.h>

#define	MAX_PKT_BURST	0x20

/*
 * BE related structures.
 */

struct netbe_port {
	uint32_t id;
	uint32_t lcore;
	uint32_t mtu;
	uint32_t rx_offload;
	uint32_t tx_offload;
	uint32_t ipv4;
	struct in6_addr ipv6;
	struct ether_addr mac;
};

struct netbe_dest {
	uint32_t line;
	uint32_t port;
	uint32_t mtu;
	uint32_t prfx;
	uint16_t family;
	union {
		struct in_addr ipv4;
		struct in6_addr ipv6;
	};
	struct ether_addr mac;
};

struct netbe_dest_prm {
	uint32_t nb_dest;
	struct netbe_dest *dest;
};

struct pkt_buf {
	uint32_t num;
	struct rte_mbuf *pkt[2 * MAX_PKT_BURST];
};

struct netbe_dev {
	uint16_t rxqid;
	uint16_t txqid;
	struct netbe_port port;
	struct tle_udp_dev *dev;
	struct {
		uint64_t in;
		uint64_t up;
		uint64_t drop;
	} rx_stat;
	struct {
		uint64_t down;
		uint64_t out;
		uint64_t drop;
	} tx_stat;
	struct pkt_buf tx_buf;
};

/* 8 bit LPM user data. */
#define	LCORE_MAX_DST	(UINT8_MAX + 1)

struct netbe_lcore {
	uint32_t id;
	struct rte_lpm *lpm4;
	struct rte_lpm6 *lpm6;
	struct rte_ip_frag_tbl *ftbl;
	struct tle_udp_ctx *ctx;
	uint32_t prt_num;
	uint32_t dst4_num;
	uint32_t dst6_num;
	struct netbe_dev prt[RTE_MAX_ETHPORTS];
	struct tle_udp_dest dst4[LCORE_MAX_DST];
	struct tle_udp_dest dst6[LCORE_MAX_DST];
	struct rte_ip_frag_death_row death_row;
};

struct netbe_cfg {
	uint32_t promisc;
	uint32_t prt_num;
	uint32_t cpu_num;
	struct netbe_port prt[RTE_MAX_ETHPORTS];
	struct netbe_lcore cpu[RTE_MAX_LCORE];
};

/*
 * FE related structures.
 */

enum {
	RXONLY,
	TXONLY,
	RXTX,
	FWD,
};

struct netfe_sprm {
	uint32_t bidx;  /* BE index to use. */
	struct tle_udp_stream_param prm;
};

struct netfe_stream_prm {
	uint32_t lcore;
	uint32_t line;
	uint16_t op;
	uint16_t txlen; /* valid/used only for TXONLY op. */
	struct netfe_sprm sprm;
	struct netfe_sprm fprm;  /* valid/used only for FWD op. */
};

struct netfe_lcore_prm {
	uint32_t max_streams;
	uint32_t nb_streams;
	struct netfe_stream_prm *stream;
};

struct netfe_stream {
	struct tle_udp_stream *s;
	struct tle_event *rxev;
	struct tle_event *txev;
	uint16_t op;
	uint16_t family;
	uint16_t txlen;
	struct {
		uint64_t rxp;
		uint64_t txp;
		uint64_t fwp;
		uint64_t drops;
		uint64_t rxev[TLE_SEV_NUM];
		uint64_t txev[TLE_SEV_NUM];
	} stat;
	struct pkt_buf pbuf;
	struct sockaddr_storage raddr;
	struct netfe_sprm fwdprm;
};

struct netfe_lcore {
	uint32_t snum;  /* max number of streams */
	uint32_t sidx;  /* last open stream index */
	struct tle_evq *rxeq;
	struct tle_evq *txeq;
	struct rte_hash *fw4h;
	struct rte_hash *fw6h;
	struct netfe_stream *fs;
};

struct lcore_prm {
	struct {
		struct netbe_lcore *lc;
	} be;
	struct netfe_lcore_prm fe;
};

/*
 * debug/trace macros.
 */

#define	DUMMY_MACRO	do {} while (0)

#ifdef NETFE_DEBUG
#define	NETFE_TRACE(fmt, arg...)	printf(fmt, ##arg)
#define	NETFE_PKT_DUMP(p)		rte_pktmbuf_dump(stdout, (p), 64)
#else
#define	NETFE_TRACE(fmt, arg...)	DUMMY_MACRO
#define	NETFE_PKT_DUMP(p)		DUMMY_MACRO
#endif

#ifdef NETBE_DEBUG
#define	NETBE_TRACE(fmt, arg...)	printf(fmt, ##arg)
#define	NETBE_PKT_DUMP(p)		rte_pktmbuf_dump(stdout, (p), 64)
#else
#define	NETBE_TRACE(fmt, arg...)	DUMMY_MACRO
#define	NETBE_PKT_DUMP(p)		DUMMY_MACRO
#endif

#define FUNC_STAT(v, c) do { \
	static uint64_t nb_call, nb_data; \
	nb_call++; \
	nb_data += (v); \
	if ((nb_call & ((c) - 1)) == 0) { \
		printf("%s#%d@%u: nb_call=%lu, avg(" #v ")=%#Lf\n", \
			__func__, __LINE__, rte_lcore_id(), nb_call, \
			(long double)nb_data / nb_call); \
		nb_call = 0; \
		nb_data = 0; \
	} \
} while (0)

#define FUNC_TM_STAT(v, c) do { \
	static uint64_t nb_call, nb_data; \
	static uint64_t cts, pts, sts; \
	cts = rte_rdtsc(); \
	if (pts != 0) \
		sts += cts - pts; \
	pts = cts; \
	nb_call++; \
	nb_data += (v); \
	if ((nb_call & ((c) - 1)) == 0) { \
		printf("%s#%d@%u: nb_call=%lu, " \
			"avg(" #v ")=%#Lf, " \
			"avg(cycles)=%#Lf, " \
			"avg(cycles/" #v ")=%#Lf\n", \
			__func__, __LINE__, rte_lcore_id(), nb_call, \
			(long double)nb_data / nb_call, \
			(long double)sts / nb_call, \
			(long double)sts / nb_data); \
		nb_call = 0; \
		nb_data = 0; \
		sts = 0; \
	} \
} while (0)

int setup_rx_cb(const struct netbe_port *uprt, struct netbe_lcore *lc);

#endif /* __NETBE_H__ */

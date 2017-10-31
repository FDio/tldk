/*
 * Copyright (c) 2017  Intel Corporation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef __NGX_TLDK_H__
#define __NGX_TLDK_H__

#include <stdint.h>
#include <stddef.h>
#include <inttypes.h>

#include <ngx_config.h>
#include <ngx_core.h>

#include <rte_config.h>
#include <rte_eal.h>
#include <rte_common.h>
#include <rte_ether.h>

#include <tle_ctx.h>
#include <tle_event.h>

#define MAX_PKT_BURST 0x20

#define MAX_PORT_QUEUE		\
	(sizeof(((struct tldk_port_conf *)NULL)->queue_map) * CHAR_BIT)

#define MAX_CTX_PER_LOCRE 32

struct tldk_port_conf {
	uint32_t id;
	uint32_t nb_queues;
	uint32_t queue_map;
	uint32_t mtu;
	uint32_t rx_offload;
	uint32_t tx_offload;
	uint32_t ipv4;
	struct in6_addr ipv6;
	struct ether_addr mac;
};

struct tldk_dev_conf {
	uint32_t id;
	uint32_t port;
	uint32_t queue;
};

struct tldk_dest_conf {
	uint32_t dev;
	uint32_t mtu;
	uint32_t prfx;
	uint16_t family;
	union {
		struct in_addr ipv4;
		struct in6_addr ipv6;
	};
	struct ether_addr mac;
};

#define	TLDK_MAX_DEST	0x10

struct tldk_ctx_conf {
	ngx_uint_t worker;
	uint32_t lcore;
	uint32_t nb_mbuf;
	uint32_t nb_stream;
	uint32_t nb_rbuf;
	uint32_t nb_sbuf;
	uint32_t nb_dev;
	uint32_t nb_dest;
	uint32_t be_in_worker;
	uint32_t tcp_timewait; /* TCP TIME_WAIT value in milliseconds */
	struct tldk_dev_conf dev[RTE_MAX_ETHPORTS];
	struct tldk_dest_conf dest[TLDK_MAX_DEST];
};

typedef struct tldk_conf tldk_conf_t;

struct tldk_conf {
	uint32_t eal_argc;
	char *eal_argv[NGX_CONF_MAX_ARGS];
	char eal_cmd[PATH_MAX];
	uint32_t nb_port;
	struct tldk_port_conf port[RTE_MAX_ETHPORTS];
	uint32_t nb_ctx;
	struct tldk_ctx_conf ctx[RTE_MAX_LCORE];
};

extern char *tldk_block_parse(ngx_conf_t *, ngx_command_t *, void *);
extern char *tldk_ctx_parse(ngx_conf_t *, ngx_command_t *, void *);

struct pkt_buf {
	uint32_t num;
	struct rte_mbuf *pkt[2 * MAX_PKT_BURST];
};

struct tldk_dev {
	struct tle_dev *dev;
	struct tldk_dev_conf cf;
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

#define LCORE_MAX_DST (UINT8_MAX + 1)

struct tldk_ctx {
	const struct tldk_ctx_conf *cf;
	struct rte_lpm *lpm4;
	struct rte_lpm6 *lpm6;
	struct tle_ctx *ctx;
	struct rte_mempool *mpool;
	struct rte_mempool *frag_mpool;
	uint32_t nb_dev;
	struct tldk_dev dev[RTE_MAX_ETHPORTS];
	uint32_t dst4_num;
	uint32_t dst6_num;
	struct tle_dest dst4[LCORE_MAX_DST];
	struct tle_dest dst6[LCORE_MAX_DST];
	struct {
		uint64_t flags[UINT8_MAX + 1];
	} tcp_stat;
} __rte_cache_aligned;

extern struct tldk_ctx wrk2ctx[RTE_MAX_LCORE];

struct lcore_ctxs_list {
	uint32_t nb_ctxs;
	struct tldk_ctx *ctxs[MAX_CTX_PER_LOCRE];
};

/* helper macros */
#define	DUMMY_MACRO	do {} while (0)

#ifdef BE_DEBUG
#define	BE_TRACE(fmt, arg...)	printf(fmt, ##arg)
#define	BE_PKT_DUMP(p)		rte_pktmbuf_dump(stdout, (p), 74)
#else
#define	BE_TRACE(fmt, arg...)	DUMMY_MACRO
#define	BE_PKT_DUMP(p)		DUMMY_MACRO
#endif

#ifdef FE_DEBUG
#define	FE_TRACE(fmt, arg...)	printf(fmt, ##arg)
#define	FE_PKT_DUMP(p)		rte_pktmbuf_dump(stdout, (p), 74)
#else
#define	FE_TRACE(fmt, arg...)	DUMMY_MACRO
#define	FE_PKT_DUMP(p)		DUMMY_MACRO
#endif


#endif /* __NGX_TLDK_H__ */

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

#include <time.h>

#include "netbe.h"
#include "parse.h"

#define	MAX_RULES	0x100
#define	MAX_TBL8	0x800

#define	RX_RING_SIZE	0x400
#define	TX_RING_SIZE	0x800

#define	MPOOL_CACHE_SIZE	0x100
#define	MPOOL_NB_BUF		0x20000

#define FRAG_MBUF_BUF_SIZE	(RTE_PKTMBUF_HEADROOM + TLE_DST_MAX_HDR)
#define FRAG_TTL		MS_PER_S
#define	FRAG_TBL_BUCKET_ENTRIES	16

#define	FIRST_PORT	0x8000

#define RX_CSUM_OFFLOAD	(DEV_RX_OFFLOAD_IPV4_CKSUM | DEV_RX_OFFLOAD_UDP_CKSUM)
#define TX_CSUM_OFFLOAD	(DEV_TX_OFFLOAD_IPV4_CKSUM | DEV_TX_OFFLOAD_UDP_CKSUM)

RTE_DEFINE_PER_LCORE(struct netbe_lcore *, _be);
RTE_DEFINE_PER_LCORE(struct netfe_lcore *, _fe);

#include "fwdtbl.h"

/**
 * Location to be modified to create the IPv4 hash key which helps
 * to distribute packets based on the destination TCP/UDP port.
 */
#define RSS_HASH_KEY_DEST_PORT_LOC_IPV4 15

/**
 * Location to be modified to create the IPv6 hash key which helps
 * to distribute packets based on the destination TCP/UDP port.
 */
#define RSS_HASH_KEY_DEST_PORT_LOC_IPV6 39

/**
 * Size of the rte_eth_rss_reta_entry64 array to update through
 * rte_eth_dev_rss_reta_update.
 */
#define RSS_RETA_CONF_ARRAY_SIZE (ETH_RSS_RETA_SIZE_512/RTE_RETA_GROUP_SIZE)

#define NETBE_REALLOC(loc, n) do { \
	(loc) = rte_realloc((loc), sizeof(*(loc)) * (n), RTE_CACHE_LINE_SIZE); \
	if ((loc) == NULL) { \
		RTE_LOG(ERR, USER1, \
			"%s: failed to reallocate memory\n", \
			__func__); \
		return -ENOMEM; \
	} \
} while (0)

static volatile int force_quit;

static struct netbe_cfg becfg;
static struct rte_mempool *mpool[RTE_MAX_NUMA_NODES + 1];
static struct rte_mempool *frag_mpool[RTE_MAX_NUMA_NODES + 1];
static clock_t time_start, time_end;
static char proto_name[3][10] = {"udp", "tcp", ""};

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.max_rx_pkt_len = ETHER_MAX_VLAN_FRAME_LEN,
		.hw_vlan_strip = 1,
		.jumbo_frame = 1,
	},
};

/* function pointers */
static TLE_RX_BULK_FUNCTYPE tle_rx_bulk;
static TLE_TX_BULK_FUNCTYPE tle_tx_bulk;
static TLE_STREAM_RECV_FUNCTYPE tle_stream_recv;
static TLE_STREAM_CLOSE_FUNCTYPE tle_stream_close;

static LCORE_MAIN_FUNCTYPE lcore_main;

#include "common.h"
#include "parse.h"
#include "lcore.h"
#include "port.h"
#include "tcp.h"
#include "udp.h"

static void
netbe_lcore_fini(struct netbe_cfg *cfg)
{
	uint32_t i;

	for (i = 0; i != cfg->cpu_num; i++) {
		tle_ctx_destroy(cfg->cpu[i].ctx);
		rte_ip_frag_table_destroy(cfg->cpu[i].ftbl);
		rte_lpm_free(cfg->cpu[i].lpm4);
		rte_lpm6_free(cfg->cpu[i].lpm6);

		rte_free(cfg->cpu[i].prtq);
		cfg->cpu[i].prtq_num = 0;
	}

	rte_free(cfg->cpu);
	cfg->cpu_num = 0;
	for (i = 0; i != cfg->prt_num; i++) {
		rte_free(cfg->prt[i].lcore_id);
		cfg->prt[i].nb_lcore = 0;
	}
	rte_free(cfg->prt);
	cfg->prt_num = 0;
}

static int
netbe_dest_init(const char *fname, struct netbe_cfg *cfg)
{
	int32_t rc;
	uint32_t f, i, p;
	uint32_t k, l, cnt;
	struct netbe_lcore *lc;
	struct netbe_dest_prm prm;

	rc = netbe_parse_dest(fname, &prm);
	if (rc != 0)
		return rc;

	rc = 0;
	for (i = 0; i != prm.nb_dest; i++) {

		p = prm.dest[i].port;
		f = prm.dest[i].family;

		cnt = 0;
		for (k = 0; k != cfg->cpu_num; k++) {
			lc = cfg->cpu + k;
			for (l = 0; l != lc->prtq_num; l++)
				if (lc->prtq[l].port.id == p) {
					rc = netbe_add_dest(lc, l, f,
							prm.dest + i, 1);
					if (rc != 0) {
						RTE_LOG(ERR, USER1,
							"%s(lcore=%u, family=%u) could not "
							"add destinations(%u);\n",
							__func__, lc->id, f, i);
						return -ENOSPC;
					}
					cnt++;
				}
		}

		if (cnt == 0) {
			RTE_LOG(ERR, USER1, "%s(%s) error at line %u: "
				"port %u not managed by any lcore;\n",
				__func__, fname, prm.dest[i].line, p);
			break;
		}
	}

	free(prm.dest);
	return rc;
}

static void
func_ptrs_init(uint32_t proto) {
	if (proto == TLE_PROTO_TCP) {
		tle_rx_bulk = tle_tcp_rx_bulk;
		tle_tx_bulk = tle_tcp_tx_bulk;
		tle_stream_recv = tle_tcp_stream_recv;
		tle_stream_close = tle_tcp_stream_close;

		lcore_main = lcore_main_tcp;

	} else {
		tle_rx_bulk = tle_udp_rx_bulk;
		tle_tx_bulk = tle_udp_tx_bulk;
		tle_stream_recv = tle_udp_stream_recv;
		tle_stream_close = tle_udp_stream_close;

		lcore_main = lcore_main_udp;
	}
}

int
main(int argc, char *argv[])
{
	int32_t rc;
	uint32_t i;
	struct tle_ctx_param ctx_prm;
	struct netfe_lcore_prm feprm;
	struct rte_eth_stats stats;
	char fecfg_fname[PATH_MAX + 1];
	char becfg_fname[PATH_MAX + 1];
	struct lcore_prm prm[RTE_MAX_LCORE];
	struct rte_eth_dev_info dev_info;

	fecfg_fname[0] = 0;
	becfg_fname[0] = 0;
	memset(prm, 0, sizeof(prm));

	rc = rte_eal_init(argc, argv);
	if (rc < 0)
		rte_exit(EXIT_FAILURE,
			"%s: rte_eal_init failed with error code: %d\n",
			__func__, rc);

	memset(&ctx_prm, 0, sizeof(ctx_prm));

	signal(SIGINT, sig_handle);

	argc -= rc;
	argv += rc;

	rc = parse_app_options(argc, argv, &becfg, &ctx_prm,
		fecfg_fname, becfg_fname);
	if (rc != 0)
		rte_exit(EXIT_FAILURE,
			"%s: parse_app_options failed with error code: %d\n",
			__func__, rc);

	/* init all the function pointer */
	func_ptrs_init(becfg.proto);

	rc = netbe_port_init(&becfg);
	if (rc != 0)
		rte_exit(EXIT_FAILURE,
			"%s: netbe_port_init failed with error code: %d\n",
			__func__, rc);

	rc = netbe_lcore_init(&becfg, &ctx_prm);
	if (rc != 0)
		sig_handle(SIGQUIT);

	if ((rc = netbe_dest_init(becfg_fname, &becfg)) != 0)
		sig_handle(SIGQUIT);

	for (i = 0; i != becfg.prt_num && rc == 0; i++) {
		RTE_LOG(NOTICE, USER1, "%s: starting port %u\n",
			__func__, becfg.prt[i].id);
		rc = rte_eth_dev_start(becfg.prt[i].id);
		if (rc != 0) {
			RTE_LOG(ERR, USER1,
				"%s: rte_eth_dev_start(%u) returned "
				"error code: %d\n",
				__func__, becfg.prt[i].id, rc);
			sig_handle(SIGQUIT);
		}
		rte_eth_dev_info_get(becfg.prt[i].id, &dev_info);
		rc = update_rss_reta(&becfg.prt[i], &dev_info);
		if (rc != 0)
			sig_handle(SIGQUIT);
	}

	feprm.max_streams = ctx_prm.max_streams * becfg.cpu_num;
	if (rc == 0 &&
		(rc = netfe_parse_cfg(fecfg_fname, &feprm)) != 0)
		sig_handle(SIGQUIT);

	for (i = 0; rc == 0 && i != becfg.cpu_num; i++)
		prm[becfg.cpu[i].id].be.lc = becfg.cpu + i;

	if (rc == 0 && (rc = netfe_lcore_fill(prm, &feprm)) != 0)
		sig_handle(SIGQUIT);

	/* launch all slave lcores. */
	RTE_LCORE_FOREACH_SLAVE(i) {
		if (prm[i].be.lc != NULL || prm[i].fe.max_streams != 0)
			rte_eal_remote_launch(lcore_main, prm + i, i);
	}

	/* launch master lcore. */
	i = rte_get_master_lcore();
	if (prm[i].be.lc != NULL || prm[i].fe.max_streams != 0)
		lcore_main(prm + i);

	rte_eal_mp_wait_lcore();

	for (i = 0; i != becfg.prt_num; i++) {
		RTE_LOG(NOTICE, USER1, "%s: stoping port %u\n",
			__func__, becfg.prt[i].id);
		rte_eth_stats_get(becfg.prt[i].id, &stats);
		RTE_LOG(NOTICE, USER1, "port %u stats={\n"
			"ipackets=%" PRIu64 ";"
			"ibytes=%" PRIu64 ";"
			"ierrors=%" PRIu64 ";\n"
			"opackets=%" PRIu64 ";"
			"obytes=%" PRIu64 ";"
			"oerrors=%" PRIu64 ";\n"
			"}\n",
			becfg.prt[i].id,
			stats.ipackets,
			stats.ibytes,
			stats.ierrors,
			stats.opackets,
			stats.obytes,
			stats.oerrors);
		rte_eth_dev_stop(becfg.prt[i].id);
	}

	netbe_lcore_fini(&becfg);

	return 0;
}

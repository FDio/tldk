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
#include "parse.h"

#define	MAX_RULES	0x100
#define	MAX_TBL8	0x800

#define	RX_RING_SIZE	0x400
#define	TX_RING_SIZE	0x800

#define	MPOOL_CACHE_SIZE	0x100
#define	MPOOL_NB_BUF		0x20000

#define FRAG_MBUF_BUF_SIZE	(RTE_PKTMBUF_HEADROOM + TLE_UDP_MAX_HDR)
#define FRAG_TTL		MS_PER_S
#define	FRAG_TBL_BUCKET_ENTRIES	16

#define	FIRST_PORT	0x8000

#define RX_CSUM_OFFLOAD	(DEV_RX_OFFLOAD_IPV4_CKSUM | DEV_RX_OFFLOAD_UDP_CKSUM)
#define TX_CSUM_OFFLOAD	(DEV_TX_OFFLOAD_IPV4_CKSUM | DEV_TX_OFFLOAD_UDP_CKSUM)

#define	OPT_SHORT_SBULK		'B'
#define	OPT_LONG_SBULK		"sburst"

#define	OPT_SHORT_PROMISC	'P'
#define	OPT_LONG_PROMISC	"promisc"

#define	OPT_SHORT_RBUFS	'R'
#define	OPT_LONG_RBUFS	"rbufs"

#define	OPT_SHORT_SBUFS	'S'
#define	OPT_LONG_SBUFS	"sbufs"

#define	OPT_SHORT_STREAMS	's'
#define	OPT_LONG_STREAMS	"streams"

#define	OPT_SHORT_FECFG	'f'
#define	OPT_LONG_FECFG	"fecfg"

#define	OPT_SHORT_BECFG	'b'
#define	OPT_LONG_BECFG	"becfg"

RTE_DEFINE_PER_LCORE(struct netbe_lcore *, _be);
RTE_DEFINE_PER_LCORE(struct netfe_lcore *, _fe);

#include "fwdtbl.h"

static const struct option long_opt[] = {
	{OPT_LONG_BECFG, 1, 0, OPT_SHORT_BECFG},
	{OPT_LONG_FECFG, 1, 0, OPT_SHORT_FECFG},
	{OPT_LONG_PROMISC, 0, 0, OPT_SHORT_PROMISC},
	{OPT_LONG_RBUFS, 1, 0, OPT_SHORT_RBUFS},
	{OPT_LONG_SBUFS, 1, 0, OPT_SHORT_SBUFS},
	{OPT_LONG_SBULK, 1, 0, OPT_SHORT_SBULK},
	{OPT_LONG_STREAMS, 1, 0, OPT_SHORT_STREAMS},
	{NULL, 0, 0, 0}
};

static volatile int force_quit;

static struct netbe_cfg becfg;
static struct rte_mempool *mpool[RTE_MAX_NUMA_NODES + 1];
static struct rte_mempool *frag_mpool[RTE_MAX_NUMA_NODES + 1];

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.max_rx_pkt_len = ETHER_MAX_VLAN_FRAME_LEN,
		.hw_vlan_strip = 1,
		.jumbo_frame = 1,
	},
};

#include "parse.h"

static void
sig_handle(int signum)
{
	RTE_LOG(ERR, USER1, "%s(%d)\n", __func__, signum);
	force_quit = 1;
}

/*
 * Initilise DPDK port.
 * In current version, only one queue per port is used.
 */
static int
port_init(struct netbe_port *uprt, struct rte_mempool *mp)
{
	int32_t socket, rc;
	uint16_t q;
	struct rte_eth_conf port_conf;
	struct rte_eth_dev_info dev_info;

	const uint16_t rx_rings = 1, tx_rings = 1;

	rte_eth_dev_info_get(uprt->id, &dev_info);
	if ((dev_info.rx_offload_capa & uprt->rx_offload) != uprt->rx_offload) {
		RTE_LOG(ERR, USER1,
			"port#%u supported/requested RX offloads don't match, "
			"supported: %#x, requested: %#x;\n",
			uprt->id, dev_info.rx_offload_capa, uprt->rx_offload);
		return -EINVAL;
	}
	if ((dev_info.tx_offload_capa & uprt->tx_offload) != uprt->tx_offload) {
		RTE_LOG(ERR, USER1,
			"port#%u supported/requested TX offloads don't match, "
			"supported: %#x, requested: %#x;\n",
			uprt->id, dev_info.tx_offload_capa, uprt->tx_offload);
		return -EINVAL;
	}

	port_conf = port_conf_default;
	if ((uprt->rx_offload & RX_CSUM_OFFLOAD) != 0) {
		RTE_LOG(ERR, USER1, "%s(%u): enabling RX csum offload;\n",
			__func__, uprt->id);
		port_conf.rxmode.hw_ip_checksum = 1;
	}

	port_conf.rxmode.max_rx_pkt_len = uprt->mtu + ETHER_CRC_LEN;

	rc = rte_eth_dev_configure(uprt->id, rx_rings, tx_rings, &port_conf);
	RTE_LOG(NOTICE, USER1,
		"%s: rte_eth_dev_configure(%u) returns %d;\n",
		__func__, uprt->id, rc);
	if (rc != 0)
		return rc;

	socket = rte_eth_dev_socket_id(uprt->id);

	dev_info.default_rxconf.rx_drop_en = 1;

	dev_info.default_txconf.tx_free_thresh = TX_RING_SIZE / 2;
	if (uprt->tx_offload != 0) {
		RTE_LOG(ERR, USER1, "%s(%u): enabling full featured TX;\n",
			__func__, uprt->id);
		dev_info.default_txconf.txq_flags = 0;
	}

	for (q = 0; q < rx_rings; q++) {
		rc = rte_eth_rx_queue_setup(uprt->id, q, RX_RING_SIZE,
			socket, NULL, mp);
		if (rc < 0)
			return rc;
	}

	for (q = 0; q < tx_rings; q++) {
		rc = rte_eth_tx_queue_setup(uprt->id, q, TX_RING_SIZE,
			socket, &dev_info.default_txconf);
		if (rc < 0)
			return rc;
	}


	return 0;
}

/*
 * Check that lcore is enabled, not master, and not in use already.
 */
static int
check_lcore(uint32_t lc)
{
	if (rte_lcore_is_enabled(lc) == 0) {
		RTE_LOG(ERR, USER1, "lcore %u is not enabled\n", lc);
		return -EINVAL;
	}
	if (rte_eal_get_lcore_state(lc) == RUNNING) {
		RTE_LOG(ERR, USER1, "lcore %u already running %p\n",
			lc, lcore_config[lc].f);
		return -EINVAL;
	}
	return 0;
}

static void
log_netbe_prt(const struct netbe_port *uprt)
{
	RTE_LOG(NOTICE, USER1,
		"uprt %p = <id = %u, lcore = %u, "
		"mtu = %u, rx_offload = %u, tx_offload = %u,\n"
		"ipv4 = %#x, "
		"ipv6 = %04hx:%04hx:%04hx:%04hx:%04hx:%04hx:%04hx:%04hx, "
		"mac = %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx>;\n",
		uprt, uprt->id, uprt->lcore,
		uprt->mtu, uprt->rx_offload, uprt->tx_offload,
		uprt->ipv4,
		uprt->ipv6.s6_addr16[0], uprt->ipv6.s6_addr16[1],
		uprt->ipv6.s6_addr16[2], uprt->ipv6.s6_addr16[3],
		uprt->ipv6.s6_addr16[4], uprt->ipv6.s6_addr16[5],
		uprt->ipv6.s6_addr16[6], uprt->ipv6.s6_addr16[7],
		uprt->mac.addr_bytes[0], uprt->mac.addr_bytes[1],
		uprt->mac.addr_bytes[2], uprt->mac.addr_bytes[3],
		uprt->mac.addr_bytes[4], uprt->mac.addr_bytes[5]);
}

static void
log_netbe_cfg(const struct netbe_cfg *ucfg)
{
	uint32_t i;

	RTE_LOG(NOTICE, USER1,
		"ucfg @ %p, prt_num = %u\n", ucfg, ucfg->prt_num);

	for (i = 0; i != ucfg->prt_num; i++)
		log_netbe_prt(ucfg->prt + i);
}

static int
pool_init(uint32_t sid)
{
	int32_t rc;
	struct rte_mempool *mp;
	char name[RTE_MEMPOOL_NAMESIZE];

	snprintf(name, sizeof(name), "MP%u", sid);
	mp = rte_pktmbuf_pool_create(name, MPOOL_NB_BUF, MPOOL_CACHE_SIZE, 0,
		RTE_MBUF_DEFAULT_BUF_SIZE, sid - 1);
	if (mp == NULL) {
		rc = -rte_errno;
		RTE_LOG(ERR, USER1, "%s(%d) failed with error code: %d\n",
			__func__, sid - 1, rc);
		return rc;
	}

	mpool[sid] = mp;
	return 0;
}

static int
frag_pool_init(uint32_t sid)
{
	int32_t rc;
	struct rte_mempool *frag_mp;
	char frag_name[RTE_MEMPOOL_NAMESIZE];

	snprintf(frag_name, sizeof(frag_name), "frag_MP%u", sid);
	frag_mp = rte_pktmbuf_pool_create(frag_name, MPOOL_NB_BUF,
		MPOOL_CACHE_SIZE, 0, FRAG_MBUF_BUF_SIZE, sid - 1);
	if (frag_mp == NULL) {
		rc = -rte_errno;
		RTE_LOG(ERR, USER1, "%s(%d) failed with error code: %d\n",
			__func__, sid - 1, rc);
		return rc;
	}

	frag_mpool[sid] = frag_mp;
	return 0;
}


/*
 * Setup all enabled ports.
 */
static void
netbe_port_init(struct netbe_cfg *cfg, int argc, char *argv[])
{
	int32_t rc;
	uint32_t i, n, sid;

	n = RTE_MIN(RTE_DIM(cfg->prt), (uint32_t)argc);

	rc = 0;
	for (i = 0; i != n; i++) {
		rc = parse_netbe_arg(cfg->prt + i, argv[i]);
		if (rc != 0)
			break;

		rc = check_lcore(cfg->prt[i].lcore);
		if (rc != 0)
			break;

		sid = rte_lcore_to_socket_id(cfg->prt[i].lcore) + 1;
		assert(sid < RTE_DIM(mpool));

		if (mpool[sid] == NULL && (rc = pool_init(sid)) != 0)
			break;

		if (frag_mpool[sid] == NULL && (rc = frag_pool_init(sid)) != 0)
			break;

		rc = port_init(cfg->prt + i, mpool[sid]);
		if (rc != 0)
			break;

		rte_eth_macaddr_get(cfg->prt[i].id, &cfg->prt[i].mac);
		if (cfg->promisc)
			rte_eth_promiscuous_enable(cfg->prt[i].id);
	}

	if (rc != 0)
		rte_exit(EXIT_FAILURE,
			"%s: processing of \"%s\" failed with error code: %d\n",
			__func__, argv[i], rc);

	cfg->prt_num = i;
	log_netbe_cfg(cfg);
}

/*
 * UDP IPv4 destination lookup callback.
 */
static int
lpm4_dst_lookup(void *data, const struct in_addr *addr,
	struct tle_udp_dest *res)
{
	int32_t rc;
	uint32_t idx;
	struct netbe_lcore *lc;
	struct tle_udp_dest *dst;

	lc = data;

	rc = rte_lpm_lookup(lc->lpm4, rte_be_to_cpu_32(addr->s_addr), &idx);
	if (rc == 0) {
		dst = &lc->dst4[idx];
		rte_memcpy(res, dst, dst->l2_len + dst->l3_len +
			offsetof(struct tle_udp_dest, hdr));
	}
	return rc;
}

/*
 * UDP IPv6 destination lookup callback.
 */
static int
lpm6_dst_lookup(void *data, const struct in6_addr *addr,
	struct tle_udp_dest *res)
{
	int32_t rc;
	uint8_t idx;
	struct netbe_lcore *lc;
	struct tle_udp_dest *dst;
	uintptr_t p;

	lc = data;
	p = (uintptr_t)addr->s6_addr;

	rc = rte_lpm6_lookup(lc->lpm6, (uint8_t *)p, &idx);
	if (rc == 0) {
		dst = &lc->dst6[idx];
		rte_memcpy(res, dst, dst->l2_len + dst->l3_len +
			offsetof(struct tle_udp_dest, hdr));
	}
	return rc;
}

static int
netbe_add_ipv4_route(struct netbe_lcore *lc, const struct netbe_dest *dst,
	uint8_t idx)
{
	int32_t rc;
	uint32_t addr, depth;
	char str[INET_ADDRSTRLEN];

	depth = dst->prfx;
	addr = rte_be_to_cpu_32(dst->ipv4.s_addr);

	inet_ntop(AF_INET, &dst->ipv4, str, sizeof(str));
	rc = rte_lpm_add(lc->lpm4, addr, depth, idx);
	RTE_LOG(NOTICE, USER1, "%s(lcore=%u,port=%u,dev=%p,"
		"ipv4=%s/%u,mtu=%u,"
		"mac=%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx) "
		"returns %d;\n",
		__func__, lc->id, dst->port, lc->dst4[idx].dev,
		str, depth, lc->dst4[idx].mtu,
		dst->mac.addr_bytes[0], dst->mac.addr_bytes[1],
		dst->mac.addr_bytes[2], dst->mac.addr_bytes[3],
		dst->mac.addr_bytes[4], dst->mac.addr_bytes[5],
		rc);
	return rc;
}

static int
netbe_add_ipv6_route(struct netbe_lcore *lc, const struct netbe_dest *dst,
	uint8_t idx)
{
	int32_t rc;
	uint32_t depth;
	char str[INET6_ADDRSTRLEN];

	depth = dst->prfx;

	rc = rte_lpm6_add(lc->lpm6, (uint8_t *)(uintptr_t)dst->ipv6.s6_addr,
		depth, idx);

	inet_ntop(AF_INET6, &dst->ipv6, str, sizeof(str));
	RTE_LOG(NOTICE, USER1, "%s(lcore=%u,port=%u,dev=%p,"
		"ipv6=%s/%u,mtu=%u,"
		"mac=%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx) "
		"returns %d;\n",
		__func__, lc->id, dst->port, lc->dst6[idx].dev,
		str, depth, lc->dst4[idx].mtu,
		dst->mac.addr_bytes[0], dst->mac.addr_bytes[1],
		dst->mac.addr_bytes[2], dst->mac.addr_bytes[3],
		dst->mac.addr_bytes[4], dst->mac.addr_bytes[5],
		rc);
	return rc;
}

static int
lcore_lpm_init(struct netbe_lcore *lc)
{
	int32_t sid;
	char str[RTE_LPM_NAMESIZE];
	const struct rte_lpm_config lpm4_cfg = {
		.max_rules = MAX_RULES,
		.number_tbl8s = MAX_TBL8,
	};
	const struct rte_lpm6_config lpm6_cfg = {
		.max_rules = MAX_RULES,
		.number_tbl8s = MAX_TBL8,
	};

	sid = rte_lcore_to_socket_id(lc->id);

	snprintf(str, sizeof(str), "LPM4%u\n", lc->id);
	lc->lpm4 = rte_lpm_create(str, sid, &lpm4_cfg);
	RTE_LOG(NOTICE, USER1, "%s(lcore=%u): lpm4=%p;\n",
		__func__, lc->id, lc->lpm4);
	if (lc->lpm4 == NULL)
		return -ENOMEM;

	snprintf(str, sizeof(str), "LPM6%u\n", lc->id);
	lc->lpm6 = rte_lpm6_create(str, sid, &lpm6_cfg);
	RTE_LOG(NOTICE, USER1, "%s(lcore=%u): lpm6=%p;\n",
		__func__, lc->id, lc->lpm6);
	if (lc->lpm6 == NULL)
		return -ENOMEM;

	return 0;
}

static void
fill_dst(struct tle_udp_dest *dst, struct netbe_dev *bed,
	const struct netbe_dest *bdp, uint16_t l3_type, int32_t sid)
{
	struct ether_hdr *eth;
	struct ipv4_hdr *ip4h;
	struct ipv6_hdr *ip6h;

	static const struct ipv4_hdr ipv4_tmpl = {
		.version_ihl =  4 << 4 | sizeof(*ip4h) / IPV4_IHL_MULTIPLIER,
		.time_to_live = 64,
		.next_proto_id = IPPROTO_UDP,
	};

	static const struct ipv6_hdr ipv6_tmpl = {
		.vtc_flow = 6 << 4,
		.proto = IPPROTO_UDP,
		.hop_limits = 64,
	};

	dst->dev = bed->dev;
	dst->head_mp = frag_mpool[sid + 1];
	dst->mtu = RTE_MIN(bdp->mtu, bed->port.mtu);
	dst->l2_len = sizeof(*eth);

	eth = (struct ether_hdr *)dst->hdr;

	ether_addr_copy(&bed->port.mac, &eth->s_addr);
	ether_addr_copy(&bdp->mac, &eth->d_addr);
	eth->ether_type = rte_cpu_to_be_16(l3_type);

	if (l3_type == ETHER_TYPE_IPv4) {
		dst->l3_len = sizeof(*ip4h);
		ip4h = (struct ipv4_hdr *)(eth + 1);
		ip4h[0] = ipv4_tmpl;
	} else if (l3_type == ETHER_TYPE_IPv6) {
		dst->l3_len = sizeof(*ip6h);
		ip6h = (struct ipv6_hdr *)(eth + 1);
		ip6h[0] = ipv6_tmpl;
	}
}


/*
 * BE lcore setup routine.
 */
static int
lcore_init(struct netbe_lcore *lc, const struct tle_udp_ctx_param *ctx_prm,
	const struct netbe_port prt[], uint32_t prt_num)
{
	int32_t rc, sid;
	uint32_t i;
	uint64_t frag_cycles;
	struct tle_udp_ctx_param cprm;
	struct tle_udp_dev_param dprm;

	lc->id = prt[0].lcore;
	lc->prt_num = prt_num;

	sid = rte_lcore_to_socket_id(lc->id);

	rc = lcore_lpm_init(lc);
	if (rc != 0)
		return rc;

	cprm = *ctx_prm;
	cprm.socket_id = sid;
	cprm.lookup4 = lpm4_dst_lookup;
	cprm.lookup4_data = lc;
	cprm.lookup6 = lpm6_dst_lookup;
	cprm.lookup6_data = lc;

	/* to facilitate both IPv4 and IPv6. */
	cprm.max_streams *= 2;

	frag_cycles = (rte_get_tsc_hz() + MS_PER_S - 1) / MS_PER_S * FRAG_TTL;
	lc->ftbl = rte_ip_frag_table_create(cprm.max_streams,
		FRAG_TBL_BUCKET_ENTRIES, cprm.max_streams, frag_cycles, sid);
	RTE_LOG(NOTICE, USER1, "%s(lcore=%u): frag_tbl=%p;\n",
		__func__, lc->id, lc->ftbl);

	lc->ctx = tle_udp_create(&cprm);
	RTE_LOG(NOTICE, USER1, "%s(lcore=%u): udp_ctx=%p;\n",
		__func__, lc->id, lc->ctx);

	if (lc->ctx == NULL || lc->ftbl == NULL)
		rc = ENOMEM;

	for (i = 0; i != prt_num && rc == 0; i++) {

		memset(&dprm, 0, sizeof(dprm));

		lc->prt[i].rxqid = 0;
		lc->prt[i].txqid = 0;
		lc->prt[i].port = prt[i];

		dprm.rx_offload = prt[i].rx_offload;
		dprm.tx_offload = prt[i].tx_offload;
		dprm.local_addr4.s_addr = prt[i].ipv4;
		memcpy(&dprm.local_addr6,  &prt[i].ipv6, sizeof(prt[i].ipv6));

		lc->prt[i].dev = tle_udp_add_dev(lc->ctx, &dprm);
		RTE_LOG(NOTICE, USER1, "%s(lcore=%u, port=%u), udp_dev: %p;\n",
			__func__, lc->id, prt[i].id, lc->prt[i].dev);
		if (lc->prt[i].dev == NULL)
			rc = -rte_errno;
	}

	if (rc != 0) {
		RTE_LOG(ERR, USER1, "%s(lcore=%u) failed with error code: %d\n",
			__func__, lc->id, rc);
		tle_udp_destroy(lc->ctx);
		rte_ip_frag_table_destroy(lc->ftbl);
		rte_lpm_free(lc->lpm4);
		rte_lpm6_free(lc->lpm6);
	}

	return rc;
}

static int
prt_lcore_cmp(const void *s1, const void *s2)
{
	const struct netbe_port *p1, *p2;

	p1 = s1;
	p2 = s2;
	return p1->lcore - p2->lcore;
}

static void
netbe_lcore_init(struct netbe_cfg *cfg, const struct tle_udp_ctx_param *ctx_prm)
{
	int32_t rc;
	uint32_t i, k, n, num;
	struct netbe_port sp[RTE_DIM(cfg->prt)];

	num = cfg->prt_num;
	memcpy(sp, cfg->prt, sizeof(sp[0]) * num);
	qsort(sp, num, sizeof(sp[0]), prt_lcore_cmp);

	/* Fill ports to be used by each lcore. */

	k = 0;
	n = 0;
	rc = 0;
	for (i = 0; i != num && rc == 0; i++) {
		if (sp[n].lcore != sp[i].lcore) {
			rc = lcore_init(cfg->cpu + k, ctx_prm, sp + n, i - n);
			n = i;
			k++;
		}
	}

	if (rc == 0 && i != n) {
		rc = lcore_init(cfg->cpu + k, ctx_prm, sp + n, i - n);
		k++;
	}

	if (rc != 0)
		rte_exit(EXIT_FAILURE, "%s: failed with error code: %d\n",
			__func__, rc);

	cfg->cpu_num = k;
}

static void
netbe_lcore_fini(struct netbe_cfg *cfg)
{
	uint32_t i;

	for (i = 0; i != cfg->cpu_num; i++) {
		tle_udp_destroy(cfg->cpu[i].ctx);
		rte_ip_frag_table_destroy(cfg->cpu[i].ftbl);
		rte_lpm_free(cfg->cpu[i].lpm4);
		rte_lpm6_free(cfg->cpu[i].lpm6);
	}

	memset(cfg->cpu, 0, sizeof(cfg->cpu));
	cfg->cpu_num = 0;
}

static int
netbe_add_dest(struct netbe_lcore *lc, uint32_t dev_idx, uint16_t family,
	const struct netbe_dest *dst, uint32_t dnum)
{
	int32_t rc, sid;
	uint16_t l3_type;
	uint32_t i, n, m;
	struct tle_udp_dest *dp;

	if (family == AF_INET) {
		n = lc->dst4_num;
		dp = lc->dst4 + n;
		m = RTE_DIM(lc->dst4);
		l3_type = ETHER_TYPE_IPv4;
	} else {
		n = lc->dst6_num;
		dp = lc->dst6 + n;
		m = RTE_DIM(lc->dst6);
		l3_type = ETHER_TYPE_IPv6;
	}

	if (n + dnum >= m) {
		RTE_LOG(ERR, USER1, "%s(lcore=%u, family=%hu, dnum=%u) exceeds "
			"maximum allowed number of destinations(%u);\n",
			__func__, lc->id, family, dnum, m);
		return -ENOSPC;
	}

	sid = rte_lcore_to_socket_id(lc->id);
	rc = 0;

	for (i = 0; i != dnum && rc == 0; i++) {
		fill_dst(dp + i, lc->prt + dev_idx, dst + i, l3_type, sid);
		if (family == AF_INET)
			rc = netbe_add_ipv4_route(lc, dst + i, n + i);
		else
			rc = netbe_add_ipv6_route(lc, dst + i, n + i);
	}

	if (family == AF_INET)
		lc->dst4_num = n + i;
	else
		lc->dst6_num = n + i;

	return rc;
}

static int
netbe_port2lcore(struct netbe_cfg *cfg, uint32_t port, struct netbe_lcore **plc)
{
	uint32_t i, j;
	struct netbe_lcore *lc;

	for (i = 0; i != cfg->cpu_num; i++) {
		lc = cfg->cpu + i;
		for (j = 0; j != cfg->prt_num; j++) {
			if (lc->prt[j].port.id == port) {
				*plc = lc;
				return j;
			}
		}
	}

	return -ENOENT;
}

static int
netbe_dest_cmp(const void *s1, const void *s2)
{
	const struct netbe_dest *p1, *p2;

	p1 = s1;
	p2 = s2;
	if (p1->port == p2->port)
		return p1->family - p2->family;
	else
		return p1->port - p2->port;
}

static int
netbe_dest_init(const char *fname, struct netbe_cfg *cfg)
{
	int32_t rc;
	uint32_t f, i, j, p;
	struct netbe_lcore *lc;
	struct netbe_dest_prm prm;

	rc = netbe_parse_dest(fname, &prm);
	if (rc != 0)
		return rc;

	qsort(prm.dest, prm.nb_dest, sizeof(prm.dest[0]), netbe_dest_cmp);

	rc = 0;
	for (i = 0; i != prm.nb_dest; i = j) {

		p = prm.dest[i].port;
		f = prm.dest[i].family;
		for (j = i + 1; j != prm.nb_dest && p == prm.dest[j].port &&
				f == prm.dest[j].family;
				j++)
			;

		rc = netbe_port2lcore(cfg, p, &lc);
		if (rc < 0) {
			RTE_LOG(ERR, USER1, "%s(%s) error at line %u: "
				"port %u not managed by any lcore;\n",
				__func__, fname, prm.dest[i].line, p);
			break;
		}

		rc = netbe_add_dest(lc, rc, f, prm.dest + i, j - i);
		if (rc != 0)
			break;
	}

	free(prm.dest);
	return rc;
}

static void
netfe_stream_close(struct netfe_lcore *fe, uint32_t dec)
{
	uint32_t sidx;

	fe->sidx -= dec;
	sidx = fe->sidx;
	tle_event_free(fe->fs[sidx].txev);
	tle_event_free(fe->fs[sidx].rxev);
	tle_udp_stream_close(fe->fs[sidx].s);
	memset(&fe->fs[sidx], 0, sizeof(fe->fs[sidx]));
}

static void
netfe_stream_dump(const struct netfe_stream *fes)
{
	struct sockaddr_in *l4, *r4;
	struct sockaddr_in6 *l6, *r6;
	uint16_t lport, rport;
	struct tle_udp_stream_param sprm;
	char laddr[INET6_ADDRSTRLEN];
	char raddr[INET6_ADDRSTRLEN];

	tle_udp_stream_get_param(fes->s, &sprm);

	if (sprm.local_addr.ss_family == AF_INET) {

		l4 = (struct sockaddr_in *)&sprm.local_addr;
		r4 = (struct sockaddr_in *)&sprm.remote_addr;

		lport = l4->sin_port;
		rport = r4->sin_port;

	} else if (sprm.local_addr.ss_family == AF_INET6) {

		l6 = (struct sockaddr_in6 *)&sprm.local_addr;
		r6 = (struct sockaddr_in6 *)&sprm.remote_addr;

		lport = l6->sin6_port;
		rport = r6->sin6_port;

	} else {
		RTE_LOG(ERR, USER1, "stream@%p - unknown family=%hu\n",
			fes->s, sprm.local_addr.ss_family);
		return;
	}

	format_addr(&sprm.local_addr, laddr, sizeof(laddr));
	format_addr(&sprm.remote_addr, raddr, sizeof(raddr));

	RTE_LOG(INFO, USER1,
		"stream@%p={"
		"family=%hu,laddr=%s,lport=%hu,raddr=%s,rport=%hu,"
		"stats={"
		"rxp=%" PRIu64 ",txp=%" PRIu64 ",drops=%" PRIu64 ","
		"rxev[IDLE, DOWN, UP]=[%" PRIu64 ", %" PRIu64 ", %" PRIu64 "],"
		"txev[IDLE, DOWN, UP]=[%" PRIu64 ", %" PRIu64 ", %" PRIu64 "],"
		"}};\n",
		fes->s,
		sprm.local_addr.ss_family,
		laddr, ntohs(lport), raddr, ntohs(rport),
		fes->stat.rxp, fes->stat.txp, fes->stat.drops,
		fes->stat.rxev[TLE_SEV_IDLE],
		fes->stat.rxev[TLE_SEV_DOWN],
		fes->stat.rxev[TLE_SEV_UP],
		fes->stat.txev[TLE_SEV_IDLE],
		fes->stat.txev[TLE_SEV_DOWN],
		fes->stat.txev[TLE_SEV_UP]);
}


/*
 * helper function: opens IPv4 and IPv6 streams for selected port.
 */
static struct netfe_stream *
netfe_stream_open(struct netfe_lcore *fe, struct tle_udp_stream_param *sprm,
	uint32_t lcore, uint16_t op, uint32_t bidx)
{
	int32_t rc;
	uint32_t sidx;
	struct netfe_stream *fes;

	sidx = fe->sidx;
	fes = fe->fs + sidx;
	if (sidx >= fe->snum) {
		rte_errno = ENOBUFS;
		return NULL;
	}

	fes->rxev = tle_event_alloc(fe->rxeq, &fe->fs[sidx]);
	fes->txev = tle_event_alloc(fe->txeq, &fe->fs[sidx]);
	sprm->recv_ev = fes->rxev;
	if (op != FWD)
		sprm->send_ev = fes->txev;

	RTE_LOG(ERR, USER1, "%s(%u) [%u]={op=%hu, rxev=%p, txev=%p}\n",
		__func__, lcore, sidx, op, fes->rxev, fes->txev);
	if (fes->rxev == NULL || fes->txev == NULL) {
		netfe_stream_close(fe, 0);
		rte_errno = ENOMEM;
		return NULL;
	}

	if (op == TXONLY || op == FWD) {
		tle_event_active(fes->txev, TLE_SEV_DOWN);
		fes->stat.txev[TLE_SEV_DOWN]++;
	}

	if (op != TXONLY) {
		tle_event_active(fes->rxev, TLE_SEV_DOWN);
		fes->stat.rxev[TLE_SEV_DOWN]++;
	}

	fes->s = tle_udp_stream_open(becfg.cpu[bidx].ctx, sprm);
	if (fes->s == NULL) {
		rc = rte_errno;
		netfe_stream_close(fe, 0);
		rte_errno = rc;
		return NULL;
	}

	fes->op = op;
	fes->family = sprm->local_addr.ss_family;

	fe->sidx = sidx + 1;
	return fes;

}

static inline int
netfe_addr_eq(struct sockaddr_storage *l, struct sockaddr_storage *r,
	uint16_t family)
{
	struct sockaddr_in *l4, *r4;
	struct sockaddr_in6 *l6, *r6;

	if (family == AF_INET) {
		l4 = (struct sockaddr_in *)l;
		r4 = (struct sockaddr_in *)r;
		return (l4->sin_port == r4->sin_port &&
				l4->sin_addr.s_addr == r4->sin_addr.s_addr);
	} else {
		l6 = (struct sockaddr_in6 *)l;
		r6 = (struct sockaddr_in6 *)r;
		return (l6->sin6_port == r6->sin6_port &&
				memcmp(&l6->sin6_addr, &r6->sin6_addr,
				sizeof(l6->sin6_addr)));
	}
}

static inline void
netfe_pkt_addr(const struct rte_mbuf *m, struct sockaddr_storage *ps,
	uint16_t family)
{
	const struct ipv4_hdr *ip4h;
	const struct ipv6_hdr *ip6h;
	const struct udp_hdr *udph;
	struct sockaddr_in *in4;
	struct sockaddr_in6 *in6;

	NETFE_PKT_DUMP(m);

	udph = rte_pktmbuf_mtod_offset(m, struct udp_hdr *, -m->l4_len);

	if (family == AF_INET) {
		in4 = (struct sockaddr_in *)ps;
		ip4h = rte_pktmbuf_mtod_offset(m, struct ipv4_hdr *,
			-(m->l4_len + m->l3_len));
		in4->sin_port = udph->src_port;
		in4->sin_addr.s_addr = ip4h->src_addr;
	} else {
		in6 = (struct sockaddr_in6 *)ps;
		ip6h = rte_pktmbuf_mtod_offset(m, struct ipv6_hdr *,
			-(m->l4_len + m->l3_len));
		in6->sin6_port = udph->src_port;
		rte_memcpy(&in6->sin6_addr, ip6h->src_addr,
			sizeof(in6->sin6_addr));
	}
}

static inline uint32_t
pkt_eq_addr(struct rte_mbuf *pkt[], uint32_t num, uint16_t family,
	struct sockaddr_storage *cur, struct sockaddr_storage *nxt)
{
	uint32_t i;

	for (i = 0; i != num; i++) {
		netfe_pkt_addr(pkt[i], nxt, family);
		if (netfe_addr_eq(cur, nxt, family) == 0)
			break;
	}

	return i;
}

static inline void
pkt_buf_empty(struct pkt_buf *pb)
{
	uint32_t i;

	for (i = 0; i != pb->num; i++)
		rte_pktmbuf_free(pb->pkt[i]);

	pb->num = 0;
}

static inline void
pkt_buf_fill(uint32_t lcore, struct pkt_buf *pb, uint32_t dlen)
{
	uint32_t i;
	int32_t sid;

	sid = rte_lcore_to_socket_id(lcore) + 1;

	for (i = pb->num; i != RTE_DIM(pb->pkt); i++) {
		pb->pkt[i] = rte_pktmbuf_alloc(mpool[sid]);
		if (pb->pkt[i] == NULL)
			break;
		rte_pktmbuf_append(pb->pkt[i], dlen);
	}

	pb->num = i;
}

static struct netfe_stream *
find_fwd_dst(uint32_t lcore, struct netfe_stream *fes,
	const struct sockaddr *sa)
{
	uint32_t rc;
	struct netfe_stream *fed;
	struct netfe_lcore *fe;
	struct tle_udp_stream_param sprm;

	fe = RTE_PER_LCORE(_fe);

	fed = fwd_tbl_lkp(fe, fes->family, sa);
	if (fed != NULL)
		return fed;

	/* create a new stream and put it into the fwd table. */

	sprm = fes->fwdprm.prm;

	/* open forward stream with wildcard remote addr. */
	memset(&sprm.remote_addr.ss_family + 1, 0,
		sizeof(sprm.remote_addr) - sizeof(sprm.remote_addr.ss_family));
	fed = netfe_stream_open(fe, &sprm, lcore, FWD, fes->fwdprm.bidx);
	if (fed == NULL)
		return NULL;

	rc = fwd_tbl_add(fe, fes->family, sa, fed);
	if (rc != 0) {
		netfe_stream_close(fe, 1);
		fed = NULL;
	}

	fed->fwdprm.prm.remote_addr = *(const struct sockaddr_storage *)sa;
	return fed;
}

static inline void
netfe_tx_process(uint32_t lcore, struct netfe_stream *fes)
{
	uint32_t i, k, n;

	/* refill with new mbufs. */
	pkt_buf_fill(lcore, &fes->pbuf, fes->txlen);

	n = fes->pbuf.num;
	if (n == 0)
		return;

	k = tle_udp_stream_send(fes->s, fes->pbuf.pkt, n, NULL);
	NETFE_TRACE("%s(%u): tle_udp_stream_send(%p, %u) returns %u\n",
		__func__, lcore, fes->s, n, k);
	fes->stat.txp += k;
	fes->stat.drops += n - k;

	if (k == 0)
		return;

	/* adjust pbuf array. */
	fes->pbuf.num = n - k;
	for (i = k; i != n; i++)
		fes->pbuf.pkt[i - k] = fes->pbuf.pkt[i];
}


static inline void
netfe_fwd(uint32_t lcore, struct netfe_stream *fes)
{
	uint32_t i, j, k, n, x;
	uint16_t family;
	void *pi0, *pi1, *pt;
	struct rte_mbuf **pkt;
	struct netfe_stream *fed;
	struct sockaddr_storage in[2];

	family = fes->family;
	n = fes->pbuf.num;
	pkt = fes->pbuf.pkt;

	if (n == 0)
		return;

	in[0].ss_family = family;
	in[1].ss_family = family;
	pi0 = &in[0];
	pi1 = &in[1];

	netfe_pkt_addr(pkt[0], pi0, family);

	x = 0;
	for (i = 0; i != n; i = j) {

		j = i + pkt_eq_addr(&pkt[i + 1],
			n - i - 1, family, pi0, pi1) + 1;

		fed = find_fwd_dst(lcore, fes, (const struct sockaddr *)pi0);
		if (fed != NULL) {

			k = tle_udp_stream_send(fed->s, pkt + i, j - i,
				(const struct sockaddr *)
				&fes->fwdprm.prm.remote_addr);

			NETFE_TRACE("%s(%u): tle_udp_stream_send(%p, %u) "
				"returns %u\n",
				__func__, lcore, fed->s, j - i, k);
			fed->stat.txp += k;
			fed->stat.drops += j - i - k;
			fes->stat.fwp += k;

		} else {
			NETFE_TRACE("%s(%u, %p): no fwd stream for %u pkts;\n",
				__func__, lcore, fes->s, j - i);
			for (k = i; k != j; k++) {
				NETFE_TRACE("%s(%u, %p): free(%p);\n",
				__func__, lcore, fes->s, pkt[k]);
				rte_pktmbuf_free(pkt[j]);
			}
			fes->stat.drops += j - i;
		}

		/* copy unforwarded mbufs. */
		for (i += k; i != j; i++, x++)
			pkt[x] = pkt[i];

		/* swap the pointers */
		pt = pi0;
		pi0 = pi1;
		pi1 = pt;
	}

	fes->pbuf.num = x;

	if (x != 0) {
		tle_event_raise(fes->txev);
		fes->stat.txev[TLE_SEV_UP]++;
	}

	if (n == RTE_DIM(fes->pbuf.pkt)) {
		tle_event_active(fes->rxev, TLE_SEV_UP);
		fes->stat.rxev[TLE_SEV_UP]++;
	}
}

static inline void
netfe_rx_process(__rte_unused uint32_t lcore, struct netfe_stream *fes)
{
	uint32_t k, n;

	n = fes->pbuf.num;
	k = RTE_DIM(fes->pbuf.pkt) - n;

	/* packet buffer is full, can't receive any new packets. */
	if (k == 0) {
		tle_event_idle(fes->rxev);
		fes->stat.rxev[TLE_SEV_IDLE]++;
		return;
	}

	n = tle_udp_stream_recv(fes->s, fes->pbuf.pkt + n, k);
	if (n == 0)
		return;

	NETFE_TRACE("%s(%u): tle_udp_stream_recv(%p, %u) returns %u\n",
		__func__, lcore, fes->s, k, n);

	fes->pbuf.num += n;
	fes->stat.rxp += n;

	/* free all received mbufs. */
	if (fes->op == RXONLY)
		pkt_buf_empty(&fes->pbuf);
	/* mark stream as writable */
	else if (k ==  RTE_DIM(fes->pbuf.pkt)) {
		if (fes->op == RXTX) {
			tle_event_active(fes->txev, TLE_SEV_UP);
			fes->stat.txev[TLE_SEV_UP]++;
		} else if (fes->op == FWD) {
			tle_event_raise(fes->txev);
			fes->stat.txev[TLE_SEV_UP]++;
		}
	}
}

static inline void
netfe_rxtx_process(__rte_unused uint32_t lcore, struct netfe_stream *fes)
{
	uint32_t i, j, k, n;
	uint16_t family;
	void *pi0, *pi1, *pt;
	struct rte_mbuf **pkt;
	struct sockaddr_storage in[2];

	family = fes->family;
	n = fes->pbuf.num;
	pkt = fes->pbuf.pkt;

	/* there is nothing to send. */
	if (n == 0) {
		tle_event_idle(fes->txev);
		fes->stat.txev[TLE_SEV_IDLE]++;
		return;
	}

	in[0].ss_family = family;
	in[1].ss_family = family;
	pi0 = &in[0];
	pi1 = &in[1];

	netfe_pkt_addr(pkt[0], pi0, family);

	for (i = 0; i != n; i = j) {

		j = i + pkt_eq_addr(&pkt[i + 1],
			n - i - 1, family, pi0, pi1) + 1;

		k = tle_udp_stream_send(fes->s, pkt + i, j - i,
			(const struct sockaddr *)pi0);

		NETFE_TRACE("%s(%u): tle_udp_stream_send(%p, %u) returns %u\n",
			__func__, lcore, fes->s, j - i, k);
		fes->stat.txp += k;
		fes->stat.drops += j - i - k;

		i += k;

		/* stream send buffer is full */
		if (i != j)
			break;

		/* swap the pointers */
		pt = pi0;
		pi0 = pi1;
		pi1 = pt;
	}

	/* not able to send anything. */
	if (i == 0)
		return;

	if (n == RTE_DIM(fes->pbuf.pkt)) {
		/* mark stream as readable */
		tle_event_active(fes->rxev, TLE_SEV_UP);
		fes->stat.rxev[TLE_SEV_UP]++;
	}

	/* adjust pbuf array. */
	fes->pbuf.num = n - i;
	for (j = i; j != n; j++)
		pkt[j - i] = pkt[j];
}

static int
netfe_lcore_init(const struct netfe_lcore_prm *prm)
{
	size_t sz;
	int32_t rc;
	uint32_t i, lcore, snum;
	struct netfe_lcore *fe;
	struct tle_evq_param eprm;
	struct tle_udp_stream_param sprm;
	struct netfe_stream *fes;

	lcore = rte_lcore_id();

	snum = prm->max_streams;
	RTE_LOG(NOTICE, USER1, "%s(lcore=%u, nb_streams=%u, max_streams=%u)\n",
		__func__, lcore, prm->nb_streams, snum);

	memset(&eprm, 0, sizeof(eprm));
	eprm.socket_id = rte_lcore_to_socket_id(lcore);
	eprm.max_events = snum;

	sz = sizeof(*fe) + snum * sizeof(fe->fs[0]);
	fe = rte_zmalloc_socket(NULL, sz, RTE_CACHE_LINE_SIZE,
		rte_lcore_to_socket_id(lcore));

	if (fe == NULL) {
		RTE_LOG(ERR, USER1, "%s:%d failed to allocate %zu bytes\n",
			__func__, __LINE__, sz);
		return -ENOMEM;
	}

	RTE_PER_LCORE(_fe) = fe;

	fe->snum = snum;
	fe->fs = (struct netfe_stream *)(fe + 1);

	fe->rxeq = tle_evq_create(&eprm);
	fe->txeq = tle_evq_create(&eprm);

	RTE_LOG(INFO, USER1, "%s(%u) rx evq=%p, tx evq=%p\n",
		__func__, lcore, fe->rxeq, fe->txeq);
	if (fe->rxeq == NULL || fe->txeq == NULL)
		return -ENOMEM;

	rc = fwd_tbl_init(fe, AF_INET, lcore);
	RTE_LOG(ERR, USER1, "%s(%u) fwd_tbl_init(%u) returns %d\n",
		__func__, lcore, AF_INET, rc);
	if (rc != 0)
		return rc;

	rc = fwd_tbl_init(fe, AF_INET6, lcore);
	RTE_LOG(ERR, USER1, "%s(%u) fwd_tbl_init(%u) returns %d\n",
		__func__, lcore, AF_INET6, rc);
	if (rc != 0)
		return rc;

	/* open all requested streams. */
	for (i = 0; i != prm->nb_streams; i++) {
		sprm = prm->stream[i].sprm.prm;
		fes = netfe_stream_open(fe, &sprm, lcore, prm->stream[i].op,
			prm->stream[i].sprm.bidx);
		if (fes == NULL) {
			rc = -rte_errno;
			break;
		}

		netfe_stream_dump(fes);

		if (prm->stream[i].op == FWD) {
			fes->fwdprm = prm->stream[i].fprm;
			rc = fwd_tbl_add(fe,
				prm->stream[i].fprm.prm.remote_addr.ss_family,
				(const struct sockaddr *)
				&prm->stream[i].fprm.prm.remote_addr,
				fes);
			if (rc != 0) {
				netfe_stream_close(fe, 1);
				break;
			}
		} else if (prm->stream[i].op == TXONLY) {
			fes->txlen = prm->stream[i].txlen;
			fes->raddr = sprm.remote_addr;
		}
	}

	return rc;
}

static inline void
netfe_lcore(void)
{
	struct netfe_lcore *fe;
	uint32_t j, n, lcore;
	struct netfe_stream *fs[MAX_PKT_BURST];

	fe = RTE_PER_LCORE(_fe);
	if (fe == NULL)
		return;

	lcore = rte_lcore_id();

	n = tle_evq_get(fe->rxeq, (const void **)(uintptr_t)fs, RTE_DIM(fs));

	if (n != 0) {
		NETFE_TRACE("%s(%u): tle_evq_get(rxevq=%p) returns %u\n",
			__func__, lcore, fe->rxeq, n);
		for (j = 0; j != n; j++)
			netfe_rx_process(lcore, fs[j]);
	}

	n = tle_evq_get(fe->txeq, (const void **)(uintptr_t)fs, RTE_DIM(fs));

	if (n != 0) {
		NETFE_TRACE("%s(%u): tle_evq_get(txevq=%p) returns %u\n",
			__func__, lcore, fe->txeq, n);
		for (j = 0; j != n; j++) {
			if (fs[j]->op == RXTX)
				netfe_rxtx_process(lcore, fs[j]);
			else if (fs[j]->op == FWD)
				netfe_fwd(lcore, fs[j]);
			else if (fs[j]->op == TXONLY)
				netfe_tx_process(lcore, fs[j]);
		}
	}
}


static void
netfe_lcore_fini(void)
{
	struct netfe_lcore *fe;
	uint32_t i;

	fe = RTE_PER_LCORE(_fe);
	if (fe == NULL)
		return;

	while (fe->sidx != 0) {

		i = fe->sidx - 1;
		netfe_stream_dump(fe->fs + i);
		netfe_stream_close(fe, 1);
	}

	tle_evq_destroy(fe->txeq);
	tle_evq_destroy(fe->rxeq);
	RTE_PER_LCORE(_fe) = NULL;
	rte_free(fe);
}

static inline void
netbe_rx(struct netbe_lcore *lc, uint32_t pidx)
{
	uint32_t j, k, n;
	struct rte_mbuf *pkt[MAX_PKT_BURST];
	struct rte_mbuf *rp[MAX_PKT_BURST];
	int32_t rc[MAX_PKT_BURST];

	n = rte_eth_rx_burst(lc->prt[pidx].port.id,
			lc->prt[pidx].rxqid, pkt, RTE_DIM(pkt));
	if (n == 0)
		return;

	lc->prt[pidx].rx_stat.in += n;
	NETBE_TRACE("%s(%u): rte_eth_rx_burst(%u, %u) returns %u\n",
		__func__, lc->id, lc->prt[pidx].port.id, lc->prt[pidx].rxqid,
		n);

	k = tle_udp_rx_bulk(lc->prt[pidx].dev, pkt, rp, rc, n);

	lc->prt[pidx].rx_stat.up += k;
	lc->prt[pidx].rx_stat.drop += n - k;
	NETBE_TRACE("%s(%u): tle_udp_rx_bulk(%p, %u) returns %u\n",
		__func__, lc->id, lc->prt[pidx].dev, n, k);

	for (j = 0; j != n - k; j++) {
		NETBE_TRACE("%s:%d(port=%u) rp[%u]={%p, %d};\n",
			__func__, __LINE__, lc->prt[pidx].port.id,
			j, rp[j], rc[j]);
		rte_pktmbuf_free(rp[j]);
	}
}

static inline void
netbe_tx(struct netbe_lcore *lc, uint32_t pidx)
{
	uint32_t j, k, n;
	struct rte_mbuf **mb;

	n = lc->prt[pidx].tx_buf.num;
	k = RTE_DIM(lc->prt[pidx].tx_buf.pkt) - n;
	mb = lc->prt[pidx].tx_buf.pkt;

	if (k >= RTE_DIM(lc->prt[pidx].tx_buf.pkt) / 2) {
		j = tle_udp_tx_bulk(lc->prt[pidx].dev, mb + n, k);
		n += j;
		lc->prt[pidx].tx_stat.down += j;
	}

	if (n == 0)
		return;

	NETBE_TRACE("%s(%u): tle_udp_tx_bulk(%p) returns %u,\n"
		"total pkts to send: %u\n",
		__func__, lc->id, lc->prt[pidx].dev, j, n);

	for (j = 0; j != n; j++)
		NETBE_PKT_DUMP(mb[j]);

	k = rte_eth_tx_burst(lc->prt[pidx].port.id,
			lc->prt[pidx].txqid, mb, n);

	lc->prt[pidx].tx_stat.out += k;
	lc->prt[pidx].tx_stat.drop += n - k;
	NETBE_TRACE("%s(%u): rte_eth_tx_burst(%u, %u, %u) returns %u\n",
		__func__, lc->id, lc->prt[pidx].port.id, lc->prt[pidx].txqid,
		n, k);

	lc->prt[pidx].tx_buf.num = n - k;
	if (k != 0)
		for (j = k; j != n; j++)
			mb[j - k] = mb[j];
}

static int
netbe_lcore_setup(struct netbe_lcore *lc)
{
	uint32_t i;
	int32_t rc;

	RTE_LOG(NOTICE, USER1, "%s(lcore=%u, udp_ctx: %p) start\n",
		__func__, lc->id, lc->ctx);

	/*
	 * ???????
	 * wait for FE lcores to start, so BE dont' drop any packets
	 * because corresponding streams not opened yet by FE.
	 * usefull when used with pcap PMDS.
	 * think better way, or should this timeout be a cmdlien parameter.
	 * ???????
	 */
	rte_delay_ms(10);

	rc = 0;
	for (i = 0; i != lc->prt_num && rc == 0; i++) {
		RTE_LOG(NOTICE, USER1, "%s:%u(port=%u, udp_dev: %p)\n",
			__func__, i, lc->prt[i].port.id, lc->prt[i].dev);
		rc = setup_rx_cb(&lc->prt[i].port, lc);
	}

	if (rc == 0)
		RTE_PER_LCORE(_be) = lc;
	return rc;
}

static inline void
netbe_lcore(void)
{
	uint32_t i;
	struct netbe_lcore *lc;

	lc = RTE_PER_LCORE(_be);
	if (lc == NULL)
		return;

	for (i = 0; i != lc->prt_num; i++) {
		netbe_rx(lc, i);
		netbe_tx(lc, i);
	}
}

static void
netbe_lcore_clear(void)
{
	uint32_t i, j;
	struct netbe_lcore *lc;

	lc = RTE_PER_LCORE(_be);
	if (lc == NULL)
		return;

	RTE_LOG(NOTICE, USER1, "%s(lcore=%u, udp_ctx: %p) finish\n",
		__func__, lc->id, lc->ctx);
	for (i = 0; i != lc->prt_num; i++) {
		RTE_LOG(NOTICE, USER1, "%s:%u(port=%u) "
			"rx_stats={"
			"in=%" PRIu64 ",up=%" PRIu64 ",drop=%" PRIu64 "}, "
			"tx_stats={"
			"in=%" PRIu64 ",up=%" PRIu64 ",drop=%" PRIu64 "};\n",
			__func__, i, lc->prt[i].port.id,
			lc->prt[i].rx_stat.in,
			lc->prt[i].rx_stat.up,
			lc->prt[i].rx_stat.drop,
			lc->prt[i].tx_stat.down,
			lc->prt[i].tx_stat.out,
			lc->prt[i].tx_stat.drop);
	}


	for (i = 0; i != lc->prt_num; i++) {
		for (j = 0; j != lc->prt[i].tx_buf.num; j++)
			rte_pktmbuf_free(lc->prt[i].tx_buf.pkt[j]);
	}

	RTE_PER_LCORE(_be) = NULL;
}

static int
lcore_main(void *arg)
{
	int32_t rc;
	uint32_t lcore;
	struct lcore_prm *prm;

	prm = arg;
	lcore = rte_lcore_id();

	RTE_LOG(NOTICE, USER1, "%s(lcore=%u) start\n",
		__func__, lcore);

	rc = 0;

	/* lcore FE init. */
	if (prm->fe.max_streams != 0)
		rc = netfe_lcore_init(&prm->fe);

	/* lcore FE init. */
	if (rc == 0 && prm->be.lc != NULL) {
		rc = netbe_lcore_setup(prm->be.lc);
	}

	if (rc != 0)
		sig_handle(SIGQUIT);

	while (force_quit == 0) {
		netfe_lcore();
		netbe_lcore();
	}

	RTE_LOG(NOTICE, USER1, "%s(lcore=%u) finish\n",
		__func__, lcore);

	netfe_lcore_fini();
	netbe_lcore_clear();

	return rc;
}



static int
netfe_lcore_cmp(const void *s1, const void *s2)
{
	const struct netfe_stream_prm *p1, *p2;

	p1 = s1;
	p2 = s2;
	return p1->lcore - p2->lcore;
}

/*
 * Helper functions, finds BE by given local and remote addresses.
 */
static int
netbe_find4(const struct in_addr *laddr, const struct in_addr *raddr)
{
	uint32_t i, j;
	int32_t rc;
	uint32_t idx;
	struct netbe_lcore *bc;

	if (laddr->s_addr == INADDR_ANY) {

		/* we have exactly one BE, use it for all traffic */
		if (becfg.cpu_num == 1)
			return 0;

		/* search by remote address. */
		for (i = 0; i != becfg.cpu_num; i++) {
			bc = becfg.cpu + i;
			rc = rte_lpm_lookup(bc->lpm4,
				rte_be_to_cpu_32(raddr->s_addr), &idx);
			if (rc == 0)
				return i;
		}
	} else {

		/* search by local address */
		for (i = 0; i != becfg.cpu_num; i++) {
			bc = becfg.cpu + i;
			for (j = 0; j != bc->prt_num; j++)
				if (laddr->s_addr == bc->prt[j].port.ipv4)
					return i;
		}
	}

	return -ENOENT;
}

static int
netbe_find6(const struct in6_addr *laddr, const struct in6_addr *raddr)
{
	uint32_t i, j;
	int32_t rc;
	uint8_t idx;
	struct netbe_lcore *bc;

	if (memcmp(laddr, &in6addr_any, sizeof(*laddr)) == 0) {

		/* we have exactly one BE, use it for all traffic */
		if (becfg.cpu_num == 1)
			return 0;

		/* search by remote address. */
		for (i = 0; i != becfg.cpu_num; i++) {
			bc = becfg.cpu + i;
			rc = rte_lpm6_lookup(bc->lpm6,
				(uint8_t *)(uintptr_t)raddr->s6_addr, &idx);
			if (rc == 0)
				return i;
		}
	} else {
		/* search by local address */
		for (i = 0; i != becfg.cpu_num; i++) {
			bc = becfg.cpu + i;
			for (j = 0; j != bc->prt_num; j++)
				if (memcmp(laddr, &bc->prt[j].port.ipv6,
						sizeof(*laddr)) == 0)
					return i;
		}
	}

	return -ENOENT;
}

static int
netbe_find(const struct tle_udp_stream_param *p)
{
	const struct sockaddr_in *l4, *r4;
	const struct sockaddr_in6 *l6, *r6;

	if (p->local_addr.ss_family == AF_INET) {
		l4 = (const struct sockaddr_in *)&p->local_addr;
		r4 = (const struct sockaddr_in *)&p->remote_addr;
		return netbe_find4(&l4->sin_addr, &r4->sin_addr);
	} else if (p->local_addr.ss_family == AF_INET6) {
		l6 = (const struct sockaddr_in6 *)&p->local_addr;
		r6 = (const struct sockaddr_in6 *)&p->remote_addr;
		return netbe_find6(&l6->sin6_addr, &r6->sin6_addr);
	}
	return -EINVAL;
}

static int
netfe_sprm_flll_be(struct netfe_sprm *sp, uint32_t line)
{
	int32_t bidx;

	bidx = netbe_find(&sp->prm);
	if (bidx < 0) {
		RTE_LOG(ERR, USER1, "%s(line=%u): no BE for that stream\n",
			__func__, line);
		return -EINVAL;
	}
	sp->bidx = bidx;
	return 0;
}

/* start front-end processing. */
static int
netfe_lcore_fill(struct lcore_prm prm[RTE_MAX_LCORE],
	struct netfe_lcore_prm *lprm)
{
	uint32_t i, j, lc, ln;

	/* determine on what BE each stream should be open. */
	for (i = 0; i != lprm->nb_streams; i++) {

		lc = lprm->stream[i].lcore;
		ln = lprm->stream[i].line;

		if (netfe_sprm_flll_be(&lprm->stream[i].sprm, ln) != 0 ||
				(lprm->stream[i].op == FWD &&
				netfe_sprm_flll_be(&lprm->stream[i].fprm,
				ln) != 0))
			return -EINVAL;
	}

	/* group all fe parameters by lcore. */

	qsort(lprm->stream, lprm->nb_streams, sizeof(lprm->stream[0]),
		netfe_lcore_cmp);

	for (i = 0; i != lprm->nb_streams; i = j) {

		lc = lprm->stream[i].lcore;
		ln = lprm->stream[i].line;

		if (rte_lcore_is_enabled(lc) == 0) {
			RTE_LOG(ERR, USER1,
				"%s(line=%u): lcore %u is not enabled\n",
				__func__, ln, lc);
			return -EINVAL;
		}

		if (rte_get_master_lcore() != lc &&
				rte_eal_get_lcore_state(lc) == RUNNING) {
			RTE_LOG(ERR, USER1,
				"%s(line=%u): lcore %u already in use\n",
				__func__, ln, lc);
			return -EINVAL;
		}

		for (j = i + 1; j != lprm->nb_streams &&
				lc == lprm->stream[j].lcore;
				j++)
			;

		prm[lc].fe.max_streams = lprm->max_streams;
		prm[lc].fe.nb_streams = j - i;
		prm[lc].fe.stream = lprm->stream + i;
	}

	return 0;
}

int
main(int argc, char *argv[])
{
	int32_t opt, opt_idx, rc;
	uint32_t i;
	uint64_t v;
	struct tle_udp_ctx_param ctx_prm;
	struct netfe_lcore_prm feprm;
	struct rte_eth_stats stats;
	char fecfg_fname[PATH_MAX + 1];
	char becfg_fname[PATH_MAX + 1];
	struct lcore_prm prm[RTE_MAX_LCORE];

	fecfg_fname[0] = 0;
	becfg_fname[0] = 0;
	memset(prm, 0, sizeof(prm));

	rc = rte_eal_init(argc, argv);
	if (rc < 0)
		rte_exit(EXIT_FAILURE,
			"%s: rte_eal_init failed with error code: %d\n",
			__func__, rc);

	memset(&ctx_prm, 0, sizeof(ctx_prm));

	argc -= rc;
	argv += rc;

	optind = 0;
	optarg = NULL;
	while ((opt = getopt_long(argc, argv, "B:PR:S:b:f:s:", long_opt,
			&opt_idx)) != EOF) {
		if (opt == OPT_SHORT_SBULK) {
			rc = parse_uint_val(NULL, optarg, &v);
			if (rc < 0)
				rte_exit(EXIT_FAILURE, "%s: invalid value: %s "
					"for option: \'%c\'\n",
					__func__, optarg, opt);
			ctx_prm.send_bulk_size = v;
		} else if (opt == OPT_SHORT_PROMISC) {
			becfg.promisc = 1;
		} else if (opt == OPT_SHORT_RBUFS) {
			rc = parse_uint_val(NULL, optarg, &v);
			if (rc < 0)
				rte_exit(EXIT_FAILURE, "%s: invalid value: %s "
					"for option: \'%c\'\n",
					__func__, optarg, opt);
			ctx_prm.max_stream_rbufs = v;
		} else if (opt == OPT_SHORT_SBUFS) {
			rc = parse_uint_val(NULL, optarg, &v);
			if (rc < 0)
				rte_exit(EXIT_FAILURE, "%s: invalid value: %s "
					"for option: \'%c\'\n",
					__func__, optarg, opt);
			ctx_prm.max_stream_sbufs = v;
		} else if (opt == OPT_SHORT_STREAMS) {
			rc = parse_uint_val(NULL, optarg, &v);
			if (rc < 0)
				rte_exit(EXIT_FAILURE, "%s: invalid value: %s "
					"for option: \'%c\'\n",
					__func__, optarg, opt);
			ctx_prm.max_streams = v;
		} else if (opt == OPT_SHORT_BECFG) {
			snprintf(becfg_fname, sizeof(becfg_fname), "%s",
				optarg);
		} else if (opt == OPT_SHORT_FECFG) {
			snprintf(fecfg_fname, sizeof(fecfg_fname), "%s",
				optarg);
		} else {
			rte_exit(EXIT_FAILURE,
				"%s: unknown option: \'%c\'\n",
				__func__, opt);
		}
	}

	signal(SIGINT, sig_handle);

	netbe_port_init(&becfg, argc - optind, argv + optind);
	netbe_lcore_init(&becfg, &ctx_prm);

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
	}

	feprm.max_streams = ctx_prm.max_streams * becfg.cpu_num;
	if (rc == 0 && (rc = netfe_parse_cfg(fecfg_fname, &feprm)) != 0)
		sig_handle(SIGQUIT);

	for (i = 0; rc == 0 && i != becfg.cpu_num; i++) {
		prm[becfg.cpu[i].id].be.lc = becfg.cpu + i;
	}

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

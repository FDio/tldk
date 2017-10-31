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

#include <assert.h>
#include <netinet/ip6.h>

#include <rte_version.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_errno.h>
#include <rte_lpm6.h>
#include <rte_lpm.h>
#include <rte_ip.h>
#include <rte_tcp.h>

#include <tle_tcp.h>

#include <ngx_config.h>
#include <ngx_core.h>

#include "be.h"

#define RX_RING_SIZE    0x400
#define TX_RING_SIZE    0x800
#define MAX_RULES       0x100
#define MAX_TBL8        0x800

#define MPOOL_CACHE_SIZE        0x100
#define MPOOL_NB_BUF            0x20000

#define FRAG_MBUF_BUF_SIZE      (RTE_PKTMBUF_HEADROOM + TLE_DST_MAX_HDR)

#define RX_CSUM_OFFLOAD (DEV_RX_OFFLOAD_IPV4_CKSUM | DEV_RX_OFFLOAD_TCP_CKSUM)

#define TCP_MAX_PROCESS 0x20

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.hw_vlan_strip = 1,
	},
};

struct ptype2cb {
	uint32_t mask;
	const char *name;
	rte_rx_callback_fn fn;
};

enum {
	ETHER_PTYPE = 0x1,
	IPV4_PTYPE = 0x2,
	IPV4_EXT_PTYPE = 0x4,
	IPV6_PTYPE = 0x8,
	IPV6_EXT_PTYPE = 0x10,
	TCP_PTYPE = 0x20,
	UDP_PTYPE = 0x40,
};

int
be_lcore_lpm_init(struct tldk_ctx *tcx, uint32_t sid,
		const struct tldk_ctx_conf *cf)
{
	ngx_uint_t worker = cf->worker;
	uint32_t lcore = cf->lcore;
	char str[RTE_LPM_NAMESIZE];

	const struct rte_lpm_config lpm4_cfg = {
		.max_rules = MAX_RULES,
		.number_tbl8s = MAX_TBL8,
	};

	const struct rte_lpm6_config lpm6_cfg = {
		.max_rules = MAX_RULES,
		.number_tbl8s = MAX_TBL8,
	};

	snprintf(str, sizeof(str), "LPM4%lu-%u\n", worker, lcore);
	tcx->lpm4 = rte_lpm_create(str, sid, &lpm4_cfg);
	RTE_LOG(NOTICE, USER1, "%s(worker=%lu, lcore=%u): lpm4=%p;\n",
		__func__, worker, lcore, tcx->lpm4);
	if (tcx->lpm4 == NULL)
		return -ENOMEM;

	snprintf(str, sizeof(str), "LPM6%lu-%u\n", worker, lcore);
	tcx->lpm6 = rte_lpm6_create(str, sid, &lpm6_cfg);
	RTE_LOG(NOTICE, USER1, "%s(worker=%lu, lcore=%u): lpm6=%p;\n",
		__func__, worker, lcore, tcx->lpm6);
	if (tcx->lpm6 == NULL) {
		rte_lpm_free(tcx->lpm4);
		return -ENOMEM;
	}

	return 0;
}

int
be_lpm4_dst_lookup(void *data, const struct in_addr *addr,
		struct tle_dest *res)
{
	int32_t rc;
	uint32_t idx;
	struct tldk_ctx *tcx;
	struct tle_dest *dst;

	tcx = data;
	rc = rte_lpm_lookup(tcx->lpm4, rte_be_to_cpu_32(addr->s_addr), &idx);
	if (rc == 0) {
		dst = &tcx->dst4[idx];
		memcpy(res, dst, dst->l2_len + dst->l3_len +
				offsetof(struct tle_dest, hdr));
	}

	return rc;
}

int
be_lpm6_dst_lookup(void *data, const struct in6_addr *addr,
	struct tle_dest *res)
{
	int32_t rc;
	struct tldk_ctx *tcx;
	struct tle_dest *dst;
	uintptr_t p;
#if RTE_VERSION_NUM(17, 5, 0, 0) <= RTE_VERSION
	uint32_t idx;
#else
	uint8_t idx;
#endif

	tcx = data;
	p = (uintptr_t)addr->s6_addr;
	rc = rte_lpm6_lookup(tcx->lpm6, (uint8_t *)p, &idx);
	if (rc == 0) {
		dst = &tcx->dst6[idx];
		memcpy(res, dst, dst->l2_len + dst->l3_len +
				offsetof(struct tle_dest, hdr));
	}

	return rc;
}

/*
 * Initialise DPDK port.
 */
static int
port_init(const struct tldk_port_conf *pcf)
{
	int32_t rc;
	struct rte_eth_conf port_conf;
	struct rte_eth_dev_info dev_info;

	rte_eth_dev_info_get(pcf->id, &dev_info);

	if ((dev_info.rx_offload_capa & pcf->rx_offload) != pcf->rx_offload) {
		RTE_LOG(ERR, USER1,
			"port#%u supported/requested RX offloads don't match, "
			"supported: %#x, requested: %#x;\n",
			pcf->id, dev_info.rx_offload_capa, pcf->rx_offload);
		return NGX_ERROR;
	}
	if ((dev_info.tx_offload_capa & pcf->tx_offload) != pcf->tx_offload) {
		RTE_LOG(ERR, USER1,
			"port#%u supported/requested TX offloads don't match, "
			"supported: %#x, requested: %#x;\n",
			pcf->id, dev_info.tx_offload_capa, pcf->tx_offload);
		return NGX_ERROR;
	}

	port_conf = port_conf_default;

	if ((pcf->rx_offload & RX_CSUM_OFFLOAD) != 0) {
		RTE_LOG(ERR, USER1, "%s(%u): enabling RX csum offload;\n",
			__func__, pcf->id);
		port_conf.rxmode.hw_ip_checksum = 1;
	}

	port_conf.rxmode.max_rx_pkt_len = pcf->mtu + ETHER_CRC_LEN;
	if (port_conf.rxmode.max_rx_pkt_len > ETHER_MAX_LEN)
		port_conf.rxmode.jumbo_frame = 1;
	port_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
	port_conf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_IP | ETH_RSS_TCP;

	rc = rte_eth_dev_configure(pcf->id, pcf->nb_queues, pcf->nb_queues,
			&port_conf);
	RTE_LOG(NOTICE, USER1,
		"%s: rte_eth_dev_configure(prt_id=%u, nb_rxq=%u, nb_txq=%u) "
		"returns %d;\n", __func__, pcf->id, pcf->nb_queues,
		pcf->nb_queues, rc);

	if (rc != 0)
		return NGX_ERROR;

	return NGX_OK;
}

/*
 * Check that lcore is enabled, not master, and not in use already.
 */
int
be_check_lcore(uint32_t lid)
{
	if (rte_lcore_is_enabled(lid) == 0) {
		RTE_LOG(ERR, USER1, "lcore %u is not enabled\n", lid);
		return -EINVAL;
	}

	if (rte_get_master_lcore() != lid &&
		rte_eal_get_lcore_state(lid) == RUNNING) {
		RTE_LOG(ERR, USER1, "lcore %u already running %p\n",
			lid, lcore_config[lid].f);
		return -EINVAL;
	}

	return 0;
}

int
be_mpool_init(struct tldk_ctx *tcx)
{
	int32_t rc;
	uint32_t nmb, sid;
	struct rte_mempool *mp;
	char name[RTE_MEMPOOL_NAMESIZE];

	ngx_uint_t worker = tcx->cf->worker;
	uint32_t lcore = tcx->cf->lcore;

	sid = rte_lcore_to_socket_id(tcx->cf->lcore);
	nmb = (tcx->cf->nb_mbuf == 0) ? MPOOL_NB_BUF : tcx->cf->nb_mbuf;

	snprintf(name, sizeof(name), "MP%lu-%u", worker, lcore);
	mp = rte_pktmbuf_pool_create(name, nmb, MPOOL_CACHE_SIZE, 0,
			RTE_MBUF_DEFAULT_BUF_SIZE, sid);
	if (mp == NULL) {
		rc = -rte_errno;
		RTE_LOG(ERR, USER1, "%s:Mempool creation failed for "
			"ctx:wrk(%lu)-ctx:lcore(%u) with error code: %d\n",
			__func__, worker, lcore, rc);
		return rc;
	}

	tcx->mpool = mp;

	snprintf(name, sizeof(name), "frag_MP%lu-%u",
			worker, lcore);
	mp = rte_pktmbuf_pool_create(name, nmb,
			MPOOL_CACHE_SIZE, 0, FRAG_MBUF_BUF_SIZE, sid - 1);
	if (mp == NULL) {
		rc = -rte_errno;
		RTE_LOG(ERR, USER1, "%s:Frag mempool creation failed for "
			"ctx:wrk(%lu)-ctx:lcore(%u) with error code: %d\n",
			__func__, worker, lcore, rc);
		return rc;
	}

	tcx->frag_mpool = mp;

	return 0;
}

int
be_queue_init(struct tldk_ctx *tcx, const tldk_conf_t *cf)
{
	int32_t socket, rc;
	uint16_t queue_id;
	uint32_t port_id, i;
	struct rte_eth_dev_info dev_info;
	const struct tldk_ctx_conf *ctx;
	const struct tldk_port_conf *pcf;

	ctx = tcx->cf;
	for (i = 0; i < ctx->nb_dev; i++) {
		port_id = ctx->dev[i].port;
		queue_id = ctx->dev[i].queue;
		pcf = &cf->port[port_id];

		rte_eth_dev_info_get(port_id, &dev_info);
		dev_info.default_rxconf.rx_drop_en = 1;
		dev_info.default_txconf.tx_free_thresh = TX_RING_SIZE / 2;

		if (pcf->tx_offload != 0) {
			RTE_LOG(ERR, USER1,
				"%s(port=%u): enabling full featured TX;\n",
				__func__, port_id);
			dev_info.default_txconf.txq_flags = 0;
		}

		socket = rte_eth_dev_socket_id(port_id);

		rc = rte_eth_rx_queue_setup(port_id, queue_id, RX_RING_SIZE,
				socket, &dev_info.default_rxconf, tcx->mpool);
		if (rc < 0) {
			RTE_LOG(ERR, USER1,
				"%s: rx queue=%u setup failed with error "
				"code: %d\n", __func__, queue_id, rc);
			return rc;
		}

		rc = rte_eth_tx_queue_setup(port_id, queue_id, TX_RING_SIZE,
				socket, &dev_info.default_txconf);
		if (rc < 0) {
			RTE_LOG(ERR, USER1,
				"%s: tx queue=%u setup failed with error "
				"code: %d\n", __func__, queue_id, rc);
			return rc;
		}
	}

	return 0;
}

/*
 * Setup all enabled ports.
 */
int
be_port_init(tldk_conf_t *cf)
{
	int32_t rc;
	uint32_t i;
	struct tldk_port_conf *dpf;

	for (i = 0; i != cf->nb_port; i++) {
		dpf = &cf->port[i];
		rc = port_init(dpf);
		if (rc != 0) {
			RTE_LOG(ERR, USER1,
				"%s: port=%u init failed with error code: %d\n",
				__func__, dpf->id, rc);
			return NGX_ERROR;
		}
		rte_eth_macaddr_get(dpf->id, &dpf->mac);
		rte_eth_promiscuous_enable(dpf->id);
	}

	return NGX_OK;
}

static int
be_add_ipv4_route(struct tldk_ctx *tcx, const struct tldk_dest_conf *dcf,
	uint8_t idx)
{
	int32_t rc;
	uint32_t addr, depth;
	char str[INET_ADDRSTRLEN];

	depth = dcf->prfx;
	addr = rte_be_to_cpu_32(dcf->ipv4.s_addr);

	inet_ntop(AF_INET, &dcf->ipv4, str, sizeof(str));
	rc = rte_lpm_add(tcx->lpm4, addr, depth, idx);
	RTE_LOG(NOTICE, USER1, "%s(lcore=%u,dev_id=%u,dev=%p,"
			"ipv4=%s/%u,mtu=%u,"
			"mac=%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx) "
			"returns %d;\n",
			__func__, tcx->cf->lcore, dcf->dev, tcx->dst4[idx].dev,
			str, depth, tcx->dst4[idx].mtu,
			dcf->mac.addr_bytes[0], dcf->mac.addr_bytes[1],
			dcf->mac.addr_bytes[2], dcf->mac.addr_bytes[3],
			dcf->mac.addr_bytes[4], dcf->mac.addr_bytes[5],
			rc);

	return rc;
}

static int
be_add_ipv6_route(struct tldk_ctx *tcx, const struct tldk_dest_conf *dcf,
	uint8_t idx)
{
	int32_t rc;
	uint32_t depth;
	char str[INET6_ADDRSTRLEN];

	depth = dcf->prfx;

	rc = rte_lpm6_add(tcx->lpm6, (uint8_t *)(uintptr_t)dcf->ipv6.s6_addr,
			depth, idx);

	inet_ntop(AF_INET6, &dcf->ipv6, str, sizeof(str));
	RTE_LOG(NOTICE, USER1, "%s(lcore=%u,dev_id=%u,dev=%p,"
		"ipv6=%s/%u,mtu=%u,"
		"mac=%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx) "
		"returns %d;\n",
		__func__, tcx->cf->lcore, dcf->dev, tcx->dst6[idx].dev,
		str, depth, tcx->dst4[idx].mtu,
		dcf->mac.addr_bytes[0], dcf->mac.addr_bytes[1],
		dcf->mac.addr_bytes[2], dcf->mac.addr_bytes[3],
		dcf->mac.addr_bytes[4], dcf->mac.addr_bytes[5],
		rc);

	return rc;
}

static void
fill_dst(struct tle_dest *dst, const struct tldk_dev *td,
	const struct tldk_port_conf *pcf, const struct tldk_dest_conf *dest,
	uint16_t l3_type, struct rte_mempool *mp)
{
	struct ether_hdr *eth;
	struct ipv4_hdr *ip4h;
	struct ipv6_hdr *ip6h;

	dst->dev = td->dev;
	dst->head_mp = mp;
	dst->mtu = RTE_MIN(dest->mtu, pcf->mtu);
	dst->l2_len = sizeof(*eth);

	eth = (struct ether_hdr *)dst->hdr;

	ether_addr_copy(&pcf->mac, &eth->s_addr);
	ether_addr_copy(&dest->mac, &eth->d_addr);
	eth->ether_type = rte_cpu_to_be_16(l3_type);

	if (l3_type == ETHER_TYPE_IPv4) {
		dst->l3_len = sizeof(*ip4h);
		ip4h = (struct ipv4_hdr *)(eth + 1);
		ip4h->version_ihl = 4 << 4 |
			sizeof(*ip4h) / IPV4_IHL_MULTIPLIER;
		ip4h->time_to_live = 64;
		ip4h->next_proto_id = IPPROTO_TCP;
	} else if (l3_type == ETHER_TYPE_IPv6) {
		dst->l3_len = sizeof(*ip6h);
		ip6h = (struct ipv6_hdr *)(eth + 1);
		ip6h->vtc_flow = 6 << 4;
		ip6h->proto = IPPROTO_TCP;
		ip6h->hop_limits = 64;
	}
}

static int
be_add_dest(const struct tldk_dest_conf *dcf, struct tldk_ctx *tcx,
	uint32_t dev_idx, const struct tldk_port_conf *pcf, uint32_t family,
	uint32_t dnum)
{
	struct tle_dest *dp;
	uint32_t i, n, m;
	uint16_t l3_type;
	int32_t rc = 0;

	if (family == AF_INET) {
		n = tcx->dst4_num;
		dp = tcx->dst4 + n;
		m = RTE_DIM(tcx->dst4);
		l3_type = ETHER_TYPE_IPv4;
	} else {
		n = tcx->dst6_num;
		dp = tcx->dst6 + n;
		m = RTE_DIM(tcx->dst6);
		l3_type = ETHER_TYPE_IPv6;
	}

	if (n + dnum >= m) {
		RTE_LOG(ERR, USER1, "%s(lcore=%u, family=%hu, dnum=%u) exceeds "
			"maximum allowed number of destinations(%u);\n",
			__func__, tcx->cf->lcore, family, dnum, m);
		return -ENOSPC;
	}

	for (i = 0; i != dnum && rc == 0; i++) {
		fill_dst(dp + i, &tcx->dev[dev_idx], pcf, dcf,
			l3_type, tcx->frag_mpool);
		if (family == AF_INET)
			rc = be_add_ipv4_route(tcx, dcf, n + i);
		else
			rc = be_add_ipv6_route(tcx, dcf, n + i);
	}

	if (family == AF_INET)
		tcx->dst4_num = n + i;
	else
		tcx->dst6_num = n + i;

	return rc;
}

int
be_dst_init(struct tldk_ctx *tcx, const tldk_conf_t *cf)
{
	uint32_t i, f, d, l, port_id;
	const struct tldk_ctx_conf *ctx_cf = tcx->cf;
	const struct tldk_dest_conf *dcf;
	const struct tldk_port_conf *pcf;
	int32_t rc = 0;

	for (i = 0; i < ctx_cf->nb_dest; i++) {
		dcf = &ctx_cf->dest[i];
		f = dcf->family;
		d = dcf->dev;
		for (l = 0; l != tcx->nb_dev; l++) {
			if (tcx->dev[l].cf.id == d) {
				/* fetch the port conf for the port
				 * associated with device
				 */
				port_id = tcx->dev[l].cf.port;
				pcf = &cf->port[port_id];
				rc = be_add_dest(dcf, tcx, l, pcf, f, 1);
				if (rc != 0) {
					RTE_LOG(ERR, USER1,
						"%s(tcx=%u, family=%u) "
						"could not add "
						"destinations(%u)\n",
						__func__, ctx_cf->lcore, f, i);
					return -ENOSPC;
				}
				break;
			}
		}
	}

	return rc;
}

int
be_add_dev(struct tldk_ctx *tcx, const tldk_conf_t *cf)
{
	int32_t rc = 0;
	uint32_t i, port_id;
	struct tle_dev_param dprm;
	const struct tldk_port_conf *pcf;

	memset(&dprm, 0, sizeof(dprm));

	/* add the tle_dev on all applicable ports of the context */
	for (i = 0; i != tcx->cf->nb_dev; i++) {

		/* get the port id associated with the device */
		port_id = tcx->cf->dev[i].port;

		/* get the port config by port id */
		pcf = &cf->port[port_id];

		/* populate the tle_dev_param struct */
		dprm.rx_offload = pcf->rx_offload;
		dprm.tx_offload = pcf->tx_offload;
		dprm.local_addr4.s_addr = pcf->ipv4;

		memcpy(&dprm.local_addr6, &pcf->ipv6,
			sizeof(pcf->ipv6));

		/* add the tle_dev */
		tcx->dev[i].dev = tle_add_dev(tcx->ctx, &dprm);

		RTE_LOG(NOTICE, USER1, "%s(port=%u), dev: %p\n",
			__func__, port_id,
			tcx->dev[i].dev);

		if (tcx->dev[i].dev == NULL)
			rc = -rte_errno;

		if (rc != 0)
			return rc;

		tcx->nb_dev++;
		tcx->dev[i].cf = tcx->cf->dev[i];
	}

	return rc;
}

static uint32_t
get_ptypes(const struct tldk_dev *td)
{
	uint32_t smask;
	int32_t i, rc;
	const uint32_t pmask = RTE_PTYPE_L2_MASK | RTE_PTYPE_L3_MASK |
		RTE_PTYPE_L4_MASK;

	smask = 0;
	rc = rte_eth_dev_get_supported_ptypes(td->cf.port, pmask, NULL, 0);
	if (rc < 0) {
		RTE_LOG(ERR, USER1,
			"%s(port=%u) failed to get supported ptypes;\n",
			__func__, td->cf.port);
		return smask;
	}

	uint32_t ptype[rc];
	rc = rte_eth_dev_get_supported_ptypes(td->cf.port, pmask, ptype, rc);

	for (i = 0; i != rc; i++) {
		switch (ptype[i]) {
		case RTE_PTYPE_L2_ETHER:
			smask |= ETHER_PTYPE;
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
		}
	}

	return smask;
}

static inline uint64_t
_mbuf_tx_offload(uint64_t il2, uint64_t il3, uint64_t il4, uint64_t tso,
	uint64_t ol3, uint64_t ol2)
{
	return il2 | il3 << 7 | il4 << 16 | tso << 24 | ol3 << 40 | ol2 << 49;
}

static inline void
fill_pkt_hdr_len(struct rte_mbuf *m, uint32_t l2, uint32_t l3, uint32_t l4)
{
	m->tx_offload = _mbuf_tx_offload(l2, l3, l4, 0, 0, 0);
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

static inline void
adjust_ipv4_pktlen(struct rte_mbuf *m, uint32_t l2_len)
{
	uint32_t plen, trim;
	const struct ipv4_hdr *iph;

	iph = rte_pktmbuf_mtod_offset(m, const struct ipv4_hdr *, l2_len);
	plen = rte_be_to_cpu_16(iph->total_length) + l2_len;
	if (plen < m->pkt_len) {
		trim = m->pkt_len - plen;
		rte_pktmbuf_trim(m, trim);
	}
}

static inline void
adjust_ipv6_pktlen(struct rte_mbuf *m, uint32_t l2_len)
{
	uint32_t plen, trim;
	const struct ipv6_hdr *iph;

	iph = rte_pktmbuf_mtod_offset(m, const struct ipv6_hdr *, l2_len);
	plen = rte_be_to_cpu_16(iph->payload_len) + sizeof(*iph) + l2_len;
	if (plen < m->pkt_len) {
		trim = m->pkt_len - plen;
		rte_pktmbuf_trim(m, trim);
	}
}

static inline void
tcp_stat_update(struct tldk_ctx *lc, const struct rte_mbuf *m,
	uint32_t l2_len, uint32_t l3_len)
{
	const struct tcp_hdr *th;

	th = rte_pktmbuf_mtod_offset(m, struct tcp_hdr *, l2_len + l3_len);
	lc->tcp_stat.flags[th->tcp_flags]++;
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

static inline int
ipv6x_hdr(uint32_t proto)
{
	return (proto == IPPROTO_HOPOPTS ||
		proto == IPPROTO_ROUTING ||
		proto == IPPROTO_FRAGMENT ||
		proto == IPPROTO_AH ||
		proto == IPPROTO_NONE ||
		proto == IPPROTO_DSTOPTS);
}

static inline uint32_t
get_ipv6x_hdr_len(struct rte_mbuf *m, uint32_t l2, uint32_t nproto,
	uint32_t fproto)
{
	const struct ip6_ext *ipx;
	int32_t dlen, len, ofs;

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

	/* unrecognized or invalid packet. */
	if ((ofs == 0 && nproto != fproto) || len > dlen)
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
	else if (ipv6x_hdr(iph->proto) != 0)
		return get_ipv6x_hdr_len(m, l2, iph->proto, fproto);

	m->packet_type = RTE_PTYPE_UNKNOWN;
	return 0;
}

static inline void
fill_eth_tcp_hdr_len(struct rte_mbuf *m)
{
	uint32_t dlen, l2_len, l3_len, l4_len;
	uint16_t etp;
	const struct ether_hdr *eth;

	dlen = rte_pktmbuf_data_len(m);

	/* check that first segment is at least 54B long. */
	if (dlen < sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +
			sizeof(struct tcp_hdr)) {
		m->packet_type = RTE_PTYPE_UNKNOWN;
		return;
	}

	l2_len = sizeof(*eth);

	eth = rte_pktmbuf_mtod(m, const struct ether_hdr *);
	etp = eth->ether_type;
	if (etp == rte_be_to_cpu_16(ETHER_TYPE_VLAN))
		l2_len += sizeof(struct vlan_hdr);

	if (etp == rte_be_to_cpu_16(ETHER_TYPE_IPv4)) {
		m->packet_type = RTE_PTYPE_L4_TCP |
			RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
			RTE_PTYPE_L2_ETHER;
		l3_len = get_ipv4_hdr_len(m, l2_len, IPPROTO_TCP, 1);
		l4_len = get_tcp_header_size(m, l2_len, l3_len);
		fill_pkt_hdr_len(m, l2_len, l3_len, l4_len);
		adjust_ipv4_pktlen(m, l2_len);
	} else if (etp == rte_be_to_cpu_16(ETHER_TYPE_IPv6) &&
			dlen >= l2_len + sizeof(struct ipv6_hdr) +
			sizeof(struct tcp_hdr)) {
		m->packet_type = RTE_PTYPE_L4_TCP |
			RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
			RTE_PTYPE_L2_ETHER;
		l3_len = get_ipv6_hdr_len(m, l2_len, IPPROTO_TCP);
		l4_len = get_tcp_header_size(m, l2_len, l3_len);
		fill_pkt_hdr_len(m, l2_len, l3_len, l4_len);
		adjust_ipv6_pktlen(m, l2_len);
	} else
		m->packet_type = RTE_PTYPE_UNKNOWN;
}

/*
 * HW can recognize L2/L3 with/without extensions/L4 (ixgbe/igb/fm10k)
 */
static uint16_t
type0_tcp_rx_callback(__rte_unused uint8_t port, __rte_unused uint16_t queue,
	struct rte_mbuf *pkt[], uint16_t nb_pkts,
	__rte_unused uint16_t max_pkts, __rte_unused void *user_param)
{
	uint32_t j, tp;
	uint32_t l4_len, l3_len, l2_len;
	const struct ether_hdr *eth;

	l2_len = sizeof(*eth);

	for (j = 0; j != nb_pkts; j++) {

		BE_PKT_DUMP(pkt[j]);

		tp = pkt[j]->packet_type & (RTE_PTYPE_L4_MASK |
			RTE_PTYPE_L3_MASK | RTE_PTYPE_L2_MASK);

		switch (tp) {
		/* non fragmented tcp packets. */
		case (RTE_PTYPE_L4_TCP | RTE_PTYPE_L3_IPV4 |
				RTE_PTYPE_L2_ETHER):
			l4_len = get_tcp_header_size(pkt[j], l2_len,
				sizeof(struct ipv4_hdr));
			fill_pkt_hdr_len(pkt[j], l2_len,
				sizeof(struct ipv4_hdr), l4_len);
			adjust_ipv4_pktlen(pkt[j], l2_len);
			break;
		case (RTE_PTYPE_L4_TCP | RTE_PTYPE_L3_IPV6 |
				RTE_PTYPE_L2_ETHER):
			l4_len = get_tcp_header_size(pkt[j], l2_len,
				sizeof(struct ipv6_hdr));
			fill_pkt_hdr_len(pkt[j], l2_len,
				sizeof(struct ipv6_hdr), l4_len);
			adjust_ipv6_pktlen(pkt[j], l2_len);
			break;
		case (RTE_PTYPE_L4_TCP | RTE_PTYPE_L3_IPV4_EXT |
				RTE_PTYPE_L2_ETHER):
			l3_len = get_ipv4_hdr_len(pkt[j], l2_len,
				IPPROTO_TCP, 0);
			l4_len = get_tcp_header_size(pkt[j], l2_len, l3_len);
			fill_pkt_hdr_len(pkt[j], l2_len, l3_len, l4_len);
			adjust_ipv4_pktlen(pkt[j], l2_len);
			break;
		case (RTE_PTYPE_L4_TCP | RTE_PTYPE_L3_IPV6_EXT |
				RTE_PTYPE_L2_ETHER):
			l3_len = get_ipv6_hdr_len(pkt[j], l2_len, IPPROTO_TCP);
			l4_len = get_tcp_header_size(pkt[j], l2_len, l3_len);
			fill_pkt_hdr_len(pkt[j], l2_len, l3_len, l4_len);
			adjust_ipv6_pktlen(pkt[j], l2_len);
			break;
		default:
			/* treat packet types as invalid. */
			pkt[j]->packet_type = RTE_PTYPE_UNKNOWN;
			break;
		}
	}

	return nb_pkts;
}

/*
 * HW can recognize L2/L3/L4 and fragments (i40e).
 */
static uint16_t
type1_tcp_rx_callback(__rte_unused uint8_t port, __rte_unused uint16_t queue,
	struct rte_mbuf *pkt[], uint16_t nb_pkts,
	__rte_unused uint16_t max_pkts, void *user_param)
{
	uint32_t j, tp;
	struct tldk_ctx *tcx;
	uint32_t l4_len, l3_len, l2_len;
	const struct ether_hdr *eth;

	tcx = user_param;
	l2_len = sizeof(*eth);

	for (j = 0; j != nb_pkts; j++) {

		BE_PKT_DUMP(pkt[j]);

		tp = pkt[j]->packet_type & (RTE_PTYPE_L4_MASK |
			RTE_PTYPE_L3_MASK | RTE_PTYPE_L2_MASK);

		switch (tp) {
		case (RTE_PTYPE_L4_TCP | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_L2_ETHER):
			l3_len = get_ipv4_hdr_len(pkt[j], l2_len,
				IPPROTO_TCP, 0);
			l4_len = get_tcp_header_size(pkt[j], l2_len, l3_len);
			fill_pkt_hdr_len(pkt[j], l2_len, l3_len, l4_len);
			adjust_ipv4_pktlen(pkt[j], l2_len);
			tcp_stat_update(tcx, pkt[j], l2_len, l3_len);
			break;
		case (RTE_PTYPE_L4_TCP | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_L2_ETHER):
			l3_len = get_ipv6_hdr_len(pkt[j], l2_len, IPPROTO_TCP);
			l4_len = get_tcp_header_size(pkt[j], l2_len, l3_len);
			fill_pkt_hdr_len(pkt[j], l2_len, l3_len, l4_len);
			adjust_ipv6_pktlen(pkt[j], l2_len);
			tcp_stat_update(tcx, pkt[j], l2_len, l3_len);
			break;
		default:
			/* treat packet types as invalid. */
			pkt[j]->packet_type = RTE_PTYPE_UNKNOWN;
			break;
		}

	}

	return nb_pkts;
}

static uint16_t
typen_tcp_rx_callback(__rte_unused uint8_t port, __rte_unused uint16_t queue,
	struct rte_mbuf *pkt[], uint16_t nb_pkts,
	__rte_unused uint16_t max_pkts, __rte_unused void *user_param)
{
	uint32_t j;

	for (j = 0; j != nb_pkts; j++) {

		BE_PKT_DUMP(pkt[j]);
		fill_eth_tcp_hdr_len(pkt[j]);
	}

	return nb_pkts;
}

int
setup_rx_cb(const struct tldk_dev *td, struct tldk_ctx *tcx)
{
	int32_t rc;
	uint32_t i, n, smask;
	void *cb;
	const struct ptype2cb *ptype2cb;

	static const struct ptype2cb tcp_ptype2cb[] = {
		{
			.mask = ETHER_PTYPE | IPV4_PTYPE | IPV4_EXT_PTYPE |
				IPV6_PTYPE | IPV6_EXT_PTYPE | TCP_PTYPE,
			.name = "HW l2/l3x/l4-tcp ptype",
			.fn = type0_tcp_rx_callback,
		},
		{
			.mask = ETHER_PTYPE | IPV4_PTYPE | IPV6_PTYPE |
				TCP_PTYPE,
			.name = "HW l2/l3/l4-tcp ptype",
			.fn = type1_tcp_rx_callback,
		},
		{
			.mask = 0,
			.name = "tcp no HW ptype",
			.fn = typen_tcp_rx_callback,
		},
	};

	smask = get_ptypes(td);

	ptype2cb = tcp_ptype2cb;
	n = RTE_DIM(tcp_ptype2cb);

	for (i = 0; i != n; i++) {
		if ((smask & ptype2cb[i].mask) == ptype2cb[i].mask) {
			cb = rte_eth_add_rx_callback(td->cf.port, td->cf.queue,
				ptype2cb[i].fn, tcx);
			rc = -rte_errno;
			RTE_LOG(ERR, USER1,
				"%s(port=%u), setup RX callback \"%s\" "
				"returns %p;\n",
				__func__, td->cf.port,  ptype2cb[i].name, cb);
				return ((cb == NULL) ? rc : 0);
		}
	}

	/* no proper callback found. */
	RTE_LOG(ERR, USER1,
		"%s(port=%u) failed to find an appropriate callback;\n",
		__func__, td->cf.port);
	return -ENOENT;
}

int
be_lcore_setup(struct tldk_ctx *tcx)
{
	uint32_t i;
	int32_t rc;

	RTE_LOG(NOTICE, USER1, "%s:(lcore=%u, ctx=%p) start\n",
		__func__, tcx->cf->lcore, tcx->ctx);

	rc = 0;
	for (i = 0; i != tcx->nb_dev && rc == 0; i++) {
		RTE_LOG(NOTICE, USER1, "%s:%u(port=%u, q=%u)\n",
			__func__, i, tcx->dev[i].cf.port, tcx->dev[i].cf.queue);

		rc = setup_rx_cb(&tcx->dev[i], tcx);
		if (rc < 0)
			return rc;
	}

	return rc;
}

static inline void
be_rx(struct tldk_dev *dev)
{
	uint32_t j, k, n;
	struct rte_mbuf *pkt[MAX_PKT_BURST];
	struct rte_mbuf *rp[MAX_PKT_BURST];
	int32_t rc[MAX_PKT_BURST];

	n = rte_eth_rx_burst(dev->cf.port,
		dev->cf.queue, pkt, RTE_DIM(pkt));

	if (n != 0) {
		dev->rx_stat.in += n;
		BE_TRACE("%s(%u): rte_eth_rx_burst(%u, %u) returns %u\n",
			__func__, dev->cf.id, dev->cf.port,
			dev->cf.queue, n);

		k = tle_tcp_rx_bulk(dev->dev, pkt, rp, rc, n);

		dev->rx_stat.up += k;
		dev->rx_stat.drop += n - k;
		BE_TRACE("%s: tle_tcp_rx_bulk(%p, %u) returns %u\n",
			__func__, dev->dev, n, k);

		for (j = 0; j != n - k; j++) {
			BE_TRACE("%s:%d(port=%u) rp[%u]={%p, %d};\n",
				__func__, __LINE__, dev->cf.port,
				j, rp[j], rc[j]);
			rte_pktmbuf_free(rp[j]);
		}
	}
}

static inline void
be_tx(struct tldk_dev *dev)
{
	uint32_t j = 0, k, n;
	struct rte_mbuf **mb;

	n = dev->tx_buf.num;
	k = RTE_DIM(dev->tx_buf.pkt) - n;
	mb = dev->tx_buf.pkt;

	if (k >= RTE_DIM(dev->tx_buf.pkt) / 2) {
		j = tle_tcp_tx_bulk(dev->dev, mb + n, k);
		n += j;
		dev->tx_stat.down += j;
	}

	if (n == 0)
		return;

	BE_TRACE("%s: tle_tcp_tx_bulk(%p) returns %u,\n"
		"total pkts to send: %u\n",
		__func__, dev->dev, j, n);

	for (j = 0; j != n; j++)
		BE_PKT_DUMP(mb[j]);

	k = rte_eth_tx_burst(dev->cf.port,
			dev->cf.queue, mb, n);

	dev->tx_stat.out += k;
	dev->tx_stat.drop += n - k;
	BE_TRACE("%s: rte_eth_tx_burst(%u, %u, %u) returns %u\n",
		__func__, dev->cf.port,
		dev->cf.queue, n, k);

	dev->tx_buf.num = n - k;
	if (k != 0)
		for (j = k; j != n; j++)
			mb[j - k] = mb[j];
}

void
be_lcore_tcp(struct tldk_ctx *tcx)
{
	uint32_t i;

	if (tcx == NULL)
		return;

	for (i = 0; i != tcx->nb_dev; i++) {
		be_rx(&tcx->dev[i]);
		be_tx(&tcx->dev[i]);
	}
	tle_tcp_process(tcx->ctx, TCP_MAX_PROCESS);
}

void
be_lcore_clear(struct tldk_ctx *tcx)
{
	uint32_t i, j;

	if (tcx == NULL)
		return;

	RTE_LOG(NOTICE, USER1, "%s(lcore=%u, ctx: %p) finish\n",
		__func__, tcx->cf->lcore, tcx->ctx);
	for (i = 0; i != tcx->nb_dev; i++) {
		RTE_LOG(NOTICE, USER1, "%s:%u(port=%u, q=%u, lcore=%u, dev=%p) "
			"rx_stats={"
			"in=%" PRIu64 ",up=%" PRIu64 ",drop=%" PRIu64 "}, "
			"tx_stats={"
			"in=%" PRIu64 ",up=%" PRIu64 ",drop=%" PRIu64 "};\n",
			__func__, i, tcx->dev[i].cf.port, tcx->dev[i].cf.queue,
			tcx->cf->lcore,
			tcx->dev[i].dev,
			tcx->dev[i].rx_stat.in,
			tcx->dev[i].rx_stat.up,
			tcx->dev[i].rx_stat.drop,
			tcx->dev[i].tx_stat.down,
			tcx->dev[i].tx_stat.out,
			tcx->dev[i].tx_stat.drop);
	}

	RTE_LOG(NOTICE, USER1, "tcp_stat={\n");
	for (i = 0; i != RTE_DIM(tcx->tcp_stat.flags); i++) {
		if (tcx->tcp_stat.flags[i] != 0)
			RTE_LOG(NOTICE, USER1, "[flag=%#x]==%" PRIu64 ";\n",
				i, tcx->tcp_stat.flags[i]);
	}
	RTE_LOG(NOTICE, USER1, "};\n");

	for (i = 0; i != tcx->nb_dev; i++)
		for (j = 0; j != tcx->dev[i].tx_buf.num; j++)
			rte_pktmbuf_free(tcx->dev[i].tx_buf.pkt[j]);

}

void
be_stop_port(uint32_t port)
{
	struct rte_eth_stats stats;

	RTE_LOG(NOTICE, USER1, "%s: stoping port %u\n", __func__, port);

	rte_eth_stats_get(port, &stats);
	RTE_LOG(NOTICE, USER1, "port %u stats={\n"
		"ipackets=%" PRIu64 ";"
		"ibytes=%" PRIu64 ";"
		"ierrors=%" PRIu64 ";"
		"imissed=%" PRIu64 ";\n"
		"opackets=%" PRIu64 ";"
		"obytes=%" PRIu64 ";"
		"oerrors=%" PRIu64 ";\n"
		"}\n",
		port,
		stats.ipackets,
		stats.ibytes,
		stats.ierrors,
		stats.imissed,
		stats.opackets,
		stats.obytes,
		stats.oerrors);
	rte_eth_dev_stop(port);
}

int
be_lcore_main(void *arg)
{
	int32_t rc;
	uint32_t lid, i;
	struct tldk_ctx *tcx;
	struct lcore_ctxs_list *lc_ctx;

	lc_ctx = arg;
	lid = rte_lcore_id();

	RTE_LOG(NOTICE, USER1, "%s(lcore=%u) start\n", __func__, lid);

	rc = 0;
	while (force_quit == 0) {
		for (i = 0; i < lc_ctx->nb_ctxs; i++) {
			tcx = lc_ctx->ctxs[i];
			be_lcore_tcp(tcx);
		}
	}

	RTE_LOG(NOTICE, USER1, "%s(lcore=%u) finish\n", __func__, lid);

	return rc;
}

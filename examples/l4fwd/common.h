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

#ifndef COMMON_H_
#define COMMON_H_

#include <rte_arp.h>

static void
sig_handle(int signum)
{
	RTE_LOG(ERR, USER1, "%s(%d)\n", __func__, signum);
	force_quit = 1;
}

static void
netfe_stream_dump(const struct netfe_stream *fes, struct sockaddr_storage *la,
	struct sockaddr_storage *ra)
{
	struct sockaddr_in *l4, *r4;
	struct sockaddr_in6 *l6, *r6;
	uint16_t lport, rport;
	char laddr[INET6_ADDRSTRLEN];
	char raddr[INET6_ADDRSTRLEN];

	if (la->ss_family == AF_INET) {

		l4 = (struct sockaddr_in *)la;
		r4 = (struct sockaddr_in *)ra;

		lport = l4->sin_port;
		rport = r4->sin_port;

	} else if (la->ss_family == AF_INET6) {

		l6 = (struct sockaddr_in6 *)la;
		r6 = (struct sockaddr_in6 *)ra;

		lport = l6->sin6_port;
		rport = r6->sin6_port;

	} else {
		RTE_LOG(ERR, USER1, "stream@%p - unknown family=%hu\n",
			fes->s, la->ss_family);
		return;
	}

	format_addr(la, laddr, sizeof(laddr));
	format_addr(ra, raddr, sizeof(raddr));

	RTE_LOG(INFO, USER1, "stream@%p={s=%p,"
		"family=%hu,proto=%s,laddr=%s,lport=%hu,raddr=%s,rport=%hu;"
		"stats={"
		"rxp=%" PRIu64 ",rxb=%" PRIu64
		",txp=%" PRIu64 ",txb=%" PRIu64
		",drops=%" PRIu64 ","
		"rxev[IDLE, DOWN, UP]=[%" PRIu64 ", %" PRIu64 ", %" PRIu64 "],"
		"txev[IDLE, DOWN, UP]=[%" PRIu64 ", %" PRIu64 ", %" PRIu64 "]"
		"};};\n",
		fes, fes->s, la->ss_family, proto_name[fes->proto],
		laddr, ntohs(lport), raddr, ntohs(rport),
		fes->stat.rxp, fes->stat.rxb,
		fes->stat.txp, fes->stat.txb,
		fes->stat.drops,
		fes->stat.rxev[TLE_SEV_IDLE],
		fes->stat.rxev[TLE_SEV_DOWN],
		fes->stat.rxev[TLE_SEV_UP],
		fes->stat.txev[TLE_SEV_IDLE],
		fes->stat.txev[TLE_SEV_DOWN],
		fes->stat.txev[TLE_SEV_UP]);
}

static inline uint32_t
netfe_get_streams(struct netfe_stream_list *list, struct netfe_stream *rs[],
	uint32_t num)
{
	struct netfe_stream *s;
	uint32_t i, n;

	n = RTE_MIN(list->num, num);
	for (i = 0, s = LIST_FIRST(&list->head);
			i != n;
			i++, s = LIST_NEXT(s, link)) {
		rs[i] = s;
	}

	if (s == NULL)
		/* we retrieved all free entries */
		LIST_INIT(&list->head);
	else
		LIST_FIRST(&list->head) = s;

	list->num -= n;

	return n;
}

static inline struct netfe_stream *
netfe_get_stream(struct netfe_stream_list *list)
{
	struct netfe_stream *s;

	s = NULL;
	if (list->num == 0)
		return s;

	netfe_get_streams(list, &s, 1);

	return s;
}

static inline void
netfe_put_streams(struct netfe_lcore *fe, struct netfe_stream_list *list,
	struct netfe_stream *fs[], uint32_t num)
{
	uint32_t i, n;

	n = RTE_MIN(fe->snum - list->num, num);
	if (n != num)
		RTE_LOG(ERR, USER1, "%s: list overflow by %u\n", __func__,
			num - n);

	for (i = 0; i != n; i++)
		LIST_INSERT_HEAD(&list->head, fs[i], link);
	list->num += n;
}

static inline void
netfe_put_stream(struct netfe_lcore *fe, struct netfe_stream_list *list,
	struct netfe_stream *s)
{
	if (list->num == fe->snum) {
		RTE_LOG(ERR, USER1, "%s: list is full\n", __func__);
		return;
	}

	netfe_put_streams(fe, list, &s, 1);
}

static inline void
netfe_rem_stream(struct netfe_stream_list *list, struct netfe_stream *s)
{
	LIST_REMOVE(s, link);
	list->num--;
}

static void
netfe_stream_close(struct netfe_lcore *fe, struct netfe_stream *fes)
{
	tle_stream_close(fes->s);
	tle_event_free(fes->txev);
	tle_event_free(fes->rxev);
	tle_event_free(fes->erev);
	memset(fes, 0, sizeof(*fes));
	netfe_put_stream(fe, &fe->free, fes);
}

/*
 * Helper functions, verify the queue for corresponding UDP port.
 */
static uint8_t
verify_queue_for_port(const struct netbe_dev *prtq, const uint16_t lport)
{
	uint32_t align_nb_q, qid;

	align_nb_q = rte_align32pow2(prtq->port.nb_lcore);
	qid = (lport % align_nb_q) % prtq->port.nb_lcore;
	if (prtq->rxqid == qid)
		return 1;

	return 0;
}

static inline size_t
pkt_buf_empty(struct pkt_buf *pb)
{
	uint32_t i;
	size_t x;

	x = 0;
	for (i = 0; i != pb->num; i++) {
		x += pb->pkt[i]->pkt_len;
		NETFE_PKT_DUMP(pb->pkt[i]);
		rte_pktmbuf_free(pb->pkt[i]);
	}

	pb->num = 0;
	return x;
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

static int
netbe_lcore_setup(struct netbe_lcore *lc)
{
	uint32_t i;
	int32_t rc;

	RTE_LOG(NOTICE, USER1, "%s:(lcore=%u, proto=%s, ctx=%p) start\n",
		__func__, lc->id, proto_name[lc->proto], lc->ctx);

	/*
	 * ???????
	 * wait for FE lcores to start, so BE dont' drop any packets
	 * because corresponding streams not opened yet by FE.
	 * useful when used with pcap PMDS.
	 * think better way, or should this timeout be a cmdlien parameter.
	 * ???????
	 */
	rte_delay_ms(10);

	rc = 0;
	for (i = 0; i != lc->prtq_num && rc == 0; i++) {
		RTE_LOG(NOTICE, USER1,
			"%s:%u(port=%u, q=%u, proto=%s, dev=%p)\n",
			__func__, i, lc->prtq[i].port.id, lc->prtq[i].rxqid,
			proto_name[lc->proto], lc->prtq[i].dev);

		rc = setup_rx_cb(&lc->prtq[i].port, lc, lc->prtq[i].rxqid,
			becfg.arp);
		if (rc < 0)
			return rc;
	}

	if (rc == 0)
		RTE_PER_LCORE(_be) = lc;
	return rc;
}

static void
netbe_lcore_clear(void)
{
	uint32_t i, j;
	struct netbe_lcore *lc;

	lc = RTE_PER_LCORE(_be);
	if (lc == NULL)
		return;

	RTE_LOG(NOTICE, USER1, "%s(lcore=%u, proto=%s, ctx: %p) finish\n",
		__func__, lc->id, proto_name[lc->proto], lc->ctx);
	for (i = 0; i != lc->prtq_num; i++) {
		RTE_LOG(NOTICE, USER1, "%s:%u(port=%u, q=%u, lcore=%u, dev=%p) "
			"rx_stats={"
			"in=%" PRIu64 ",up=%" PRIu64 ",drop=%" PRIu64 "}, "
			"tx_stats={"
			"in=%" PRIu64 ",up=%" PRIu64 ",drop=%" PRIu64 "};\n",
			__func__, i, lc->prtq[i].port.id, lc->prtq[i].rxqid,
			lc->id,
			lc->prtq[i].dev,
			lc->prtq[i].rx_stat.in,
			lc->prtq[i].rx_stat.up,
			lc->prtq[i].rx_stat.drop,
			lc->prtq[i].tx_stat.down,
			lc->prtq[i].tx_stat.out,
			lc->prtq[i].tx_stat.drop);
	}

	RTE_LOG(NOTICE, USER1, "tcp_stat={\n");
	for (i = 0; i != RTE_DIM(lc->tcp_stat.flags); i++) {
		if (lc->tcp_stat.flags[i] != 0)
			RTE_LOG(NOTICE, USER1, "[flag=%#x]==%" PRIu64 ";\n",
				i, lc->tcp_stat.flags[i]);
	}
	RTE_LOG(NOTICE, USER1, "};\n");

	for (i = 0; i != lc->prtq_num; i++)
		for (j = 0; j != lc->prtq[i].tx_buf.num; j++)
			rte_pktmbuf_free(lc->prtq[i].tx_buf.pkt[j]);

	RTE_PER_LCORE(_be) = NULL;
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

static void
fill_dst(struct tle_dest *dst, struct netbe_dev *bed,
	const struct netbe_dest *bdp, uint16_t l3_type, int32_t sid,
	uint8_t proto_id)
{
	struct rte_ether_hdr *eth;
	struct rte_ipv4_hdr *ip4h;
	struct rte_ipv6_hdr *ip6h;

	dst->dev = bed->dev;
	dst->head_mp = frag_mpool[sid + 1];
	dst->mtu = RTE_MIN(bdp->mtu, bed->port.mtu);
	dst->l2_len = sizeof(*eth);

	eth = (struct rte_ether_hdr *)dst->hdr;

	rte_ether_addr_copy(&bed->port.mac, &eth->src_addr);
	rte_ether_addr_copy(&bdp->mac, &eth->dst_addr);
	eth->ether_type = rte_cpu_to_be_16(l3_type);

	if (l3_type == RTE_ETHER_TYPE_IPV4) {
		dst->l3_len = sizeof(*ip4h);
		ip4h = (struct rte_ipv4_hdr *)(eth + 1);
		ip4h->version_ihl = 4 << 4 |
			sizeof(*ip4h) / RTE_IPV4_IHL_MULTIPLIER;
		ip4h->time_to_live = 64;
		ip4h->next_proto_id = proto_id;
	} else if (l3_type == RTE_ETHER_TYPE_IPV6) {
		dst->l3_len = sizeof(*ip6h);
		ip6h = (struct rte_ipv6_hdr *)(eth + 1);
		ip6h->vtc_flow = 6 << 4;
		ip6h->proto = proto_id;
		ip6h->hop_limits = 64;
	}
}

static int
netbe_add_dest(struct netbe_lcore *lc, uint32_t dev_idx, uint16_t family,
	const struct netbe_dest *dst, uint32_t dnum)
{
	int32_t rc, sid;
	uint8_t proto;
	uint16_t l3_type;
	uint32_t i, n, m;
	struct tle_dest *dp;

	if (family == AF_INET) {
		n = lc->dst4_num;
		dp = lc->dst4 + n;
		m = RTE_DIM(lc->dst4);
		l3_type = RTE_ETHER_TYPE_IPV4;
	} else {
		n = lc->dst6_num;
		dp = lc->dst6 + n;
		m = RTE_DIM(lc->dst6);
		l3_type = RTE_ETHER_TYPE_IPV6;
	}

	if (n + dnum >= m) {
		RTE_LOG(ERR, USER1, "%s(lcore=%u, family=%hu, dnum=%u) exceeds "
			"maximum allowed number of destinations(%u);\n",
			__func__, lc->id, family, dnum, m);
		return -ENOSPC;
	}

	sid = rte_lcore_to_socket_id(lc->id);
	proto = (becfg.proto == TLE_PROTO_UDP) ? IPPROTO_UDP : IPPROTO_TCP;
	rc = 0;

	for (i = 0; i != dnum && rc == 0; i++) {
		fill_dst(dp + i, lc->prtq + dev_idx, dst + i, l3_type, sid,
			proto);
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

static inline void
fill_arp_reply(struct netbe_dev *dev, struct rte_mbuf *m)
{
	struct rte_ether_hdr *eth;
	struct rte_arp_hdr *ahdr;
	struct rte_arp_ipv4 *adata;
	uint32_t tip;

	/* set up the ethernet data */
	eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	eth->dst_addr = eth->src_addr;
	eth->src_addr = dev->port.mac;

	/* set up the arp data */
	ahdr = rte_pktmbuf_mtod_offset(m, struct rte_arp_hdr *, m->l2_len);
	adata = &ahdr->arp_data;

	ahdr->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);

	tip = adata->arp_tip;
	adata->arp_tip = adata->arp_sip;
	adata->arp_sip = tip;

	adata->arp_tha = adata->arp_sha;
	adata->arp_sha = dev->port.mac;
}

/* this is a semi ARP response implementation of RFC 826
 * in RFC, it algo is as below
 *
 * ?Do I have the hardware type in ar$hrd?
 * Yes: (almost definitely)
 * [optionally check the hardware length ar$hln]
 * ?Do I speak the protocol in ar$pro?
 * Yes:
 *  [optionally check the protocol length ar$pln]
 *  Merge_flag := false
 *  If the pair <protocol type, sender protocol address> is
 *      already in my translation table, update the sender
 *      hardware address field of the entry with the new
 *      information in the packet and set Merge_flag to true.
 *  ?Am I the target protocol address?
 *  Yes:
 *    If Merge_flag is false, add the triplet <protocol type,
 *        sender protocol address, sender hardware address> to
 *        the translation table.
 *    ?Is the opcode ares_op$REQUEST?  (NOW look at the opcode!!)
 *    Yes:
 *      Swap hardware and protocol fields, putting the local
 *          hardware and protocol addresses in the sender fields.
 *      Set the ar$op field to ares_op$REPLY
 *      Send the packet to the (new) target hardware address on
 *          the same hardware on which the request was received.
 *
 * So, in our implementation we skip updating the local cache,
 * we assume that local cache is ok, so we just reply the packet.
 */

static inline void
send_arp_reply(struct netbe_dev *dev, struct pkt_buf *pb)
{
	uint32_t i, n, num;
	struct rte_mbuf **m;

	m = pb->pkt;
	num = pb->num;
	for (i = 0; i != num; i++) {
		fill_arp_reply(dev, m[i]);
		NETBE_PKT_DUMP(m[i]);
	}

	n = rte_eth_tx_burst(dev->port.id, dev->txqid, m, num);
	NETBE_TRACE("%s: sent n=%u arp replies\n", __func__, n);

	/* free mbufs with unsent arp response */
	for (i = n; i != num; i++)
		rte_pktmbuf_free(m[i]);

	pb->num = 0;
}

static inline void
netbe_rx(struct netbe_lcore *lc, uint32_t pidx)
{
	uint32_t j, k, n;
	struct rte_mbuf *pkt[MAX_PKT_BURST];
	struct rte_mbuf *rp[MAX_PKT_BURST];
	int32_t rc[MAX_PKT_BURST];
	struct pkt_buf *abuf;

	n = rte_eth_rx_burst(lc->prtq[pidx].port.id,
			lc->prtq[pidx].rxqid, pkt, RTE_DIM(pkt));

	if (n != 0) {
		lc->prtq[pidx].rx_stat.in += n;
		NETBE_TRACE("%s(%u): rte_eth_rx_burst(%u, %u) returns %u\n",
			__func__, lc->id, lc->prtq[pidx].port.id,
			lc->prtq[pidx].rxqid, n);

		k = tle_rx_bulk(lc->prtq[pidx].dev, pkt, rp, rc, n);

		lc->prtq[pidx].rx_stat.up += k;
		lc->prtq[pidx].rx_stat.drop += n - k;
		NETBE_TRACE("%s(%u): tle_%s_rx_bulk(%p, %u) returns %u\n",
			__func__, lc->id, proto_name[lc->proto],
			lc->prtq[pidx].dev, n, k);

		for (j = 0; j != n - k; j++) {
			NETBE_TRACE("%s:%d(port=%u) rp[%u]={%p, %d};\n",
				__func__, __LINE__, lc->prtq[pidx].port.id,
				j, rp[j], rc[j]);
			rte_pktmbuf_free(rp[j]);
		}
	}

	/* respond to incoming arp requests */
	abuf = &lc->prtq[pidx].arp_buf;
	if (abuf->num == 0)
		return;

	send_arp_reply(&lc->prtq[pidx], abuf);
}

static inline void
netbe_tx(struct netbe_lcore *lc, uint32_t pidx)
{
	uint32_t j, k, n;
	struct rte_mbuf **mb;

	n = lc->prtq[pidx].tx_buf.num;
	k = RTE_DIM(lc->prtq[pidx].tx_buf.pkt) - n;
	mb = lc->prtq[pidx].tx_buf.pkt;

	if (k >= RTE_DIM(lc->prtq[pidx].tx_buf.pkt) / 2) {
		j = tle_tx_bulk(lc->prtq[pidx].dev, mb + n, k);
		n += j;
		lc->prtq[pidx].tx_stat.down += j;
	}

	if (n == 0)
		return;

	NETBE_TRACE("%s(%u): tle_%s_tx_bulk(%p) returns %u,\n"
		"total pkts to send: %u\n",
		__func__, lc->id, proto_name[lc->proto],
		lc->prtq[pidx].dev, j, n);

	for (j = 0; j != n; j++)
		NETBE_PKT_DUMP(mb[j]);

	k = rte_eth_tx_burst(lc->prtq[pidx].port.id,
			lc->prtq[pidx].txqid, mb, n);

	lc->prtq[pidx].tx_stat.out += k;
	lc->prtq[pidx].tx_stat.drop += n - k;
	NETBE_TRACE("%s(%u): rte_eth_tx_burst(%u, %u, %u) returns %u\n",
		__func__, lc->id, lc->prtq[pidx].port.id, lc->prtq[pidx].txqid,
		n, k);

	lc->prtq[pidx].tx_buf.num = n - k;
	if (k != 0)
		for (j = k; j != n; j++)
			mb[j - k] = mb[j];
}

static inline void
netbe_lcore(void)
{
	uint32_t i;
	struct netbe_lcore *lc;

	lc = RTE_PER_LCORE(_be);
	if (lc == NULL)
		return;

	for (i = 0; i != lc->prtq_num; i++) {
		netbe_rx(lc, i);
		netbe_tx(lc, i);
	}
}

static inline int
netfe_rxtx_get_mss(struct netfe_stream *fes)
{
	switch (fes->proto) {
	case TLE_PROTO_TCP:
		return tle_tcp_stream_get_mss(fes->s);

	case TLE_PROTO_UDP:
		/* The UDP code doesn't have MSS discovery, so have to
		 * assume arbitary MTU. Going to use default mbuf
		 * data space as TLDK uses this internally as a
		 * maximum segment size.
		 */
		return RTE_MBUF_DEFAULT_DATAROOM - TLE_DST_MAX_HDR;
	default:
		return -EINVAL;
	}
}

static inline int
netfe_rxtx_dispatch_reply(uint32_t lcore, struct netfe_stream *fes)
{
	struct pkt_buf *pb;
	int32_t sid;
	uint32_t n;
	uint32_t cnt_mtu_pkts;
	uint32_t cnt_all_pkts;
	uint32_t idx_pkt;
	uint32_t len_tail;
	uint32_t mtu;
	size_t csz, len;
	char *dst;
	const uint8_t *src;

	pb = &fes->pbuf;
	sid = rte_lcore_to_socket_id(lcore) + 1;
	mtu = netfe_rxtx_get_mss(fes);

	cnt_mtu_pkts = (fes->txlen / mtu);
	cnt_all_pkts = cnt_mtu_pkts;
	len_tail = fes->txlen - (mtu * cnt_mtu_pkts);

	if (len_tail > 0)
		cnt_all_pkts++;

	if (pb->num + cnt_all_pkts >= RTE_DIM(pb->pkt)) {
		NETFE_TRACE("%s(%u): Insufficent space for outbound burst\n",
			__func__, lcore);
		return -ENOMEM;
	}
	if (rte_pktmbuf_alloc_bulk(mpool[sid], &pb->pkt[pb->num], cnt_all_pkts)
			!= 0) {
		NETFE_TRACE("%s(%u): rte_pktmbuf_alloc_bulk() failed\n",
			__func__, lcore);
		return -ENOMEM;
	}

	csz = tx_content.sz;
	src = tx_content.data;

	n = pb->num;

	/* Full MTU packets */
	for (idx_pkt = 0; idx_pkt < cnt_mtu_pkts; idx_pkt++, n++) {
		rte_pktmbuf_reset(pb->pkt[n]);
		dst = rte_pktmbuf_append(pb->pkt[n], mtu);
		if (csz > 0) {
			len = RTE_MIN(mtu, csz);
			rte_memcpy(dst, src, len);
			src += len;
			csz -= len;
		}
	}

	/* Last non-MTU packet, if any */
	if (len_tail > 0) {
		rte_pktmbuf_reset(pb->pkt[n]);
		dst = rte_pktmbuf_append(pb->pkt[n], len_tail);
		if (csz > 0) {
			len = RTE_MIN(len_tail, csz);
			rte_memcpy(dst, src, len);
			src += len;
			csz -= len;
		}
		n++;
	}

	pb->num = n;

	return 0;
}

static inline int
netfe_rx_process(uint32_t lcore, struct netfe_stream *fes)
{
	uint32_t k, n;
	uint64_t count_bytes;

	n = fes->pbuf.num;
	k = RTE_DIM(fes->pbuf.pkt) - n;

	/* packet buffer is full, can't receive any new packets. */
	if (k == 0) {
		tle_event_idle(fes->rxev);
		fes->stat.rxev[TLE_SEV_IDLE]++;
		return 0;
	}

	n = tle_stream_recv(fes->s, fes->pbuf.pkt + n, k);
	if (n == 0)
		return 0;

	NETFE_TRACE("%s(%u): tle_%s_stream_recv(%p, %u) returns %u\n",
		__func__, lcore, proto_name[fes->proto], fes->s, k, n);

	fes->pbuf.num += n;
	fes->stat.rxp += n;

	/* free all received mbufs. */
	if (fes->op == RXONLY)
		fes->stat.rxb += pkt_buf_empty(&fes->pbuf);
	else if (fes->op == RXTX) {
		/* RXTX mode. Count incoming bytes then discard.
		 * If receive threshold (rxlen) exceeded, send out a packet.
		 */
		count_bytes = pkt_buf_empty(&fes->pbuf);
		fes->stat.rxb += count_bytes;
		fes->rx_run_len += count_bytes;
		if (fes->rx_run_len >= fes->rxlen) {
			/* Idle Rx as buffer needed for Tx */
			tle_event_idle(fes->rxev);
			fes->stat.rxev[TLE_SEV_IDLE]++;

			/* Discard surplus bytes. For now pipelining of
			 * requests is not supported.
			 */
			fes->rx_run_len = 0;
			netfe_rxtx_dispatch_reply(lcore, fes);

			/* Kick off a Tx event */
			tle_event_active(fes->txev, TLE_SEV_UP);
			fes->stat.txev[TLE_SEV_UP]++;
		}
	}
	/* mark stream as writable */
	else if (k == RTE_DIM(fes->pbuf.pkt)) {
		if (fes->op == ECHO) {
			tle_event_active(fes->txev, TLE_SEV_UP);
			fes->stat.txev[TLE_SEV_UP]++;
		} else if (fes->op == FWD) {
			tle_event_raise(fes->txev);
			fes->stat.txev[TLE_SEV_UP]++;
		}
	}

	return n;
}

#endif /* COMMON_H_ */

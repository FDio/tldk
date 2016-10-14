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

static void
sig_handle(int signum)
{
	RTE_LOG(ERR, USER1, "%s(%d)\n", __func__, signum);
	force_quit = 1;
}

#define FILL_STREAM_PARAM(p, la, ra, rev, sev) \
do { \
	memset(&(p), 0, sizeof((p))); \
	(p).local_addr = (la); \
	(p).remote_addr = (ra); \
	(p).recv_ev = (rev); \
	(p).send_ev = (sev); \
} while (0)

static void
netfe_stream_close(struct netfe_lcore *fe, uint32_t dec)
{
	uint32_t sidx;

	fe->sidx -= dec;
	sidx = fe->sidx;
	tle_event_free(fe->fs[sidx].txev);
	tle_event_free(fe->fs[sidx].rxev);
	tle_stream_close(fe->fs[sidx].s);
	memset(&fe->fs[sidx], 0, sizeof(fe->fs[sidx]));
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
		RTE_LOG(NOTICE, USER1, "%s:%u(port=%u, q=%u, proto=%s, dev: %p)\n",
			__func__, i, lc->prtq[i].port.id, lc->prtq[i].rxqid,
			proto_name[lc->proto], lc->prtq[i].dev);

		rc = setup_rx_cb(&lc->prtq[i].port, lc, lc->prtq[i].rxqid);
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
			__func__, i, lc->prtq[i].port.id, lc->prtq[i].rxqid, lc->id,
			lc->prtq[i].dev,
			lc->prtq[i].rx_stat.in,
			lc->prtq[i].rx_stat.up,
			lc->prtq[i].rx_stat.drop,
			lc->prtq[i].tx_stat.down,
			lc->prtq[i].tx_stat.out,
			lc->prtq[i].tx_stat.drop);
	}

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

#endif /* COMMON_H_ */

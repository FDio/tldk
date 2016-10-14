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

#ifndef UDP_H_
#define UDP_H_

static void
netfe_stream_dump_udp(const struct netfe_stream *fes)
{
	struct sockaddr_in *l4, *r4;
	struct sockaddr_in6 *l6, *r6;
	uint16_t lport, rport;
	struct tle_udp_stream_param uprm;
	struct sockaddr_storage *la, *ra;
	char laddr[INET6_ADDRSTRLEN];
	char raddr[INET6_ADDRSTRLEN];

	tle_udp_stream_get_param(fes->s, &uprm);
	la = &uprm.local_addr;
	ra = &uprm.remote_addr;

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

	RTE_LOG(INFO, USER1,
		"stream@%p={"
		"family=%hu,proto=%s,laddr=%s,lport=%hu,raddr=%s,rport=%hu;"
		"stats={"
		"rxp=%" PRIu64 ",txp=%" PRIu64 ",drops=%" PRIu64 ","
		"rxev[IDLE, DOWN, UP]=[%" PRIu64 ", %" PRIu64 ", %" PRIu64 "],"
		"txev[IDLE, DOWN, UP]=[%" PRIu64 ", %" PRIu64 ", %" PRIu64 "],"
		"}};\n",
		fes->s, la->ss_family, proto_name[fes->proto],
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
netfe_stream_open_udp(struct netfe_lcore *fe, struct netfe_sprm *sprm,
	uint32_t lcore, uint16_t op, uint32_t bidx)
{
	int32_t rc;
	uint32_t sidx;
	struct netfe_stream *fes;
	struct sockaddr_in *l4;
	struct sockaddr_in6 *l6;
	uint16_t errport;
	struct tle_udp_stream_param uprm;

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

	RTE_LOG(ERR, USER1,
		"%s(%u) [%u]={op=%hu, proto=%s, rxev=%p, txev=%p}, belc=%u\n",
		__func__, lcore, sidx, op, proto_name[becfg.proto],
		fes->rxev, fes->txev, becfg.cpu[bidx].id);
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

	FILL_STREAM_PARAM(uprm, sprm->local_addr, sprm->remote_addr,
		sprm->recv_ev, sprm->send_ev);
	fes->s = tle_udp_stream_open(becfg.cpu[bidx].ctx, &uprm);

	if (fes->s == NULL) {
		rc = rte_errno;
		netfe_stream_close(fe, 0);
		rte_errno = rc;

		if (sprm->local_addr.ss_family == AF_INET) {
			l4 = (struct sockaddr_in *) &sprm->local_addr;
			errport = ntohs(l4->sin_port);
		} else {
			l6 = (struct sockaddr_in6 *) &sprm->local_addr;
			errport = ntohs(l6->sin6_port);
		}

		RTE_LOG(ERR, USER1, "stream open failed for port %u with error "
			"code=%u, bidx=%u, lc=%u\n",
			errport, rc, bidx, becfg.cpu[bidx].id);
		return NULL;
	}

	fes->op = op;
	fes->proto = becfg.proto;
	fes->family = sprm->local_addr.ss_family;

	fe->sidx = sidx + 1;
	return fes;
}

static int
netfe_lcore_init_udp(const struct netfe_lcore_prm *prm)
{
	size_t sz;
	int32_t rc;
	uint32_t i, lcore, snum;
	struct netfe_lcore *fe;
	struct tle_evq_param eprm;
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
		fes = netfe_stream_open_udp(fe, &prm->stream[i].sprm, lcore,
			prm->stream[i].op, prm->stream[i].sprm.bidx);
		if (fes == NULL) {
			rc = -rte_errno;
			break;
		}

		netfe_stream_dump_udp(fes);

		if (prm->stream[i].op == FWD) {
			fes->fwdprm = prm->stream[i].fprm;
			rc = fwd_tbl_add(fe,
				prm->stream[i].fprm.remote_addr.ss_family,
				(const struct sockaddr *)
				&prm->stream[i].fprm.remote_addr,
				fes);
			if (rc != 0) {
				netfe_stream_close(fe, 1);
				break;
			}
		} else if (prm->stream[i].op == TXONLY) {
			fes->txlen = prm->stream[i].txlen;
			fes->raddr = prm->stream[i].sprm.remote_addr;
		}
	}

	return rc;
}

static void
fill_dst_udp(struct tle_dest *dst, struct netbe_dev *bed,
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

static inline void
netfe_pkt_addr_udp(const struct rte_mbuf *m, struct sockaddr_storage *ps,
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
pkt_eq_addr_udp(struct rte_mbuf *pkt[], uint32_t num, uint16_t family,
	struct sockaddr_storage *cur, struct sockaddr_storage *nxt)
{
	uint32_t i;

	for (i = 0; i != num; i++) {
		netfe_pkt_addr_udp(pkt[i], nxt, family);
		if (netfe_addr_eq(cur, nxt, family) == 0)
			break;
	}

	return i;
}

static struct netfe_stream *
find_fwd_dst_udp(uint32_t lcore, struct netfe_stream *fes,
	const struct sockaddr *sa)
{
	uint32_t rc;
	struct netfe_stream *fed;
	struct netfe_lcore *fe;

	fe = RTE_PER_LCORE(_fe);

	fed = fwd_tbl_lkp(fe, fes->family, sa);
	if (fed != NULL)
		return fed;

	/* create a new stream and put it into the fwd table. */

	/* open forward stream with wildcard remote addr. */
	memset(&fes->fwdprm.remote_addr.ss_family + 1, 0,
		sizeof(fes->fwdprm.remote_addr) -
		sizeof(fes->fwdprm.remote_addr.ss_family));

	fed = netfe_stream_open_udp(fe, &fes->fwdprm, lcore, FWD,
		fes->fwdprm.bidx);
	if (fed == NULL)
		return NULL;

	rc = fwd_tbl_add(fe, fes->family, sa, fed);
	if (rc != 0) {
		netfe_stream_close(fe, 1);
		fed = NULL;
	}

	fed->fwdprm.remote_addr = *(const struct sockaddr_storage *)sa;
	return fed;
}

static inline void
netfe_fwd_udp(uint32_t lcore, struct netfe_stream *fes)
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

	netfe_pkt_addr_udp(pkt[0], pi0, family);

	x = 0;
	for (i = 0; i != n; i = j) {

		j = i + pkt_eq_addr_udp(&pkt[i + 1],
			n - i - 1, family, pi0, pi1) + 1;

		fed = find_fwd_dst_udp(lcore, fes, (const struct sockaddr *)pi0);
		if (fed != NULL) {

			/**
			 * TODO: cannot use function pointers for unequal param num.
			 */
			k = tle_udp_stream_send(fed->s, pkt + i, j - i,
				(const struct sockaddr *)
				&fes->fwdprm.remote_addr);

			NETFE_TRACE("%s(%u): tle_%s_stream_send(%p, %u) "
				"returns %u\n",
				__func__, lcore, proto_name[fes->proto],
				fed->s, j - i, k);

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
netfe_rx_process_udp(__rte_unused uint32_t lcore, struct netfe_stream *fes)
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

	NETFE_TRACE("%s(%u): tle_%s_stream_recv(%p, %u) returns %u\n",
		__func__, lcore, proto_name[fes->proto], fes->s, k, n);

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
netfe_rxtx_process_udp(__rte_unused uint32_t lcore, struct netfe_stream *fes)
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

	netfe_pkt_addr_udp(pkt[0], pi0, family);

	for (i = 0; i != n; i = j) {

		j = i + pkt_eq_addr_udp(&pkt[i + 1],
			n - i - 1, family, pi0, pi1) + 1;

		/**
		 * TODO: cannot use function pointers for unequal param num.
		 */
		k = tle_udp_stream_send(fes->s, pkt + i, j - i,
			(const struct sockaddr *)pi0);

		NETFE_TRACE("%s(%u): tle_%s_stream_send(%p, %u) returns %u\n",
			__func__, lcore, proto_name[fes->proto],
			fes->s, j - i, k);
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

static inline void
netfe_tx_process_udp(uint32_t lcore, struct netfe_stream *fes)
{
	uint32_t i, k, n;

	/* refill with new mbufs. */
	pkt_buf_fill(lcore, &fes->pbuf, fes->txlen);

	n = fes->pbuf.num;
	if (n == 0)
		return;

	/**
	 * TODO: cannot use function pointers for unequal param num.
	 */
	k = tle_udp_stream_send(fes->s, fes->pbuf.pkt, n, NULL);
	NETFE_TRACE("%s(%u): tle_%s_stream_send(%p, %u) returns %u\n",
		__func__, lcore, proto_name[fes->proto], fes->s, n, k);
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
netfe_lcore_udp(void)
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
			netfe_rx_process_udp(lcore, fs[j]);
	}

	n = tle_evq_get(fe->txeq, (const void **)(uintptr_t)fs, RTE_DIM(fs));

	if (n != 0) {
		NETFE_TRACE("%s(%u): tle_evq_get(txevq=%p) returns %u\n",
			__func__, lcore, fe->txeq, n);
		for (j = 0; j != n; j++) {
			if (fs[j]->op == RXTX)
				netfe_rxtx_process_udp(lcore, fs[j]);
			else if (fs[j]->op == FWD)
				netfe_fwd_udp(lcore, fs[j]);
			else if (fs[j]->op == TXONLY)
				netfe_tx_process_udp(lcore, fs[j]);
		}
	}
}

static inline void
netbe_rx_udp(struct netbe_lcore *lc, uint32_t pidx)
{
	uint32_t j, k, n;
	struct rte_mbuf *pkt[MAX_PKT_BURST];
	struct rte_mbuf *rp[MAX_PKT_BURST];
	int32_t rc[MAX_PKT_BURST];

	n = rte_eth_rx_burst(lc->prtq[pidx].port.id,
			lc->prtq[pidx].rxqid, pkt, RTE_DIM(pkt));
	if (n == 0)
		return;

	lc->prtq[pidx].rx_stat.in += n;
	NETBE_TRACE("%s(%u): rte_eth_rx_burst(%u, %u) returns %u\n",
		__func__, lc->id, lc->prtq[pidx].port.id, lc->prtq[pidx].rxqid,
		n);

	k = tle_udp_rx_bulk(lc->prtq[pidx].dev, pkt, rp, rc, n);

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

static inline void
netbe_tx_udp(struct netbe_lcore *lc, uint32_t pidx)
{
	uint32_t j, k, n;
	struct rte_mbuf **mb;

	n = lc->prtq[pidx].tx_buf.num;
	k = RTE_DIM(lc->prtq[pidx].tx_buf.pkt) - n;
	mb = lc->prtq[pidx].tx_buf.pkt;

	if (k >= RTE_DIM(lc->prtq[pidx].tx_buf.pkt) / 2) {
		j = tle_udp_tx_bulk(lc->prtq[pidx].dev, mb + n, k);
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
netbe_lcore_udp(void)
{
	uint32_t i;
	struct netbe_lcore *lc;

	lc = RTE_PER_LCORE(_be);
	if (lc == NULL)
		return;

	for (i = 0; i != lc->prtq_num; i++) {
		netbe_rx_udp(lc, i);
		netbe_tx_udp(lc, i);
	}
}

static void
netfe_lcore_fini_udp(void)
{
	struct netfe_lcore *fe;
	uint32_t i;

	fe = RTE_PER_LCORE(_fe);
	if (fe == NULL)
		return;

	while (fe->sidx != 0) {
		i = fe->sidx - 1;
		netfe_stream_dump_udp(fe->fs + i);
		netfe_stream_close(fe, 1);
	}

	tle_evq_destroy(fe->txeq);
	tle_evq_destroy(fe->rxeq);
	RTE_PER_LCORE(_fe) = NULL;
	rte_free(fe);
}

static int
lcore_main_udp(void *arg)
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
		rc = netfe_lcore_init_udp(&prm->fe);

	/* lcore FE init. */
	if (rc == 0 && prm->be.lc != NULL)
		rc = netbe_lcore_setup(prm->be.lc);

	if (rc != 0)
		sig_handle(SIGQUIT);

	while (force_quit == 0) {
		netfe_lcore_udp();
		netbe_lcore_udp();
	}

	RTE_LOG(NOTICE, USER1, "%s(lcore=%u) finish\n",
		__func__, lcore);

	netfe_lcore_fini_udp();
	netbe_lcore_clear();

	return rc;
}

static int
netbe_add_dest_udp(struct netbe_lcore *lc, uint32_t dev_idx, uint16_t family,
	const struct netbe_dest *dst, uint32_t dnum)
{
	int32_t rc, sid;
	uint16_t l3_type;
	uint32_t i, n, m;
	struct tle_dest *dp;

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
		fill_dst_udp(dp + i, lc->prtq + dev_idx, dst + i, l3_type, sid);
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
netbe_dest_init_udp(const char *fname, struct netbe_cfg *cfg)
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
					rc = netbe_add_dest_udp(lc, l, f,
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

#endif /* UDP_H_ */

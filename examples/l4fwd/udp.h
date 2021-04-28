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

/*
 * helper function: opens IPv4 and IPv6 streams for selected port.
 */
static struct netfe_stream *
netfe_stream_open_udp(struct netfe_lcore *fe, struct netfe_sprm *sprm,
	uint32_t lcore, uint16_t op, uint32_t bidx)
{
	int32_t rc;
	struct netfe_stream *fes;
	struct sockaddr_in *l4;
	struct sockaddr_in6 *l6;
	uint16_t errport;
	struct tle_udp_stream_param uprm;

	fes = netfe_get_stream(&fe->free);
	if (fes == NULL) {
		rte_errno = ENOBUFS;
		return NULL;
	}

	fes->rxev = tle_event_alloc(fe->rxeq, fes);
	fes->txev = tle_event_alloc(fe->txeq, fes);

	if (fes->rxev == NULL || fes->txev == NULL) {
		netfe_stream_close(fe, fes);
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

	memset(&uprm, 0, sizeof(uprm));
	uprm.local_addr = sprm->local_addr;
	uprm.remote_addr = sprm->remote_addr;
	uprm.recv_ev = fes->rxev;
	if (op != FWD)
		uprm.send_ev = fes->txev;
	fes->s = tle_udp_stream_open(becfg.cpu[bidx].ctx, &uprm);

	if (fes->s == NULL) {
		rc = rte_errno;
		netfe_stream_close(fe, fes);
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

	RTE_LOG(NOTICE, USER1,
		"%s(%u)={s=%p, op=%hu, proto=%s, rxev=%p, txev=%p}, belc=%u\n",
		__func__, lcore, fes->s, op, proto_name[becfg.proto],
		fes->rxev, fes->txev, becfg.cpu[bidx].id);

	fes->op = op;
	fes->proto = becfg.proto;
	fes->family = sprm->local_addr.ss_family;

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
	struct netfe_sprm *sprm;

	lcore = rte_lcore_id();

	snum = prm->max_streams;
	RTE_LOG(NOTICE, USER1, "%s(lcore=%u, nb_streams=%u, max_streams=%u)\n",
		__func__, lcore, prm->nb_streams, snum);

	memset(&eprm, 0, sizeof(eprm));
	eprm.socket_id = rte_lcore_to_socket_id(lcore);
	eprm.max_events = snum;

	sz = sizeof(*fe) + snum * sizeof(struct netfe_stream);
	fe = rte_zmalloc_socket(NULL, sz, RTE_CACHE_LINE_SIZE,
		rte_lcore_to_socket_id(lcore));

	if (fe == NULL) {
		RTE_LOG(ERR, USER1, "%s:%d failed to allocate %zu bytes\n",
			__func__, __LINE__, sz);
		return -ENOMEM;
	}

	RTE_PER_LCORE(_fe) = fe;

	fe->snum = snum;
	/* initialize the stream pool */
	LIST_INIT(&fe->free.head);
	LIST_INIT(&fe->use.head);
	fes = (struct netfe_stream *)(fe + 1);
	for (i = 0; i != snum; i++, fes++)
		netfe_put_stream(fe, &fe->free, fes);

	/* allocate the event queues */
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
		sprm = &prm->stream[i].sprm;
		fes = netfe_stream_open_udp(fe, sprm, lcore, prm->stream[i].op,
			sprm->bidx);
		if (fes == NULL) {
			rc = -rte_errno;
			break;
		}

		netfe_stream_dump(fes, &sprm->local_addr, &sprm->remote_addr);

		if (prm->stream[i].op == FWD) {
			fes->fwdprm = prm->stream[i].fprm;
			rc = fwd_tbl_add(fe,
				prm->stream[i].fprm.remote_addr.ss_family,
				(const struct sockaddr *)
				&prm->stream[i].fprm.remote_addr,
				fes);
			if (rc != 0) {
				netfe_stream_close(fe, fes);
				break;
			}
		} else if (prm->stream[i].op == TXONLY) {
			fes->txlen = prm->stream[i].txlen;
			fes->raddr = prm->stream[i].sprm.remote_addr;
		}
	}

	return rc;
}

static struct netfe_stream *
find_fwd_dst_udp(uint32_t lcore, struct netfe_stream *fes,
	const struct sockaddr *sa)
{
	uint32_t rc;
	struct netfe_stream *fed;
	struct netfe_lcore *fe;
	struct tle_udp_stream_param uprm;

	fe = RTE_PER_LCORE(_fe);

	fed = fwd_tbl_lkp(fe, fes->family, sa);
	if (fed != NULL)
		return fed;

	/* create a new stream and put it into the fwd table. */
	memset(&uprm, 0, sizeof(uprm));
	uprm.local_addr = fes->fwdprm.local_addr;
	uprm.remote_addr = fes->fwdprm.remote_addr;

	/* open forward stream with wildcard remote addr. */
	memset(&uprm.remote_addr.ss_family + 1, 0,
		sizeof(uprm.remote_addr) - sizeof(uprm.remote_addr.ss_family));

	fed = netfe_stream_open_udp(fe, &fes->fwdprm, lcore, FWD,
		fes->fwdprm.bidx);
	if (fed == NULL)
		return NULL;

	rc = fwd_tbl_add(fe, fes->family, sa, fed);
	if (rc != 0) {
		netfe_stream_close(fe, fed);
		fed = NULL;
	}

	fed->fwdprm.remote_addr = *(const struct sockaddr_storage *)sa;
	return fed;
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
	const struct rte_ipv4_hdr *ip4h;
	const struct rte_ipv6_hdr *ip6h;
	const struct rte_udp_hdr *udph;
	struct sockaddr_in *in4;
	struct sockaddr_in6 *in6;

	NETFE_PKT_DUMP(m);

	udph = rte_pktmbuf_mtod_offset(m, struct rte_udp_hdr *, -m->l4_len);

	if (family == AF_INET) {
		in4 = (struct sockaddr_in *)ps;
		ip4h = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *,
			-(m->l4_len + m->l3_len));
		in4->sin_port = udph->src_port;
		in4->sin_addr.s_addr = ip4h->src_addr;
	} else {
		in6 = (struct sockaddr_in6 *)ps;
		ip6h = rte_pktmbuf_mtod_offset(m, struct rte_ipv6_hdr *,
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

	netfe_pkt_addr(pkt[0], pi0, family);

	x = 0;
	for (i = 0; i != n; i = j) {

		j = i + pkt_eq_addr(&pkt[i + 1],
			n - i - 1, family, pi0, pi1) + 1;

		fed = find_fwd_dst_udp(lcore, fes,
			(const struct sockaddr *)pi0);
		if (fed != NULL) {

			/**
			 * TODO: cannot use function pointers for unequal
			 * number of params.
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

	netfe_pkt_addr(pkt[0], pi0, family);

	for (i = 0; i != n; i = j) {

		j = i + pkt_eq_addr(&pkt[i + 1],
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

	/* look for rx events */
	n = tle_evq_get(fe->rxeq, (const void **)(uintptr_t)fs, RTE_DIM(fs));

	if (n != 0) {
		NETFE_TRACE("%s(%u): tle_evq_get(rxevq=%p) returns %u\n",
			__func__, lcore, fe->rxeq, n);
		for (j = 0; j != n; j++)
			netfe_rx_process(lcore, fs[j]);
	}

	/* look for tx events */
	n = tle_evq_get(fe->txeq, (const void **)(uintptr_t)fs, RTE_DIM(fs));

	if (n != 0) {
		NETFE_TRACE("%s(%u): tle_evq_get(txevq=%p) returns %u\n",
			__func__, lcore, fe->txeq, n);
		for (j = 0; j != n; j++) {
			if (fs[j]->op == ECHO)
				netfe_rxtx_process_udp(lcore, fs[j]);
			else if (fs[j]->op == FWD)
				netfe_fwd_udp(lcore, fs[j]);
			else if (fs[j]->op == TXONLY)
				netfe_tx_process_udp(lcore, fs[j]);
		}
	}
}

static void
netfe_lcore_fini_udp(void)
{
	struct netfe_lcore *fe;
	uint32_t i;
	struct tle_udp_stream_param uprm;
	struct netfe_stream *fes;

	fe = RTE_PER_LCORE(_fe);
	if (fe == NULL)
		return;

	for (i = 0; i != fe->use.num; i++) {
		fes = netfe_get_stream(&fe->use);
		tle_udp_stream_get_param(fes->s, &uprm);
		netfe_stream_dump(fes, &uprm.local_addr, &uprm.remote_addr);
		netfe_stream_close(fe, fes);
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
		netbe_lcore();
	}

	RTE_LOG(NOTICE, USER1, "%s(lcore=%u) finish\n",
		__func__, lcore);

	netfe_lcore_fini_udp();
	netbe_lcore_clear();

	return rc;
}

#endif /* UDP_H_ */

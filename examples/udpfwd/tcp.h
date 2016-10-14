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

#ifndef TCP_H_
#define TCP_H_

/*
 * helper function: opens IPv4 and IPv6 streams for selected port.
 */
static struct netfe_stream *
netfe_stream_open_tcp(struct netfe_lcore *fe, struct netfe_sprm *sprm,
	uint32_t lcore, uint16_t op, uint32_t bidx, uint8_t server_mode)
{
	int32_t rc;
	uint32_t sidx;
	struct netfe_stream *fes;
	struct sockaddr_in *l4;
	struct sockaddr_in6 *l6;
	uint16_t errport;
	struct tle_tcp_stream_param tprm;

	if (fe->nb_sidx == 0) {
		rte_errno = ENOBUFS;
		return NULL;
	}
	sidx = fe->sidx[fe->nb_sidx - 1];
	fes = fe->fs + sidx;

	if (server_mode != 0)
		fes->rxev = tle_event_alloc(fe->syneq, &fe->fs[sidx]);
	else
		fes->rxev = tle_event_alloc(fe->rxeq, &fe->fs[sidx]);

	fes->erev = tle_event_alloc(fe->ereq, &fe->fs[sidx]);
	fes->txev = tle_event_alloc(fe->txeq, &fe->fs[sidx]);

	if (fes->rxev == NULL || fes->txev == NULL) {
		netfe_stream_close(fe, sidx);
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

	tle_event_active(fes->erev, TLE_SEV_DOWN);

	memset(&tprm, 0, sizeof(tprm));
	tprm.local_addr = sprm->local_addr;
	tprm.remote_addr = sprm->remote_addr;
	tprm.err_ev = fes->erev;
	tprm.recv_ev = fes->rxev;
	if (op != FWD)
		tprm.send_ev = fes->txev;
	fes->s = tle_tcp_stream_open(becfg.cpu[bidx].ctx, &tprm);

	if (fes->s == NULL) {
		rc = rte_errno;
		netfe_stream_close(fe, sidx);
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
		"%s(%u) [%u]={s=%p, op=%hu, proto=%s, rxev=%p, txev=%p}, belc=%u\n",
		__func__, lcore, sidx, fes->s, op, proto_name[becfg.proto],
		fes->rxev, fes->txev, becfg.cpu[bidx].id);

	fes->op = op;
	fes->proto = becfg.proto;
	fes->family = sprm->local_addr.ss_family;
	fes->laddr = sprm->local_addr;
	fes->id = sidx;

	fe->nb_sidx--;
	fe->fs_active[sidx] = 1;
	return fes;
}

static int
netfe_lcore_init_tcp(const struct netfe_lcore_prm *prm)
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

	sz = sizeof(*fe) + snum *
		(sizeof(fe->fs[0]) + sizeof(fe->sidx[0]) + sizeof(fe->fs_active[0]));
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
	/* initialize the stream index pool */
	fe->sidx = (uint32_t *)(fe->fs + snum);
	for (i = 0; i != snum; i++)
		fe->sidx[snum - i - 1] = i;
	fe->nb_sidx = snum;
	fe->fs_active = (uint32_t *)(fe->sidx + snum);

	/* allocate the event queues */
	fe->syneq = tle_evq_create(&eprm);
	fe->ereq = tle_evq_create(&eprm);
	fe->rxeq = tle_evq_create(&eprm);
	fe->txeq = tle_evq_create(&eprm);

	RTE_LOG(INFO, USER1, "%s(%u) synevq=%p, erevq=%p, rxevq=%p, txevq=%p\n",
		__func__, lcore, fe->syneq, fe->ereq, fe->rxeq, fe->txeq);
	if (fe->syneq == NULL || fe->ereq == NULL || fe->rxeq == NULL ||
		fe->txeq == NULL)
		return -ENOMEM;

	/* open all requested streams. */
	for (i = 0; i != prm->nb_streams; i++) {
		sprm = &prm->stream[i].sprm;
		fes = netfe_stream_open_tcp(fe, sprm, lcore, prm->stream[i].op,
			sprm->bidx, becfg.server);
		if (fes == NULL) {
			rc = -rte_errno;
			break;
		}

		netfe_stream_dump(fes, &sprm->local_addr, &sprm->remote_addr);

		if (prm->stream[i].op == FWD) {
			fes->fwdprm = prm->stream[i].fprm;
		} else if (prm->stream[i].op == TXONLY) {
			fes->txlen = prm->stream[i].txlen;
			fes->raddr = prm->stream[i].sprm.remote_addr;
		}

		if (becfg.server == 1) {
			rc = tle_tcp_stream_listen(fes->s);
			if (rc != 0) {
				rc = -rte_errno;
				break;
			}
			RTE_LOG(INFO, USER1, "%s(%u) stream=%p started listening\n",
				__func__, lcore, fes);
		} else {
			rc = tle_tcp_stream_connect(fes->s,
				(const struct sockaddr *)&prm->stream[i].sprm.remote_addr);
			if (rc != 0) {
				rc = -rte_errno;
				break;
			}
			RTE_LOG(INFO, USER1, "%s(%u) stream=%p connecting to server\n",
				__func__, lcore, fes);
		}
	}

	return rc;
}

static inline void
netfe_fwd_tcp(uint32_t lcore, struct netfe_stream *fes)
{
	uint32_t i, j, k, n, x, rc;
	uint16_t family;
	void *pi0, *pi1, *pt;
	struct rte_mbuf **pkt;
	struct netfe_stream *fed;
	struct sockaddr_storage in[2];
	struct netfe_lcore *fe;
	struct tle_tcp_stream_param tprm;

	fe = RTE_PER_LCORE(_fe);

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

		if (fes->fwds == NULL) {
			/* create a new fwd stream. */
			memset(&tprm, 0, sizeof(tprm));
			tprm.local_addr = fes->fwdprm.local_addr;
			tprm.remote_addr = fes->fwdprm.remote_addr;

			fed = netfe_stream_open_tcp(fe, &fes->fwdprm, lcore, FWD,
				fes->fwdprm.bidx, 0);
			if (fed != NULL) {
				fed->fwdprm.remote_addr = *(const struct sockaddr_storage *)pi0;

				rc = tle_tcp_stream_connect(fed->s,
					(const struct sockaddr *)pi0);
				if (rc != 0) {
					rc = -rte_errno;
					RTE_LOG(ERR, USER1, "%s(%u) stream=%p cannot connect "
						"to server\n", __func__, lcore, fes->s);
				} else
					RTE_LOG(INFO, USER1, "%s(%u) stream=%p connecting "
						"to server\n", __func__, lcore, fes->s);
			}
		} else
			fed = fes->fwds;

		if (fed != NULL) {

			/**
			 * TODO: cannot use function pointers for unequal param num.
			 */
			k = tle_tcp_stream_send(fed->s, pkt + i, j - i);

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
fill_sockaddr(struct sockaddr_in *ss, uint32_t addr, uint16_t port,
	uint8_t family)
{
	ss->sin_addr.s_addr = addr;
	ss->sin_port = port;
	ss->sin_family = family;
}

static inline void
fill_sockaddr6(struct sockaddr_in6 *ss, const uint8_t *addr,
	uint32_t addr_size, uint16_t port, uint8_t family)
{
	memcpy(&ss->sin6_addr, addr, addr_size);
	ss->sin6_port = port;
	ss->sin6_family = family;
}

static inline void
fill_accept_param(const struct netfe_lcore *fe, const struct netfe_stream *fs,
	struct tle_tcp_stream_param *prm)
{
	prm->err_ev = tle_event_alloc(fe->ereq, fs);
	prm->recv_ev = tle_event_alloc(fe->rxeq, fs);
	prm->send_ev = tle_event_alloc(fe->txeq, fs);

	tle_event_active(prm->err_ev, TLE_SEV_DOWN);
}

static inline void
netfe_new_conn_tcp(struct netfe_lcore *fe, __rte_unused uint32_t lcore,
	struct netfe_stream *fes)
{
	uint32_t i, k, n, rc, sidx;
	struct netfe_stream *ts;
	uint32_t temp_nb_sidx;
	struct tle_tcp_accept_param acpt_prm[MAX_PKT_BURST];
	struct tle_stream *rs[MAX_PKT_BURST];
	struct tle_syn_req syn_reqs[MAX_PKT_BURST];

	/* check if any syn requests are waiting */
	n = tle_tcp_stream_synreqs(fes->s, syn_reqs, RTE_DIM(syn_reqs));
	if (n == 0)
		return;

	NETFE_TRACE("%s(%u): tle_tcp_stream_synreqs(%p, %u) returns %u\n",
		__func__, lcore, fes->s, MAX_PKT_BURST, n);

	k = RTE_MIN(n, fe->nb_sidx);
	temp_nb_sidx = fe->nb_sidx;

	memset(acpt_prm, 0, sizeof(acpt_prm[0]) * k);

	/* fill accept params to accept k connection requests*/
	for (i = 0; i != k; i++) {
		sidx = fe->sidx[--temp_nb_sidx];
		acpt_prm[i].syn = syn_reqs[i];
		fill_accept_param(fe, &fe->fs[sidx], &acpt_prm[i].prm);
	}

	/* accept k new connections */
	rc = tle_tcp_stream_accept(fes->s, acpt_prm, rs, k);

	NETFE_TRACE("%s(%u): tle_tcp_stream_accept(%p, %u) returns %u, "
		"rte_errno=%d\n", __func__, lcore, fes->s, k, rc, rte_errno);
		
	if (rc != n) {
		/* n - rc connections could not be accepted */
		tle_tcp_reject(fes->s, syn_reqs + rc, n - rc);

		for (i = rc; i != k; i++) {
			tle_event_free(acpt_prm[i].prm.recv_ev);
			tle_event_free(acpt_prm[i].prm.send_ev);
			tle_event_free(acpt_prm[i].prm.err_ev);
		}
	}

	/* update the params for accepted streams */
	for (i = 0; i != rc; i++) {
		sidx = fe->sidx[--fe->nb_sidx];
		fe->fs_active[sidx] = 1;
		ts = fe->fs + sidx;

		ts->s = rs[i];
		ts->rxev = acpt_prm[i].prm.recv_ev;
		ts->txev = acpt_prm[i].prm.send_ev;
		ts->erev = acpt_prm[i].prm.err_ev;
		ts->op = fes->op;
		ts->proto = fes->proto;
		ts->family = fes->family;
		ts->id = sidx;

		if (fes->op == TXONLY || fes->op == FWD) {
			tle_event_active(ts->txev, TLE_SEV_DOWN);
			ts->stat.txev[TLE_SEV_DOWN]++;
		}
		if (fes->op != TXONLY) {
			tle_event_active(ts->rxev, TLE_SEV_DOWN);
			ts->stat.rxev[TLE_SEV_DOWN]++;
		}

		NETFE_TRACE("%s(%u) stream=%p accepted new stream=%p\n",
			__func__, lcore, fes, rs[i]);
	}
	fe->tcp_stat.acc += rc;
	fe->tcp_stat.rej += n - rc;
}

static inline void
netfe_lcore_tcp_req(void)
{
	struct netfe_lcore *fe;
	uint32_t j, n, lcore;
	struct netfe_stream *fs[MAX_PKT_BURST];

	fe = RTE_PER_LCORE(_fe);
	if (fe == NULL)
		return;

	/* look for syn events */
	n = tle_evq_get(fe->syneq, (const void **)(uintptr_t)fs, RTE_DIM(fs));
	if (n == 0)
		return;

	lcore = rte_lcore_id();

	NETFE_TRACE("%s(%u): tle_evq_get(synevq=%p) returns %u\n",
		__func__, lcore, fe->syneq, n);
	for (j = 0; j != n; j++)
		netfe_new_conn_tcp(fe, lcore, fs[j]);
}

static inline void
netfe_lcore_tcp_rst(void)
{
	struct netfe_lcore *fe;
	uint32_t j, n;
	struct tle_tcp_stream_param tprm;
	struct netfe_stream *fs[MAX_PKT_BURST];

	fe = RTE_PER_LCORE(_fe);
	if (fe == NULL)
		return;

	/* look for err events */
	n = tle_evq_get(fe->ereq, (const void **)(uintptr_t)fs, RTE_DIM(fs));
	if (n == 0)
		return;

	NETFE_TRACE("%s(%u): tle_evq_get(errevq=%p) returns %u\n",
		__func__, rte_lcore_id(), fe->ereq, n);

	for (j = 0; j != n; j++) {
		tle_tcp_stream_get_param(fs[j]->s, &tprm);
		netfe_stream_dump(fs[j], &tprm.local_addr, &tprm.remote_addr);
		netfe_stream_close(fe, fs[j]->id);
	}
}

static inline void
netfe_rxtx_process_tcp(__rte_unused uint32_t lcore, struct netfe_stream *fes)
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
		k = tle_tcp_stream_send(fes->s, pkt + i, j - i);

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
netfe_tx_process_tcp(uint32_t lcore, struct netfe_stream *fes)
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
	k = tle_tcp_stream_send(fes->s, fes->pbuf.pkt, n);

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
netfe_lcore_tcp(void)
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
			if (fs[j]->op == RXTX)
				netfe_rxtx_process_tcp(lcore, fs[j]);
			else if (fs[j]->op == FWD)
				netfe_fwd_tcp(lcore, fs[j]);
			else if (fs[j]->op == TXONLY)
				netfe_tx_process_tcp(lcore, fs[j]);
		}
	}
}

static void
netfe_lcore_fini_tcp(void)
{
	struct netfe_lcore *fe;
	uint32_t i;
	struct tle_tcp_stream_param tprm;
	uint32_t acc = 0, rej = 0;
	float time_used = 0;

	fe = RTE_PER_LCORE(_fe);
	if (fe == NULL)
		return;

	for (i = 0; i != fe->snum; i++) {
		if (fe->fs_active[i]) {
			tle_tcp_stream_get_param(fe->fs[i].s, &tprm);
			netfe_stream_dump(fe->fs + i, &tprm.local_addr, &tprm.remote_addr);
			netfe_stream_close(fe, i);
		}
	}

	acc = fe->tcp_stat.acc;
	rej = fe->tcp_stat.rej;
	time_used = (float) (time_end - time_start) / CLOCKS_PER_SEC;
	RTE_LOG(NOTICE, USER1, "Total time=%.2f sec;"
		"tcp_stats={con_acc=%u,con_rej=%u,avg_con_acc=%.2f per sec};\n",
		time_used, acc, rej, acc / time_used);

	tle_evq_destroy(fe->txeq);
	tle_evq_destroy(fe->rxeq);
	tle_evq_destroy(fe->ereq);
	tle_evq_destroy(fe->syneq);
	RTE_PER_LCORE(_fe) = NULL;
	rte_free(fe);
}

static int
lcore_main_tcp(void *arg)
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
		rc = netfe_lcore_init_tcp(&prm->fe);

	/* lcore FE init. */
	if (rc == 0 && prm->be.lc != NULL)
		rc = netbe_lcore_setup(prm->be.lc);

	if (rc != 0)
		sig_handle(SIGQUIT);

	/* save the start time */
	time_start = clock();

	while (force_quit == 0) {
		netfe_lcore_tcp_req();
		netfe_lcore_tcp_rst();
		netfe_lcore_tcp();
		netbe_lcore();
	}

	/* save the end time */
	time_end = clock();

	RTE_LOG(NOTICE, USER1, "%s(lcore=%u) finish\n",
		__func__, lcore);

	netfe_lcore_fini_tcp();
	netbe_lcore_clear();

	return rc;
}

#endif /* TCP_H_ */

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

#define	TCP_MAX_PROCESS	0x20

static inline void
netfe_stream_term_tcp(struct netfe_lcore *fe, struct netfe_stream *fes)
{
	fes->s = NULL;
	fes->fwds = NULL;
	fes->posterr = 0;
	memset(&fes->stat, 0, sizeof(fes->stat));
	pkt_buf_empty(&fes->pbuf);
	netfe_put_stream(fe, &fe->free, fes);
}

static inline void
netfe_stream_close_tcp(struct netfe_lcore *fe, struct netfe_stream *fes)
{
	tle_tcp_stream_close(fes->s);
	netfe_stream_term_tcp(fe, fes);
}

/*
 * helper function: opens IPv4 and IPv6 streams for selected port.
 */
static struct netfe_stream *
netfe_stream_open_tcp(struct netfe_lcore *fe, struct netfe_sprm *sprm,
	uint32_t lcore, uint16_t op, uint32_t bidx, uint8_t server_mode)
{
	int32_t rc;
	struct netfe_stream *fes;
	struct sockaddr_in *l4;
	struct sockaddr_in6 *l6;
	uint16_t errport;
	struct tle_tcp_stream_param tprm;

	fes = netfe_get_stream(&fe->free);
	if (fes == NULL) {
		rte_errno = ENOBUFS;
		return NULL;
	}

	if (server_mode != 0) {
		tle_event_free(fes->rxev);
		fes->rxev = tle_event_alloc(fe->syneq, fes);
	}

	if (fes->rxev == NULL) {
		netfe_stream_close_tcp(fe, fes);
		rte_errno = ENOMEM;
		return NULL;
	}

	/* activate rx, tx and err events for the stream */
	if (op == TXONLY || op == FWD) {
		tle_event_active(fes->txev, TLE_SEV_DOWN);
		fes->stat.txev[TLE_SEV_DOWN]++;
	}

	if (op != TXONLY || server_mode != 0) {
		tle_event_active(fes->rxev, TLE_SEV_DOWN);
		fes->stat.rxev[TLE_SEV_DOWN]++;
	}
	tle_event_active(fes->erev, TLE_SEV_DOWN);
	fes->stat.erev[TLE_SEV_DOWN]++;

	memset(&tprm, 0, sizeof(tprm));
	tprm.addr.local = sprm->local_addr;
	tprm.addr.remote = sprm->remote_addr;
	tprm.cfg.err_ev = fes->erev;
	tprm.cfg.recv_ev = fes->rxev;
	if (op != FWD)
		tprm.cfg.send_ev = fes->txev;

	fes->s = tle_tcp_stream_open(becfg.cpu[bidx].ctx, &tprm);

	if (fes->s == NULL) {
		rc = rte_errno;
		netfe_stream_close_tcp(fe, fes);
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
	fes->laddr = sprm->local_addr;
	netfe_put_stream(fe, &fe->use, fes);

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

	fes = (struct netfe_stream *)(fe + 1);
	for (i = 0; i != snum; i++) {
		fes[i].rxev = tle_event_alloc(fe->rxeq, fes + i);
		fes[i].txev = tle_event_alloc(fe->txeq, fes + i);
		fes[i].erev = tle_event_alloc(fe->ereq, fes + i);
		netfe_put_stream(fe, &fe->free, fes + i);
	}


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
		} else if (prm->stream[i].op == RXTX) {
			fes->txlen = prm->stream[i].txlen;
			fes->rxlen = prm->stream[i].rxlen;
		}

		if (becfg.server == 1) {
			rc = tle_tcp_stream_listen(fes->s);
			RTE_LOG(INFO, USER1,
				"%s(%u) tle_tcp_stream_listen(stream=%p) "
				"returns %d\n",
				__func__, lcore, fes->s, rc);
			if (rc != 0)
				break;
		} else {
			rc = tle_tcp_stream_connect(fes->s,
				(const struct sockaddr *)&sprm->remote_addr);
			RTE_LOG(INFO, USER1,
				"%s(%u) tle_tcp_stream_connect(stream=%p) "
				"returns %d\n",
				__func__, lcore, fes->s, rc);
			if (rc != 0)
				break;
		}
	}

	return rc;
}

static inline struct netfe_stream *
netfe_create_fwd_stream(struct netfe_lcore *fe, struct netfe_stream *fes,
	uint32_t lcore, uint32_t bidx)
{
	uint32_t rc;
	struct netfe_stream *fws;

	fws = netfe_stream_open_tcp(fe, &fes->fwdprm, lcore, FWD, bidx, 0);
	if (fws != NULL) {
		rc = tle_tcp_stream_connect(fws->s,
			(const struct sockaddr *)&fes->fwdprm.remote_addr);
		NETFE_TRACE("%s(lc=%u, fes=%p): tle_tcp_stream_connect() "
			"returns %d;\n",
			__func__, rte_lcore_id(), fes, rc);

		if (rc != 0) {
			netfe_stream_term_tcp(fe, fws);
			fws = NULL;
		}
	}

	if (fws == NULL)
		RTE_LOG(ERR, USER1, "%s(lc=%u fes=%p) failed to open "
			"forwarding stream;\n",
			__func__, rte_lcore_id(), fes);

	return fws;
}

static inline int
netfe_fwd_tcp(uint32_t lcore, struct netfe_stream *fes)
{
	uint32_t i, k, n;
	struct rte_mbuf **pkt;
	struct netfe_stream *fed;

	RTE_SET_USED(lcore);

	n = fes->pbuf.num;
	pkt = fes->pbuf.pkt;

	if (n == 0)
		return 0;

	fed = fes->fwds;

	if (fed != NULL) {

		k = tle_tcp_stream_send(fed->s, pkt, n);

		NETFE_TRACE("%s(%u): tle_%s_stream_send(%p, %u) "
				"returns %u\n",
				__func__, lcore, proto_name[fes->proto],
				fed->s, n, k);

		fed->stat.txp += k;
		fed->stat.drops += n - k;
		fes->stat.fwp += k;

	} else {
		NETFE_TRACE("%s(%u, %p): no fwd stream for %u pkts;\n",
			__func__, lcore, fes->s, n);
		for (k = 0; k != n; k++) {
			NETFE_TRACE("%s(%u, %p): free(%p);\n",
			__func__, lcore, fes->s, pkt[k]);
			rte_pktmbuf_free(pkt[k]);
		}
		fes->stat.drops += n;
	}

	/* copy unforwarded mbufs. */
	for (i = 0; i != n - k; i++)
		pkt[i] = pkt[i + k];

	fes->pbuf.num = i;

	if (i != 0) {
		tle_event_raise(fes->txev);
		fes->stat.txev[TLE_SEV_UP]++;
	}

	if (n == RTE_DIM(fes->pbuf.pkt)) {
		tle_event_active(fes->rxev, TLE_SEV_UP);
		fes->stat.rxev[TLE_SEV_UP]++;
	}

	return (fed == NULL) ? 0 : k;
}

static inline void
netfe_new_conn_tcp(struct netfe_lcore *fe, uint32_t lcore,
	struct netfe_stream *fes)
{
	uint32_t i, k, n;
	struct netfe_stream *ts;
	struct tle_stream *rs[MAX_PKT_BURST];
	struct netfe_stream *fs[MAX_PKT_BURST];
	struct tle_tcp_stream_cfg prm[MAX_PKT_BURST];

	/* check if any syn requests are waiting */
	n = tle_tcp_stream_accept(fes->s, rs, RTE_DIM(rs));
	if (n == 0)
		return;

	NETFE_TRACE("%s(%u): tle_tcp_stream_accept(%p, %u) returns %u\n",
		__func__, lcore, fes->s, MAX_PKT_BURST, n);

	/* get n free streams */
	k = netfe_get_streams(&fe->free, fs, n);
	if (n != k)
		RTE_LOG(ERR, USER1,
			"%s(lc=%u): not enough FE resources to handle %u new "
			"TCP streams;\n",
			__func__, lcore, n - k);

	/* fill accept params to accept k connection requests*/
	for (i = 0; i != k; i++) {

		ts = fs[i];
		ts->s = rs[i];
		ts->op = fes->op;
		ts->proto = fes->proto;
		ts->family = fes->family;
		ts->txlen = fes->txlen;
		ts->rxlen = fes->rxlen;

		tle_event_active(ts->erev, TLE_SEV_DOWN);
		if (fes->op == TXONLY || fes->op == FWD) {
			tle_event_active(ts->txev, TLE_SEV_UP);
			ts->stat.txev[TLE_SEV_UP]++;
		}
		if (fes->op != TXONLY) {
			tle_event_active(ts->rxev, TLE_SEV_DOWN);
			ts->stat.rxev[TLE_SEV_DOWN]++;
		}

		netfe_put_stream(fe, &fe->use, ts);

		memset(&prm[i], 0, sizeof(prm[i]));
		prm[i].recv_ev = ts->rxev;
		prm[i].send_ev = ts->txev;
		prm[i].err_ev = ts->erev;
	}

	tle_tcp_stream_update_cfg(rs, prm, k);

	tle_tcp_stream_close_bulk(rs + k, n - k);

	/* for the forwarding mode, open the second one */
	if (fes->op == FWD) {
		for (i = 0; i != k; i++) {

			ts = fs[i];

			ts->fwds = netfe_create_fwd_stream(fe, fes, lcore,
				fes->fwdprm.bidx);
			if (ts->fwds != NULL)
				ts->fwds->fwds = ts;
		}
	}

	fe->tcp_stat.acc += k;
	fe->tcp_stat.rej += n - k;
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
	struct netfe_stream *fwds;
	uint32_t j, k, n;
	struct tle_stream *s[MAX_PKT_BURST];
	struct netfe_stream *fs[MAX_PKT_BURST];
	struct tle_event *rv[MAX_PKT_BURST];
	struct tle_event *tv[MAX_PKT_BURST];
	struct tle_event *ev[MAX_PKT_BURST];

	fe = RTE_PER_LCORE(_fe);
	if (fe == NULL)
		return;

	/* look for err events */
	n = tle_evq_get(fe->ereq, (const void **)(uintptr_t)fs, RTE_DIM(fs));
	if (n == 0)
		return;

	NETFE_TRACE("%s(%u): tle_evq_get(errevq=%p) returns %u\n",
		__func__, rte_lcore_id(), fe->ereq, n);

	k = 0;
	for (j = 0; j != n; j++) {
		if (verbose > VERBOSE_NONE) {
			struct tle_tcp_stream_addr addr;
			tle_tcp_stream_get_addr(fs[j]->s, &addr);
			netfe_stream_dump(fs[j], &addr.local, &addr.remote);
		}

		/* check do we still have something to send/recv */
		if (fs[j]->posterr == 0 &&
				(tle_event_state(fs[j]->rxev) == TLE_SEV_UP ||
				tle_event_state(fs[j]->txev) == TLE_SEV_UP)) {
			fs[j]->posterr++;
		} else {
			s[k] = fs[j]->s;
			rv[k] = fs[j]->rxev;
			tv[k] = fs[j]->txev;
			ev[k] = fs[j]->erev;
			fs[k] = fs[j];
			k++;
		}
	}

	if (k == 0)
		return;

	tle_evq_idle(fe->rxeq, rv, k);
	tle_evq_idle(fe->txeq, tv, k);
	tle_evq_idle(fe->ereq, ev, k);

	tle_tcp_stream_close_bulk(s, k);

	for (j = 0; j != k; j++) {

		/* if forwarding mode, signal peer stream to terminate too. */
		fwds = fs[j]->fwds;
		if (fwds != NULL && fwds->s != NULL) {

			fwds->fwds = NULL;
			tle_event_raise(fwds->erev);
			fs[j]->fwds = NULL;
		}

		/* now terminate the stream receiving rst event*/
		netfe_rem_stream(&fe->use, fs[j]);
		netfe_stream_term_tcp(fe, fs[j]);
		fe->tcp_stat.ter++;
	}
}

static inline int
netfe_rxtx_process_tcp(__rte_unused uint32_t lcore, struct netfe_stream *fes)
{
	uint32_t i, k, n;
	struct rte_mbuf **pkt;

	n = fes->pbuf.num;
	pkt = fes->pbuf.pkt;

	/* there is nothing to send. */
	if (n == 0) {
		tle_event_idle(fes->txev);
		fes->stat.txev[TLE_SEV_IDLE]++;
		return 0;
	}


	k = tle_tcp_stream_send(fes->s, pkt, n);

	NETFE_TRACE("%s(%u): tle_%s_stream_send(%p, %u) returns %u\n",
		__func__, lcore, proto_name[fes->proto],
		fes->s, n, k);
	fes->stat.txp += k;
	fes->stat.drops += n - k;

	/* not able to send anything. */
	if (k == 0)
		return 0;

	/* Mark stream for reading if:
	 * ECHO: Buffer full
	 * RXTX: All outbound packets successfully dispatched
	 */
	if ((fes->op == ECHO && n == RTE_DIM(fes->pbuf.pkt)) ||
			(fes->op == RXTX && n - k == 0)) {
		/* mark stream as readable */
		tle_event_active(fes->rxev, TLE_SEV_UP);
		fes->stat.rxev[TLE_SEV_UP]++;
	}

	/* adjust pbuf array. */
	fes->pbuf.num = n - k;
	for (i = 0; i != n - k; i++)
		pkt[i] = pkt[i + k];

	return k;
}

static inline int
netfe_tx_process_tcp(uint32_t lcore, struct netfe_stream *fes)
{
	uint32_t i, k, n;

	/* refill with new mbufs. */
	if (fes->posterr == 0)
		pkt_buf_fill(lcore, &fes->pbuf, fes->txlen);

	n = fes->pbuf.num;
	if (n == 0)
		return 0;

	/**
	 * TODO: cannot use function pointers for unequal param num.
	 */
	k = tle_tcp_stream_send(fes->s, fes->pbuf.pkt, n);

	NETFE_TRACE("%s(%u): tle_%s_stream_send(%p, %u) returns %u\n",
		__func__, lcore, proto_name[fes->proto], fes->s, n, k);
	fes->stat.txp += k;
	fes->stat.drops += n - k;

	if (k == 0)
		return 0;

	/* adjust pbuf array. */
	fes->pbuf.num = n - k;
	for (i = k; i != n; i++)
		fes->pbuf.pkt[i - k] = fes->pbuf.pkt[i];

	return k;
}

static inline void
netfe_lcore_tcp(void)
{
	int32_t rc;
	uint32_t j, n, lcore;
	struct netfe_lcore *fe;
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

		for (j = 0; j != n; j++) {

			rc = netfe_rx_process(lcore, fs[j]);

			/* we are ok to close the stream */
			if (rc == 0 && fs[j]->posterr != 0)
				tle_event_raise(fs[j]->erev);
		}
	}

	/* look for tx events */
	n = tle_evq_get(fe->txeq, (const void **)(uintptr_t)fs, RTE_DIM(fs));

	if (n != 0) {

		NETFE_TRACE("%s(%u): tle_evq_get(txevq=%p) returns %u\n",
			__func__, lcore, fe->txeq, n);

		for (j = 0; j != n; j++) {

			rc = 0;

			if (fs[j]->op == ECHO)
				rc = netfe_rxtx_process_tcp(lcore, fs[j]);
			else if (fs[j]->op == FWD)
				rc = netfe_fwd_tcp(lcore, fs[j]);
			else if (fs[j]->op == TXONLY)
				rc = netfe_tx_process_tcp(lcore, fs[j]);
			else if (fs[j]->op == RXTX)
				rc = netfe_rxtx_process_tcp(lcore, fs[j]);

			/* we are ok to close the stream */
			if (rc == 0 && fs[j]->posterr != 0)
				tle_event_raise(fs[j]->erev);
		}
	}
}

static void
netfe_lcore_fini_tcp(void)
{
	struct netfe_lcore *fe;
	uint32_t i, snum;
	struct tle_tcp_stream_addr addr;
	struct netfe_stream *fes;
	uint32_t acc, rej, ter;

	fe = RTE_PER_LCORE(_fe);
	if (fe == NULL)
		return;

	snum = fe->use.num;
	for (i = 0; i != snum; i++) {
		fes = netfe_get_stream(&fe->use);
		tle_tcp_stream_get_addr(fes->s, &addr);
		netfe_stream_dump(fes, &addr.local, &addr.remote);
		netfe_stream_close(fe, fes);
	}

	acc = fe->tcp_stat.acc;
	rej = fe->tcp_stat.rej;
	ter = fe->tcp_stat.ter;
	RTE_LOG(NOTICE, USER1,
		"tcp_stats={con_acc=%u,con_rej=%u,con_ter=%u};\n",
		acc, rej, ter);

	tle_evq_destroy(fe->txeq);
	tle_evq_destroy(fe->rxeq);
	tle_evq_destroy(fe->ereq);
	tle_evq_destroy(fe->syneq);
	RTE_PER_LCORE(_fe) = NULL;
	rte_free(fe);
}

static inline void
netbe_lcore_tcp(void)
{
	uint32_t i;
	struct netbe_lcore *lc;

	lc = RTE_PER_LCORE(_be);
	if (lc == NULL)
		return;

	for (i = 0; i != lc->prtq_num; i++) {
		netbe_rx(lc, i);
		tle_tcp_process(lc->ctx, TCP_MAX_PROCESS);
		netbe_tx(lc, i);
	}
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

	while (force_quit == 0) {
		netfe_lcore_tcp_req();
		netfe_lcore_tcp_rst();
		netfe_lcore_tcp();
		netbe_lcore_tcp();
	}

	RTE_LOG(NOTICE, USER1, "%s(lcore=%u) finish\n",
		__func__, lcore);

	netfe_lcore_fini_tcp();
	netbe_lcore_clear();

	return rc;
}

#endif /* TCP_H_ */

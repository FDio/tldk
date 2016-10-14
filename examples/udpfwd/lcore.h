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

#ifndef LCORE_H_
#define LCORE_H_

#include "dpdk_legacy.h"

/*
 * IPv6 destination lookup callback.
 */
static int
lpm6_dst_lookup(void *data, const struct in6_addr *addr,
	struct tle_dest *res)
{
	int32_t rc;
	uint8_t idx;
	struct netbe_lcore *lc;
	struct tle_dest *dst;
	uintptr_t p;

	lc = data;
	p = (uintptr_t)addr->s6_addr;

	rc = rte_lpm6_lookup(lc->lpm6, (uint8_t *)p, &idx);
	if (rc == 0) {
		dst = &lc->dst6[idx];
		rte_memcpy(res, dst, dst->l2_len + dst->l3_len +
			offsetof(struct tle_dest, hdr));
	}
	return rc;
}

static int
create_context(struct netbe_lcore *lc, const struct tle_ctx_param *ctx_prm)
{
	uint32_t rc = 0, sid;
	uint64_t frag_cycles;
	struct tle_ctx_param cprm;

	if (lc->ctx == NULL) {
		sid = rte_lcore_to_socket_id(lc->id);

		rc = lcore_lpm_init(lc);
		if (rc != 0)
			return rc;

		cprm = *ctx_prm;
		cprm.socket_id = sid;
		cprm.proto = lc->proto;
		cprm.lookup4 = lpm4_dst_lookup;
		cprm.lookup4_data = lc;
		cprm.lookup6 = lpm6_dst_lookup;
		cprm.lookup6_data = lc;

		frag_cycles = (rte_get_tsc_hz() + MS_PER_S - 1) /
						MS_PER_S * FRAG_TTL;

		lc->ftbl = rte_ip_frag_table_create(cprm.max_streams,
			FRAG_TBL_BUCKET_ENTRIES, cprm.max_streams,
			frag_cycles, sid);

		RTE_LOG(NOTICE, USER1, "%s(lcore=%u): frag_tbl=%p;\n",
			__func__, lc->id, lc->ftbl);

		lc->ctx = tle_ctx_create(&cprm);

		RTE_LOG(NOTICE, USER1, "%s(lcore=%u): proto=%s, ctx=%p;\n",
			__func__, lc->id, proto_name[lc->proto], lc->ctx);

		if (lc->ctx == NULL || lc->ftbl == NULL)
			rc = ENOMEM;
	}

	return rc;
}

/*
 * BE lcore setup routine.
 */
static int
lcore_init(struct netbe_lcore *lc, const struct tle_ctx_param *ctx_prm,
	const uint32_t prtqid, const uint16_t *bl_ports, uint32_t nb_bl_ports)
{
	int32_t rc = 0;
	struct tle_dev_param dprm;

	rc = create_context(lc, ctx_prm);

	if (rc == 0 && lc->ctx != NULL) {
		memset(&dprm, 0, sizeof(dprm));
		dprm.rx_offload = lc->prtq[prtqid].port.rx_offload;
		dprm.tx_offload = lc->prtq[prtqid].port.tx_offload;
		dprm.local_addr4.s_addr = lc->prtq[prtqid].port.ipv4;
		memcpy(&dprm.local_addr6,  &lc->prtq[prtqid].port.ipv6,
			sizeof(lc->prtq[prtqid].port.ipv6));
		dprm.bl4.nb_port = nb_bl_ports;
		dprm.bl4.port = bl_ports;
		dprm.bl6.nb_port = nb_bl_ports;
		dprm.bl6.port = bl_ports;

		lc->prtq[prtqid].dev = tle_add_dev(lc->ctx, &dprm);

		RTE_LOG(NOTICE, USER1,
			"%s(lcore=%u, port=%u, qid=%u), dev: %p\n",
			__func__, lc->id, lc->prtq[prtqid].port.id,
			lc->prtq[prtqid].rxqid, lc->prtq[prtqid].dev);

		if (lc->prtq[prtqid].dev == NULL)
			rc = -rte_errno;

		if (rc != 0) {
			RTE_LOG(ERR, USER1,
				"%s(lcore=%u) failed with error code: %d\n",
				__func__, lc->id, rc);
			tle_ctx_destroy(lc->ctx);
			rte_ip_frag_table_destroy(lc->ftbl);
			rte_lpm_free(lc->lpm4);
			rte_lpm6_free(lc->lpm6);
			rte_free(lc->prtq[prtqid].port.lcore_id);
			lc->prtq[prtqid].port.nb_lcore = 0;
			rte_free(lc->prtq);
			lc->prtq_num = 0;
			return rc;
		}
	}

	return rc;
}

static uint16_t
create_blocklist(const struct netbe_port *beprt, uint16_t *bl_ports,
	uint32_t q)
{
	uint32_t i, j, qid, align_nb_q;

	align_nb_q = rte_align32pow2(beprt->nb_lcore);
	for (i = 0, j = 0; i < (UINT16_MAX + 1); i++) {
		qid = (i % align_nb_q) % beprt->nb_lcore;
		if (qid != q)
			bl_ports[j++] = i;
	}

	return j;
}

static int
netbe_lcore_init(struct netbe_cfg *cfg, const struct tle_ctx_param *ctx_prm)
{
	int32_t rc;
	uint32_t i, j, nb_bl_ports = 0, sz;
	struct netbe_lcore *lc;
	static uint16_t *bl_ports;

	/* Create the context and attached queue for each lcore. */
	rc = 0;
	sz = sizeof(uint16_t) * UINT16_MAX;
	bl_ports = rte_zmalloc(NULL, sz, RTE_CACHE_LINE_SIZE);
	for (i = 0; i < cfg->cpu_num; i++) {
		lc = &cfg->cpu[i];
		for (j = 0; j < lc->prtq_num; j++) {
			memset((uint8_t *)bl_ports, 0, sz);
			/* create list of blocked ports based on q */
			nb_bl_ports = create_blocklist(&lc->prtq[j].port,
				bl_ports, lc->prtq[j].rxqid);
			RTE_LOG(NOTICE, USER1,
				"lc=%u, q=%u, nb_bl_ports=%u\n",
				lc->id, lc->prtq[j].rxqid, nb_bl_ports);

			rc = lcore_init(lc, ctx_prm, j, bl_ports, nb_bl_ports);
			if (rc != 0) {
				RTE_LOG(ERR, USER1,
					"%s: failed with error code: %d\n",
					__func__, rc);
				rte_free(bl_ports);
				return rc;
			}
		}
	}
	rte_free(bl_ports);

	return 0;
}

static int
netfe_lcore_cmp(const void *s1, const void *s2)
{
	const struct netfe_stream_prm *p1, *p2;

	p1 = s1;
	p2 = s2;
	return p1->lcore - p2->lcore;
}

static int
netbe_find6(const struct in6_addr *laddr, uint16_t lport,
	const struct in6_addr *raddr, uint32_t belc)
{
	uint32_t i, j;
	uint8_t idx;
	struct netbe_lcore *bc;

	/* we have exactly one BE, use it for all traffic */
	if (becfg.cpu_num == 1)
		return 0;

	/* search by provided be_lcore */
	if (belc != LCORE_ID_ANY) {
		for (i = 0; i != becfg.cpu_num; i++) {
			bc = becfg.cpu + i;
			if (belc == bc->id)
				return i;
		}
		RTE_LOG(NOTICE, USER1, "%s: no stream with belcore=%u\n",
			__func__, belc);
		return -ENOENT;
	}

	/* search by local address */
	if (memcmp(laddr, &in6addr_any, sizeof(*laddr)) != 0) {
		for (i = 0; i != becfg.cpu_num; i++) {
			bc = becfg.cpu + i;
			/* search by queue for the local port */
			for (j = 0; j != bc->prtq_num; j++) {
				if (memcmp(laddr, &bc->prtq[j].port.ipv6,
						sizeof(*laddr)) == 0) {

					if (lport == 0)
						return i;

					if (verify_queue_for_port(bc->prtq + j,
							lport) != 0)
						return i;
				}
			}
		}
	}

	/* search by remote address */
	if (memcmp(raddr, &in6addr_any, sizeof(*raddr)) == 0) {
		for (i = 0; i != becfg.cpu_num; i++) {
			bc = becfg.cpu + i;
			if (rte_lpm6_lookup(bc->lpm6,
					(uint8_t *)(uintptr_t)raddr->s6_addr,
					&idx) == 0) {

				if (lport == 0)
					return i;

				/* search by queue for the local port */
				for (j = 0; j != bc->prtq_num; j++)
					if (verify_queue_for_port(bc->prtq + j,
							lport) != 0)
						return i;
			}
		}
	}

	return -ENOENT;
}

static int
netbe_find(const struct sockaddr_storage *la,
	const struct sockaddr_storage *ra,
	uint32_t belc)
{
	const struct sockaddr_in *l4, *r4;
	const struct sockaddr_in6 *l6, *r6;

	if (la->ss_family == AF_INET) {
		l4 = (const struct sockaddr_in *)la;
		r4 = (const struct sockaddr_in *)ra;
		return netbe_find4(&l4->sin_addr, ntohs(l4->sin_port),
				&r4->sin_addr, belc);
	} else if (la->ss_family == AF_INET6) {
		l6 = (const struct sockaddr_in6 *)la;
		r6 = (const struct sockaddr_in6 *)ra;
		return netbe_find6(&l6->sin6_addr, ntohs(l6->sin6_port),
				&r6->sin6_addr, belc);
	}
	return -EINVAL;
}

static int
netfe_sprm_flll_be(struct netfe_sprm *sp, uint32_t line, uint32_t belc)
{
	int32_t bidx;

	bidx = netbe_find(&sp->local_addr, &sp->remote_addr, belc);

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
	uint32_t belc;
	uint32_t i, j, lc, ln;
	struct netfe_stream_prm *s;

	/* determine on what BE each stream should be open. */
	for (i = 0; i != lprm->nb_streams; i++) {
		s = lprm->stream + i;
		ln = s->line;
		belc = s->belcore;
		if (netfe_sprm_flll_be(&s->sprm, ln, belc) != 0 ||
				(s->op == FWD && netfe_sprm_flll_be(&s->fprm, ln,
					belc) != 0))
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

#endif /* LCORE_H_ */

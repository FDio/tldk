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

#ifndef MAIN_DPDK_LEGACY_H_
#define MAIN_DPDK_LEGACY_H_

#include "dpdk_version.h"

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

/*
 * UDP IPv4 destination lookup callback.
 */
static int
lpm4_dst_lookup(void *data, const struct in_addr *addr,
	struct tle_udp_dest *res)
{
	int32_t rc;
#ifdef DPDK_VERSION_GE_1604
	uint32_t idx;
#else
	uint8_t idx;
#endif
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

static int
lcore_lpm_init(struct netbe_lcore *lc)
{
	int32_t sid;
	char str[RTE_LPM_NAMESIZE];
#ifdef DPDK_VERSION_GE_1604
	const struct rte_lpm_config lpm4_cfg = {
		.max_rules = MAX_RULES,
		.number_tbl8s = MAX_TBL8,
	};
#endif
	const struct rte_lpm6_config lpm6_cfg = {
		.max_rules = MAX_RULES,
		.number_tbl8s = MAX_TBL8,
	};

	sid = rte_lcore_to_socket_id(lc->id);

	snprintf(str, sizeof(str), "LPM4%u\n", lc->id);
#ifdef DPDK_VERSION_GE_1604
	lc->lpm4 = rte_lpm_create(str, sid, &lpm4_cfg);
#else
	lc->lpm4 = rte_lpm_create(str, sid, MAX_RULES, 0);
#endif
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

/*
 * Helper functions, finds BE by given local and remote addresses.
 */
static int
netbe_find4(const struct in_addr *laddr, const uint16_t lport,
	const struct in_addr *raddr, const uint32_t be_lc)
{
	uint32_t i, j;
#ifdef DPDK_VERSION_GE_1604
	uint32_t idx;
#else
	uint8_t idx;
#endif
	struct netbe_lcore *bc;

	/* we have exactly one BE, use it for all traffic */
	if (becfg.cpu_num == 1)
		return 0;

	/* search by provided be_lcore */
	if (be_lc != LCORE_ID_ANY) {
		for (i = 0; i != becfg.cpu_num; i++) {
			bc = becfg.cpu + i;
			if (be_lc == bc->id)
				return i;
		}
		RTE_LOG(NOTICE, USER1, "%s: no stream with be_lcore=%u\n",
			__func__, be_lc);
		return -ENOENT;
	}

	/* search by local address */
	if (laddr->s_addr != INADDR_ANY) {
		for (i = 0; i != becfg.cpu_num; i++) {
			bc = becfg.cpu + i;
			/* search by queue for the local port */
			for (j = 0; j != bc->prtq_num; j++) {
				if (laddr->s_addr == bc->prtq[j].port.ipv4) {

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
	if (raddr->s_addr != INADDR_ANY) {
		for (i = 0; i != becfg.cpu_num; i++) {
			bc = becfg.cpu + i;
			if (rte_lpm_lookup(bc->lpm4,
					rte_be_to_cpu_32(raddr->s_addr),
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

#endif /* MAIN_DPDK_LEGACY_H_ */

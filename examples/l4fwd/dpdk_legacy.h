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

#ifndef DPDK_LEGACY_H_
#define DPDK_LEGACY_H_

#include <rte_version.h>

#if RTE_VERSION_NUM(17, 5, 0, 0) <= RTE_VERSION
#ifndef DPDK_VERSION_GE_1705
#define DPDK_VERSION_GE_1705
#endif
#endif

/*
 * IPv6 destination lookup callback.
 */
static int
lpm6_dst_lookup(void *data, const struct in6_addr *addr,
	struct tle_dest *res)
{
	int32_t rc;
#ifdef DPDK_VERSION_GE_1705
	uint32_t idx;
#else
	uint8_t idx;
#endif
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
netbe_find6(const struct in6_addr *laddr, uint16_t lport,
	const struct in6_addr *raddr, uint32_t belc)
{
	uint32_t i, j;
#ifdef DPDK_VERSION_GE_1705
	uint32_t idx;
#else
	uint8_t idx;
#endif
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

#endif /* DPDK_LEGACY_H_ */

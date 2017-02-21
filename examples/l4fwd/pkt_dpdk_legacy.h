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

#ifndef PKT_DPDK_LEGACY_H_
#define PKT_DPDK_LEGACY_H_

#include "dpdk_version.h"

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

#ifdef DPDK_VERSION_GE_1604

static uint32_t
get_ptypes(const struct netbe_port *uprt)
{
	uint32_t smask;
	int32_t i, rc;
	const uint32_t pmask = RTE_PTYPE_L2_MASK | RTE_PTYPE_L3_MASK |
		RTE_PTYPE_L4_MASK;

	smask = 0;
	rc = rte_eth_dev_get_supported_ptypes(uprt->id, pmask, NULL, 0);
	if (rc < 0) {
		RTE_LOG(ERR, USER1,
			"%s(port=%u) failed to get supported ptypes;\n",
			__func__, uprt->id);
		return smask;
	}

	uint32_t ptype[rc];
	rc = rte_eth_dev_get_supported_ptypes(uprt->id, pmask, ptype, rc);

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

#else

static uint32_t
get_ptypes(__rte_unused const struct netbe_port *uprt)
{
	return 0;
}

#endif /* DPDK_VERSION_GE_1604 */

int
setup_rx_cb(const struct netbe_port *uprt, struct netbe_lcore *lc,
	uint16_t qid, uint32_t arp)
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

	static const struct ptype2cb tcp_arp_ptype2cb[] = {
		{
			.mask = 0,
			.name = "tcp with arp no HW ptype",
			.fn = typen_tcp_arp_rx_callback,
		},
	};

	static const struct ptype2cb udp_ptype2cb[] = {
		{
			.mask = ETHER_PTYPE | IPV4_PTYPE | IPV4_EXT_PTYPE |
				IPV6_PTYPE | IPV6_EXT_PTYPE | UDP_PTYPE,
			.name = "HW l2/l3x/l4-udp ptype",
			.fn = type0_udp_rx_callback,
		},
		{
			.mask = ETHER_PTYPE | IPV4_PTYPE | IPV6_PTYPE |
				UDP_PTYPE,
			.name = "HW l2/l3/l4-udp ptype",
			.fn = type1_udp_rx_callback,
		},
		{
			.mask = 0,
			.name = "udp no HW ptype",
			.fn = typen_udp_rx_callback,
		},
	};

	smask = get_ptypes(uprt);

	if (lc->proto == TLE_PROTO_TCP) {
		if (arp != 0) {
			ptype2cb = tcp_arp_ptype2cb;
			n = RTE_DIM(tcp_arp_ptype2cb);
		} else {
			ptype2cb = tcp_ptype2cb;
			n = RTE_DIM(tcp_ptype2cb);
		}
	} else if (lc->proto == TLE_PROTO_UDP) {
		ptype2cb = udp_ptype2cb;
		n = RTE_DIM(udp_ptype2cb);
	} else {
		RTE_LOG(ERR, USER1,
			"%s(lc=%u) unsupported proto: %u\n",
			__func__, lc->id, lc->proto);
		return -EINVAL;
	}

	for (i = 0; i != n; i++) {
		if ((smask & ptype2cb[i].mask) == ptype2cb[i].mask) {
			cb = rte_eth_add_rx_callback(uprt->id, qid,
				ptype2cb[i].fn, lc);
			rc = -rte_errno;
			RTE_LOG(ERR, USER1,
				"%s(port=%u), setup RX callback \"%s\" "
				"returns %p;\n",
				__func__, uprt->id,  ptype2cb[i].name, cb);
				return ((cb == NULL) ? rc : 0);
		}
	}

	/* no proper callback found. */
	RTE_LOG(ERR, USER1,
		"%s(port=%u) failed to find an appropriate callback;\n",
		__func__, uprt->id);
	return -ENOENT;
}

#endif /* PKT_DPDK_LEGACY_H_ */

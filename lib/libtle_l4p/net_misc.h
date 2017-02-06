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

#ifndef _NET_MISC_H_
#define _NET_MISC_H_

#include <rte_ip.h>
#include <rte_udp.h>
#include "osdep.h"

#ifdef __cplusplus
extern "C" {
#endif

#define	PKT_L234_HLEN(m)	(_tx_offload_l4_offset(m->tx_offload))
#define	PKT_L4_PLEN(m)		((m)->pkt_len - PKT_L234_HLEN(m))

/*
 * Some network protocols related structures definitions.
 * Main purpose to simplify (and optimise) processing and representation
 * of protocol related data.
 */

enum {
	TLE_V4,
	TLE_V6,
	TLE_VNUM
};

extern const struct in6_addr tle_ipv6_any;
extern const struct in6_addr tle_ipv6_none;

union l4_ports {
	uint32_t raw;
	struct {
		uint16_t src;
		uint16_t dst;
	};
};

union ipv4_addrs {
	uint64_t raw;
	struct {
		uint32_t src;
		uint32_t dst;
	};
};

union ipv6_addrs {
	_ymm_t raw;
	struct {
		rte_xmm_t src;
		rte_xmm_t dst;
	};
};

union ip_addrs {
	union ipv4_addrs v4;
	union ipv6_addrs v6;
};

#ifdef __cplusplus
}
#endif

#endif /* _NET_MISC_H_ */

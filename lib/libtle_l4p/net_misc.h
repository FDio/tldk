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
#include "osdep.h"

#ifdef __cplusplus
extern "C" {
#endif

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

/*
 * TCP related structures.
 */

#define	TCP_FLAG_FIN	0x01
#define	TCP_FLAG_SYN	0x02
#define	TCP_FLAG_RST	0x04
#define	TCP_FLAG_PSH	0x08
#define	TCP_FLAG_ACK	0x10
#define	TCP_FLAG_URG	0x20

/* TCP flags mask. */
#define	TCP_FLAG_MASK	UINT8_MAX

union typflg {
	uint16_t raw;
	struct {
		uint8_t type;  /* TLE_V4/TLE_V6 */
		uint8_t flags; /* TCP header flags */
	};
};

union pkt_info {
	rte_xmm_t raw;
	struct {
		union typflg tf;
		uint16_t reserve1;  /* just for alignment. */
		union l4_ports port;
		union {
			union ipv4_addrs addr4;
			const union ipv6_addrs *addr6;
		};
	};
};

#define	TCP_DATA_ALIGN	4

/*
 * recognizable options.
 */
#define	TCP_OPT_KIND_EOL	0x00
#define	TCP_OPT_KIND_NOP	0x01
#define	TCP_OPT_KIND_MSS	0x02
#define	TCP_OPT_KIND_WSC	0x03
#define	TCP_OPT_KIND_TMS	0x08

#define	TCP_OPT_LEN_EOL		0x01
#define	TCP_OPT_LEN_NOP		0x01
#define	TCP_OPT_LEN_MSS		0x04
#define	TCP_OPT_LEN_WSC		0x03
#define	TCP_OPT_LEN_TMS		0x0a

#define	TCP_TX_OPT_LEN_MAX	\
	RTE_ALIGN_CEIL(TCP_OPT_LEN_MSS + TCP_OPT_LEN_WSC + TCP_OPT_LEN_TMS + \
		TCP_OPT_LEN_EOL, TCP_DATA_ALIGN)

/*
 * recomended format for TSOPT from RFC 1323, appendix A:
 *  +--------+--------+--------+--------+
 *  |   NOP  |  NOP   |  TSopt |   10   |
 *  +--------+--------+--------+--------+
 *  |          TSval   timestamp        |
 *  +--------+--------+--------+--------+
 *  |          TSecr   timestamp        |
 *  +--------+--------+--------+--------+
 */
#define	TCP_TX_OPT_LEN_TMS	(TCP_OPT_LEN_TMS + 2 * TCP_OPT_LEN_NOP)

#define TCP_OPT_TMS_HDR		(rte_be_to_cpu_32( \
	TCP_OPT_KIND_NOP << 3 * CHAR_BIT | \
	TCP_OPT_KIND_NOP << 2 * CHAR_BIT | \
	TCP_OPT_KIND_TMS << CHAR_BIT | \
	TCP_OPT_LEN_TMS))

#define	TCP_OPT_KL(k, l)	(rte_be_to_cpu_16((k) << CHAR_BIT | (l)))

#define	TCP_OPT_KL_MSS		TCP_OPT_KL(TCP_OPT_KIND_MSS, TCP_OPT_LEN_MSS)
#define	TCP_OPT_KL_WSC		TCP_OPT_KL(TCP_OPT_KIND_WSC, TCP_OPT_LEN_WSC)
#define	TCP_OPT_KL_TMS		TCP_OPT_KL(TCP_OPT_KIND_TMS, TCP_OPT_LEN_TMS)

/*
 * Timestamp option.
 */
struct tsopt {
	uint32_t val;
	uint32_t ecr;
};

struct tcpopt {
	union {
		uint16_t raw;
		struct {
			uint8_t kind;
			uint8_t len;
		};
	} kl;
	union {
		uint16_t mss;
		uint8_t  wscale;
		struct tsopt ts;
	};
} __attribute__((__packed__));

struct syn_opts {
	uint16_t mss;
	uint8_t  wscale;
	struct tsopt ts;
};

#ifdef __cplusplus
}
#endif

#endif /* _NET_MISC_H_ */

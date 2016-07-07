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

#ifndef _UDP_IMPL_H_
#define _UDP_IMPL_H_

#include <rte_spinlock.h>
#include <rte_vect.h>
#include <tle_dring.h>
#include <tle_udp_impl.h>
#include <tle_event.h>

#include "port_bitmap.h"
#include "osdep.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
	TLE_UDP_V4,
	TLE_UDP_V6,
	TLE_UDP_VNUM
};

union udp_ports {
	uint32_t raw;
	struct {
		uint16_t src;
		uint16_t dst;
	};
};

union udph {
	uint64_t raw;
	struct {
		union udp_ports ports;
		uint16_t len;
		uint16_t cksum;
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


struct tle_udp_stream {

	STAILQ_ENTRY(tle_udp_stream) link;
	struct tle_udp_ctx *ctx;

	uint8_t type;	       /* TLE_UDP_V4 or TLE_UDP_V6 */

	struct {
		struct rte_ring *q;
		struct tle_event *ev;
		struct tle_udp_stream_cb cb;
		rte_atomic32_t use;
	} rx;

	union udp_ports port;
	union udp_ports pmsk;

	union {
		struct {
			union ipv4_addrs addr;
			union ipv4_addrs mask;
		} ipv4;
		struct {
			union ipv6_addrs addr;
			union ipv6_addrs mask;
		} ipv6;
	};

	struct {
		rte_atomic32_t use;
		struct {
			uint32_t nb_elem;  /* number of obects per drb. */
			uint32_t nb_max;   /* number of drbs per stream. */
			struct rte_ring *r;
		} drb;
		struct tle_event *ev;
		struct tle_udp_stream_cb cb;
	} tx __rte_cache_aligned;

	struct tle_udp_stream_param prm;
} __rte_cache_aligned;

#define UDP_STREAM_TX_PENDING(s)	\
	((s)->tx.drb.nb_max != rte_ring_count((s)->tx.drb.r))

#define UDP_STREAM_TX_FINISHED(s)	\
	((s)->tx.drb.nb_max == rte_ring_count((s)->tx.drb.r))

struct tle_udp_dport {
	struct udp_pbm use; /* ports in use. */
	struct tle_udp_stream *streams[MAX_PORT_NUM]; /* port to stream. */
};

struct tle_udp_dev {
	struct tle_udp_ctx *ctx;
	struct {
		uint64_t ol_flags[TLE_UDP_VNUM];
	} rx;
	struct {
		/* used by FE. */
		uint64_t ol_flags[TLE_UDP_VNUM];
		rte_atomic32_t packet_id[TLE_UDP_VNUM];

		/* used by FE & BE. */
		struct tle_dring dr;
	} tx;
	struct tle_udp_dev_param prm; /* copy of device paramaters. */
	struct tle_udp_dport *dp[TLE_UDP_VNUM]; /* device udp ports */
};

struct tle_udp_ctx {
	struct tle_udp_ctx_param prm;
	struct {
		rte_spinlock_t lock;
		uint32_t nb_free; /* number of free streams. */
		STAILQ_HEAD(, tle_udp_stream) free;
		struct tle_udp_stream *buf; /* array of streams */
	} streams;

	rte_spinlock_t dev_lock;
	uint32_t nb_dev;
	struct udp_pbm use[TLE_UDP_VNUM];          /* all ports in use. */
	struct tle_udp_dev dev[RTE_MAX_ETHPORTS];
};

#ifdef __cplusplus
}
#endif

#endif /* _UDP_IMPL_H_ */

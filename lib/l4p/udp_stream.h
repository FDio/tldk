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

#ifndef _UDP_STREAM_H_
#define _UDP_STREAM_H_

#include <rte_vect.h>
#include <tle_dring.h>
#include <tle_udp.h>
#include <tle_event.h>

#include "osdep.h"
#include "ctx.h"
#include "stream.h"

#ifdef __cplusplus
extern "C" {
#endif

union udph {
	uint64_t raw;
	struct {
		union l4_ports ports;
		uint16_t len;
		uint16_t cksum;
	};
};

struct tle_udp_stream {

	struct tle_stream s;

	struct {
		struct rte_ring *q;
		struct tle_event *ev;
		struct tle_stream_cb cb;
		rte_atomic32_t use;
	} rx __rte_cache_aligned;

	struct {
		rte_atomic32_t use;
		struct {
			uint32_t nb_elem;  /* number of obects per drb. */
			uint32_t nb_max;   /* number of drbs per stream. */
			struct rte_ring *r;
		} drb;
		struct tle_event *ev;
		struct tle_stream_cb cb;
	} tx __rte_cache_aligned;

	struct tle_udp_stream_param prm;
} __rte_cache_aligned;

#define UDP_STREAM(p)	\
((struct tle_udp_stream *)((uintptr_t)(p) - offsetof(struct tle_udp_stream, s)))

#define UDP_STREAM_TX_PENDING(s)	\
	((s)->tx.drb.nb_max != rte_ring_count((s)->tx.drb.r))

#define UDP_STREAM_TX_FINISHED(s)	\
	((s)->tx.drb.nb_max == rte_ring_count((s)->tx.drb.r))

#ifdef __cplusplus
}
#endif

#endif /* _UDP_STREAM_H_ */

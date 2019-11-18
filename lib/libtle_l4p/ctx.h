/*
 * Copyright (c) 2016-2017  Intel Corporation.
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

#ifndef _CTX_H_
#define _CTX_H_

#include <rte_spinlock.h>
#include <rte_vect.h>
#include <tle_dring.h>
#include <tle_ctx.h>

#include "port_statmap.h"
#include "osdep.h"
#include "net_misc.h"

#ifdef __cplusplus
extern "C" {
#endif

struct tle_dev {
	struct tle_ctx *ctx;
	struct {
		uint64_t ol_flags[TLE_VNUM];
	} rx;
	struct {
		/* used by FE. */
		uint64_t ol_flags[TLE_VNUM];
		rte_atomic32_t packet_id[TLE_VNUM];

		/* used by FE & BE. */
		struct tle_dring dr;
	} tx;
	struct tle_dev_param prm; /* copy of device parameters. */
};

struct tle_ctx {
	struct tle_ctx_param prm;
	uint32_t cycles_ms_shift;  /* to convert from cycles to ms */
	struct {
		rte_spinlock_t lock;
		uint32_t nb_free; /* number of free streams. */
		uint32_t nb_cur; /* number of allocated streams. */
		STAILQ_HEAD(, tle_stream) free;
		void *buf; /* space allocated for streams */
	} streams;

	rte_spinlock_t bhash_lock[TLE_VNUM];
	struct rte_hash *bhash[TLE_VNUM]; /* bind and listen hash table */

	uint32_t nb_dev;
	rte_spinlock_t dev_lock;
	struct tle_psm use[TLE_VNUM]; /* all ports in use. */
	struct tle_dev dev[RTE_MAX_ETHPORTS];
};

struct stream_ops {
	int (*init_streams)(struct tle_ctx *);
	uint32_t (*more_streams)(struct tle_ctx *);
	void (*fini_streams)(struct tle_ctx *);
	void (*free_drbs)(struct tle_stream *, struct tle_drb *[], uint32_t);
};

extern struct stream_ops tle_stream_ops[TLE_PROTO_NUM];

int stream_fill_ctx(struct tle_ctx *ctx, struct tle_stream *s,
	const struct sockaddr *laddr, const struct sockaddr *raddr);

int stream_clear_ctx(struct tle_ctx *ctx, struct tle_stream *s);

static inline void
fill_ipv4_am(const struct sockaddr_in *in, uint32_t *addr, uint32_t *mask)
{
	*addr = in->sin_addr.s_addr;
	*mask = (*addr == INADDR_ANY) ? INADDR_ANY : INADDR_NONE;
}

static inline void
fill_ipv6_am(const struct sockaddr_in6 *in, rte_xmm_t *addr, rte_xmm_t *mask)
{
	const struct in6_addr *pm;

	memcpy(addr, &in->sin6_addr, sizeof(*addr));
	if (IN6_IS_ADDR_UNSPECIFIED(addr))
		pm = &tle_ipv6_any;
	else
		pm = &tle_ipv6_none;

	memcpy(mask, pm, sizeof(*mask));
}

#ifdef __cplusplus
}
#endif

#endif /* _UDP_IMPL_H_ */

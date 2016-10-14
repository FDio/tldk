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

#ifndef _STREAM_H_
#define _STREAM_H_

#include "ctx.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Common structure that must be present as first field in all partcular
 * L4 (UDP/TCP, etc.) stream implementations.
 */
struct tle_stream {

	STAILQ_ENTRY(tle_stream) link;
	struct tle_ctx *ctx;

	uint8_t type;	       /* TLE_V4 or TLE_V6 */

	/* Stream address information. */
	union l4_ports port;
	union l4_ports pmsk;

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
};

static inline uint32_t
get_streams(struct tle_ctx *ctx, struct tle_stream *s[], uint32_t num)
{
	struct tle_stream *p;
	uint32_t i, n;

	rte_spinlock_lock(&ctx->streams.lock);

	n = RTE_MIN(ctx->streams.nb_free, num);
	for (i = 0, p = STAILQ_FIRST(&ctx->streams.free);
			i != n;
			i++, p = STAILQ_NEXT(p, link))
		s[i] = p;

	if (p == NULL)
		/* we retrieved all free entries */
		STAILQ_INIT(&ctx->streams.free);
	else
		STAILQ_FIRST(&ctx->streams.free) = p;

	ctx->streams.nb_free -= n;
	rte_spinlock_unlock(&ctx->streams.lock);
	return n;
}

static inline struct tle_stream *
get_stream(struct tle_ctx *ctx)
{
	struct tle_stream *s;

	s = NULL;
	if (ctx->streams.nb_free == 0)
		return s;

	get_streams(ctx, &s, 1);
	return s;
}

static inline void
put_stream(struct tle_ctx *ctx, struct tle_stream *s, int32_t head)
{
	s->type = TLE_VNUM;
	rte_spinlock_lock(&ctx->streams.lock);
	if (head != 0)
		STAILQ_INSERT_HEAD(&ctx->streams.free, s, link);
	else
		STAILQ_INSERT_TAIL(&ctx->streams.free, s, link);
	ctx->streams.nb_free++;
	rte_spinlock_unlock(&ctx->streams.lock);
}

/* calculate number of drbs per stream. */
static inline uint32_t
calc_stream_drb_num(const struct tle_ctx *ctx, uint32_t obj_num)
{
	uint32_t num;

	num = (ctx->prm.max_stream_sbufs + obj_num - 1) / obj_num;
	num = num + num / 2;
	num = RTE_MAX(num, RTE_DIM(ctx->dev) + 1);
	return num;
}

static inline uint32_t
drb_nb_elem(const struct tle_ctx *ctx)
{
	return (ctx->prm.send_bulk_size != 0) ?
		ctx->prm.send_bulk_size : MAX_PKT_BURST;
}

static inline int32_t
stream_get_dest(struct tle_stream *s, const void *dst_addr,
	struct tle_dest *dst)
{
	int32_t rc;
	const struct in_addr *d4;
	const struct in6_addr *d6;
	struct tle_ctx *ctx;
	struct tle_dev *dev;

	ctx = s->ctx;

	/* it is here just to keep gcc happy. */
	d4 = NULL;

	if (s->type == TLE_V4) {
		d4 = dst_addr;
		rc = ctx->prm.lookup4(ctx->prm.lookup4_data, d4, dst);
	} else if (s->type == TLE_V6) {
		d6 = dst_addr;
		rc = ctx->prm.lookup6(ctx->prm.lookup6_data, d6, dst);
	} else
		rc = -ENOENT;

	if (rc < 0 || dst->dev == NULL || dst->dev->ctx != ctx)
		return -ENOENT;

	dev = dst->dev;
	if (s->type == TLE_V4) {
		struct ipv4_hdr *l3h;
		l3h = (struct ipv4_hdr *)(dst->hdr + dst->l2_len);
		l3h->src_addr = dev->prm.local_addr4.s_addr;
		l3h->dst_addr = d4->s_addr;
	} else {
		struct ipv6_hdr *l3h;
		l3h = (struct ipv6_hdr *)(dst->hdr + dst->l2_len);
		rte_memcpy(l3h->src_addr, &dev->prm.local_addr6,
			sizeof(l3h->src_addr));
		rte_memcpy(l3h->dst_addr, d6, sizeof(l3h->dst_addr));
	}

	return dev - ctx->dev;
}

#ifdef __cplusplus
}
#endif

#endif /* _STREAM_H_ */

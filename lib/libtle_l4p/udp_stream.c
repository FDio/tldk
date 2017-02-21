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

#include <string.h>
#include <rte_malloc.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_udp.h>

#include "udp_stream.h"
#include "misc.h"

static void
unuse_stream(struct tle_udp_stream *s)
{
	s->s.type = TLE_VNUM;
	rte_atomic32_set(&s->rx.use, INT32_MIN);
	rte_atomic32_set(&s->tx.use, INT32_MIN);
}

static void
fini_stream(struct tle_udp_stream *s)
{
	if (s != NULL) {
		rte_free(s->rx.q);
		rte_free(s->tx.drb.r);
	}
}

static void
udp_fini_streams(struct tle_ctx *ctx)
{
	uint32_t i;
	struct tle_udp_stream *s;

	s = ctx->streams.buf;
	if (s != NULL) {
		for (i = 0; i != ctx->prm.max_streams; i++)
			fini_stream(s + i);
	}

	rte_free(s);
	ctx->streams.buf = NULL;
	STAILQ_INIT(&ctx->streams.free);
}

static int
init_stream(struct tle_ctx *ctx, struct tle_udp_stream *s)
{
	size_t bsz, rsz, sz;
	uint32_t i, k, n, nb;
	struct tle_drb *drb;
	char name[RTE_RING_NAMESIZE];

	/* init RX part. */

	n = RTE_MAX(ctx->prm.max_stream_rbufs, 1U);
	n = rte_align32pow2(n);
	sz = sizeof(*s->rx.q) + n * sizeof(s->rx.q->ring[0]);

	s->rx.q = rte_zmalloc_socket(NULL, sz, RTE_CACHE_LINE_SIZE,
		ctx->prm.socket_id);
	if (s->rx.q == NULL) {
		UDP_LOG(ERR, "%s(%p): allocation of %zu bytes on socket %d "
			"failed with error code: %d\n",
			__func__, s, sz, ctx->prm.socket_id, rte_errno);
		return -ENOMEM;
	}

	snprintf(name, sizeof(name), "%p@%zu", s, sz);
	rte_ring_init(s->rx.q, name, n, RING_F_SP_ENQ);

	/* init TX part. */

	nb = drb_nb_elem(ctx);
	k = calc_stream_drb_num(ctx, nb);
	n = rte_align32pow2(k);

	/* size of the drbs ring */
	rsz = sizeof(*s->tx.drb.r) + n * sizeof(s->tx.drb.r->ring[0]);
	rsz = RTE_ALIGN_CEIL(rsz, RTE_CACHE_LINE_SIZE);

	/* size of the drb. */
	bsz = tle_drb_calc_size(nb);

	/* total stream drbs size. */
	sz = rsz + bsz * k;

	s->tx.drb.r = rte_zmalloc_socket(NULL, sz, RTE_CACHE_LINE_SIZE,
		ctx->prm.socket_id);
	if (s->tx.drb.r == NULL) {
		UDP_LOG(ERR, "%s(%p): allocation of %zu bytes on socket %d "
			"failed with error code: %d\n",
			__func__, s, sz, ctx->prm.socket_id, rte_errno);
		return -ENOMEM;
	}

	snprintf(name, sizeof(name), "%p@%zu", s, sz);
	rte_ring_init(s->tx.drb.r, name, n, 0);

	for (i = 0; i != k; i++) {
		drb = (struct tle_drb *)((uintptr_t)s->tx.drb.r +
			rsz + bsz * i);
		drb->udata = s;
		drb->size = nb;
		rte_ring_enqueue(s->tx.drb.r, drb);
	}

	s->tx.drb.nb_elem = nb;
	s->tx.drb.nb_max = k;

	/* mark stream as avaialble to use. */

	s->s.ctx = ctx;
	unuse_stream(s);
	STAILQ_INSERT_TAIL(&ctx->streams.free, &s->s, link);

	return 0;
}

static void
udp_free_drbs(struct tle_stream *s, struct tle_drb *drb[], uint32_t nb_drb)
{
	struct tle_udp_stream *us;

	us = (struct tle_udp_stream *)s;
	rte_ring_enqueue_burst(us->tx.drb.r, (void **)drb, nb_drb);
}

static int
udp_init_streams(struct tle_ctx *ctx)
{
	size_t sz;
	uint32_t i;
	int32_t rc;
	struct tle_udp_stream *s;

	sz = sizeof(*s) * ctx->prm.max_streams;
	s = rte_zmalloc_socket(NULL, sz, RTE_CACHE_LINE_SIZE,
		ctx->prm.socket_id);
	if (s == NULL) {
		UDP_LOG(ERR, "allocation of %zu bytes on socket %d "
			"for %u udp_streams failed\n",
			sz, ctx->prm.socket_id, ctx->prm.max_streams);
		return -ENOMEM;
	}

	ctx->streams.buf = s;
	STAILQ_INIT(&ctx->streams.free);

	for (i = 0; i != ctx->prm.max_streams; i++) {
		rc = init_stream(ctx, s + i);
		if (rc != 0) {
			UDP_LOG(ERR, "initalisation of %u-th stream failed", i);
			udp_fini_streams(ctx);
			return rc;
		}
	}

	return 0;
}

static void __attribute__((constructor))
udp_stream_setup(void)
{
	static const struct stream_ops udp_ops = {
		.init_streams = udp_init_streams,
		.fini_streams = udp_fini_streams,
		.free_drbs = udp_free_drbs,
	};

	tle_stream_ops[TLE_PROTO_UDP] = udp_ops;
}

static inline void
stream_down(struct tle_udp_stream *s)
{
	rwl_down(&s->rx.use);
	rwl_down(&s->tx.use);
}

static inline void
stream_up(struct tle_udp_stream *s)
{
	rwl_up(&s->rx.use);
	rwl_up(&s->tx.use);
}

static int
check_stream_prm(const struct tle_ctx *ctx,
	const struct tle_udp_stream_param *prm)
{
	if ((prm->local_addr.ss_family != AF_INET &&
			prm->local_addr.ss_family != AF_INET6) ||
			prm->local_addr.ss_family != prm->remote_addr.ss_family)
		return -EINVAL;

	/* callback and event notifications mechanisms are mutually exclusive */
	if ((prm->recv_ev != NULL && prm->recv_cb.func != NULL) ||
			(prm->send_ev != NULL && prm->send_cb.func != NULL))
		return -EINVAL;

	/* check does context support desired address family. */
	if ((prm->local_addr.ss_family == AF_INET &&
			ctx->prm.lookup4 == NULL) ||
			(prm->local_addr.ss_family == AF_INET6 &&
			ctx->prm.lookup6 == NULL))
		return -EINVAL;

	return 0;
}

struct tle_stream *
tle_udp_stream_open(struct tle_ctx *ctx,
	const struct tle_udp_stream_param *prm)
{
	struct tle_udp_stream *s;
	int32_t rc;

	if (ctx == NULL || prm == NULL || check_stream_prm(ctx, prm) != 0) {
		rte_errno = EINVAL;
		return NULL;
	}

	s = (struct tle_udp_stream *)get_stream(ctx);
	if (s == NULL)	{
		rte_errno = ENFILE;
		return NULL;

	/* some TX still pending for that stream. */
	} else if (UDP_STREAM_TX_PENDING(s)) {
		put_stream(ctx, &s->s, 0);
		rte_errno = EAGAIN;
		return NULL;
	}

	/* copy input parameters. */
	s->prm = *prm;

	/* setup L4 ports and L3 addresses fields. */
	rc = stream_fill_ctx(ctx, &s->s,
		(const struct sockaddr *)&prm->local_addr,
		(const struct sockaddr *)&prm->remote_addr);

	if (rc != 0) {
		put_stream(ctx, &s->s, 1);
		s = NULL;
		rte_errno = rc;
	} else {
		/* setup stream notification menchanism */
		s->rx.ev = prm->recv_ev;
		s->rx.cb = prm->recv_cb;
		s->tx.ev = prm->send_ev;
		s->tx.cb = prm->send_cb;

		/* mark stream as avaialbe for RX/TX */
		if (s->tx.ev != NULL)
			tle_event_raise(s->tx.ev);
		stream_up(s);
	}

	return &s->s;
}

int
tle_udp_stream_close(struct tle_stream *us)
{
	int32_t rc;
	struct tle_ctx *ctx;
	struct tle_udp_stream *s;

	static const struct tle_stream_cb zcb;

	s = UDP_STREAM(us);
	if (us == NULL || s->s.type >= TLE_VNUM)
		return -EINVAL;

	ctx = s->s.ctx;

	/* mark stream as unavaialbe for RX/TX. */
	stream_down(s);

	/* reset stream events if any. */
	if (s->rx.ev != NULL) {
		tle_event_idle(s->rx.ev);
		s->rx.ev = NULL;
	}
	if (s->tx.ev != NULL) {
		tle_event_idle(s->tx.ev);
		s->tx.ev = NULL;
	}

	s->rx.cb = zcb;
	s->tx.cb = zcb;

	/* free stream's destination port */
	rc = stream_clear_ctx(ctx, &s->s);

	/* empty stream's RX queue */
	empty_mbuf_ring(s->rx.q);

	/*
	 * mark the stream as free again.
	 * if there still are pkts queued for TX,
	 * then put this stream to the tail of free list.
	 */
	put_stream(ctx, &s->s, UDP_STREAM_TX_FINISHED(s));
	return rc;
}

int
tle_udp_stream_get_param(const struct tle_stream *us,
	struct tle_udp_stream_param *prm)
{
	struct sockaddr_in *lin4;
	struct sockaddr_in6 *lin6;
	const struct tle_udp_stream *s;

	s = UDP_STREAM(us);
	if (prm == NULL || us == NULL || s->s.type >= TLE_VNUM)
		return -EINVAL;

	prm[0] = s->prm;
	if (prm->local_addr.ss_family == AF_INET) {
		lin4 = (struct sockaddr_in *)&prm->local_addr;
		lin4->sin_port = s->s.port.dst;
	} else if (s->prm.local_addr.ss_family == AF_INET6) {
		lin6 = (struct sockaddr_in6 *)&prm->local_addr;
		lin6->sin6_port = s->s.port.dst;
	}

	return 0;
}

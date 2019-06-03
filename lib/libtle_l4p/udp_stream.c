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
	struct udp_streams *us;
	struct tle_stream *s;

	us = CTX_UDP_STREAMS(ctx);
	if (us != NULL) {
		stbl_fini(&us->st);

		while (ctx->streams.nb_free--) {
			s = STAILQ_FIRST(&ctx->streams.free);
			STAILQ_FIRST(&ctx->streams.free) = STAILQ_NEXT(s, link);
			fini_stream(UDP_STREAM(s));
		}

	}

	rte_free(us);
	ctx->streams.buf = NULL;
	STAILQ_INIT(&ctx->streams.free);
}

/* stream memory layout:
 * [tle_udp_stream] [rx.q] [tx.drb.r]
 */
static int
add_stream(struct tle_ctx *ctx)
{
	size_t sz_s, sz_rxq, sz_drb_r, sz;
	/* for rx.q */
	uint32_t n_rxq;
	/* for tx.drb.r */
	size_t bsz, rsz;
	struct tle_drb *drb;
	uint32_t k, nb, n_drb;

	uint32_t i, f;
	char name[RTE_RING_NAMESIZE];
	struct tle_udp_stream *s;

	// stream
	sz_s = RTE_ALIGN_CEIL(sizeof(*s), RTE_CACHE_LINE_SIZE);

	// rx.q
	n_rxq = RTE_MAX(ctx->prm.max_stream_rbufs, 1U);
	n_rxq = rte_align32pow2(n_rxq);
	sz_rxq = rte_ring_get_memsize(n_rxq);
	sz_rxq = RTE_ALIGN_CEIL(sz_rxq, RTE_CACHE_LINE_SIZE);

	// tx.drb.r
	nb = drb_nb_elem(ctx);
	k = calc_stream_drb_num(ctx, nb);
	n_drb = rte_align32pow2(k);
	rsz = rte_ring_get_memsize(n_drb); /* size of the drbs ring */
	rsz = RTE_ALIGN_CEIL(rsz, RTE_CACHE_LINE_SIZE);
	bsz = tle_drb_calc_size(nb); /* size of the drb. */
	sz_drb_r = rsz + bsz * k; /* total stream drbs size. */
	sz_drb_r = RTE_ALIGN_CEIL(sz_drb_r, RTE_CACHE_LINE_SIZE);

	sz = sz_s + sz_rxq + sz_drb_r;
	s = rte_zmalloc_socket(NULL, sz, RTE_CACHE_LINE_SIZE,
				ctx->prm.socket_id);
	if (s == NULL) {
		UDP_LOG(ERR, "%s: allocation of %zu bytes on socket %d "
			"failed with error code: %d\n",
			__func__, sz, ctx->prm.socket_id, rte_errno);
		return -ENOMEM;
	}

	s->rx.q = (struct rte_ring *)((uintptr_t)s + sz_s);
	s->tx.drb.r = (struct rte_ring *)((uintptr_t)s->rx.q + sz_rxq);

	// ring flags
	f = ((ctx->prm.flags & TLE_CTX_FLAG_ST) == 0) ? 0 :
		(RING_F_SP_ENQ |  RING_F_SC_DEQ);

	/* init RX part. */
	snprintf(name, sizeof(name), "%p@%zu", s->rx.q, sz_rxq);
	rte_ring_init(s->rx.q, name, n_rxq, f);

	/* init TX part. */
	snprintf(name, sizeof(name), "%p@%zu", s->tx.drb.r, sz_drb_r);
	rte_ring_init(s->tx.drb.r, name, n_drb, f);
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
	_rte_ring_enqueue_burst(us->tx.drb.r, (void **)drb, nb_drb);
}

static int
udp_init_streams(struct tle_ctx *ctx)
{
	size_t sz;
	uint32_t i;
	int32_t rc;
	struct udp_streams *us;

	sz = sizeof(*us);
	us = rte_zmalloc_socket(NULL, sz, RTE_CACHE_LINE_SIZE,
		ctx->prm.socket_id);
	if (us == NULL) {
		UDP_LOG(ERR, "allocation of %zu bytes on socket %d "
			"for %u udp_streams failed\n",
			sz, ctx->prm.socket_id, ctx->prm.max_streams);
		return -ENOMEM;
	}

	ctx->streams.buf = us;
	STAILQ_INIT(&ctx->streams.free);

	rc = stbl_init(&us->st, (ctx->prm.flags & TLE_CTX_FLAG_ST) == 0);
	if (rc < 0) {
		UDP_LOG(ERR, "failed to init UDP stbl: rc = %dl\n", rc);
		return rc;
	}

	for (i = 0; rc == 0 && i != ctx->prm.min_streams; i++)
		rc = add_stream(ctx);

	if (rc != 0) {
		UDP_LOG(ERR, "initalisation of %u-th stream failed", i);
		udp_fini_streams(ctx);
	}

	return rc;
}

static uint32_t
udp_more_streams(struct tle_ctx *ctx)
{
	uint32_t i, nb;
	uint32_t nb_max = ctx->prm.max_streams;
	uint32_t nb_cur = ctx->streams.nb_cur;

	nb = RTE_MIN(ctx->prm.delta_streams, nb_max - nb_cur);
	for (i = 0; i < nb; i++)
		if (add_stream(ctx) != 0)
			break;

	return i;
}

static void __attribute__((constructor(101)))
udp_stream_setup(void)
{
	static const struct stream_ops udp_ops = {
		.init_streams = udp_init_streams,
		.more_streams = udp_more_streams,
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
tle_udp_stream_set(struct tle_stream *ts, struct tle_ctx *ctx,
		const struct tle_udp_stream_param *prm)
{
	struct tle_udp_stream *s;
	int32_t rc;

	if (ctx == NULL || prm == NULL || check_stream_prm(ctx, prm) != 0) {
		tle_udp_stream_close(ts);
		rte_errno = EINVAL;
		return NULL;
	}

	s = UDP_STREAM(ts);

	/* free stream's destination port */
	rc = stream_clear_ctx(ctx, &s->s);

	if (s->ste) {
		stbl_del_stream(CTX_UDP_STLB(ctx), s->ste, ts);
		s->ste = NULL;
	}

	/* copy input parameters. */
	s->prm = *prm;
	s->s.option.raw = prm->option;

	/* setup L4 ports and L3 addresses fields. */
	rc = stream_fill_ctx(ctx, &s->s,
		(const struct sockaddr *)&prm->local_addr,
		(const struct sockaddr *)&prm->remote_addr);

	if (rc != 0)
		goto error;

	/* add stream to the table for non-listen type stream */
	if (!is_empty_addr((const struct sockaddr *)&prm->remote_addr)) {
		s->ste = stbl_add_stream(CTX_UDP_STLB(ctx), &s->s);
		if (s->ste == NULL) {
			rc = EEXIST;
			goto error;
		}
	}

	return &s->s;

error:
	tle_udp_stream_close(ts);
	rte_errno = rc;
	return NULL;

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
		rte_errno = EAGAIN;
		return NULL;
	}

	/* copy input parameters. */
	s->prm = *prm;
	s->s.option.raw = prm->option;

	/* setup L4 ports and L3 addresses fields. */
	rc = stream_fill_ctx(ctx, &s->s,
		(const struct sockaddr *)&prm->local_addr,
		(const struct sockaddr *)&prm->remote_addr);

	if (rc != 0)
		goto error;

	/* add stream to the table for non-listen type stream */
	if (!is_empty_addr((const struct sockaddr *)&prm->remote_addr)) {
		s->ste = stbl_add_stream(CTX_UDP_STLB(ctx), &s->s);
		if (s->ste == NULL) {
			rc = EEXIST;
			goto error;
		}
	}

	/* setup stream notification menchanism */
	s->rx.ev = prm->recv_ev;
	s->rx.cb = prm->recv_cb;
	s->tx.ev = prm->send_ev;
	s->tx.cb = prm->send_cb;

	/* mark stream as avaialbe for RX/TX */
	if (s->tx.ev != NULL)
		tle_event_raise(s->tx.ev);
	stream_up(s);

	return &s->s;

error:
	put_stream(ctx, &s->s, 1);
	rte_errno = rc;
	return NULL;
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

	if (s->ste) {
		stbl_del_stream(CTX_UDP_STLB(ctx), s->ste, us);
		s->ste = NULL;
	}

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

/*
 * helper function, updates stream config
 */
static inline int
stream_update_cfg(struct tle_stream *us, struct tle_udp_stream_param *prm)
{
	struct tle_udp_stream *s;

	s = UDP_STREAM(us);

	/* setup stream notification menchanism */
	s->rx.ev = prm->recv_ev;
	s->rx.cb = prm->recv_cb;
	s->tx.ev = prm->send_ev;
	s->tx.cb = prm->send_cb;

	rte_smp_wmb();

	/* invoke async notifications, if any */
	if (rte_ring_count(s->rx.q) != 0) {
		if (s->rx.ev != NULL)
			tle_event_raise(s->rx.ev);
		else if (s->rx.cb.func != NULL)
			s->rx.cb.func(s->rx.cb.data, &s->s);
	}

	/* always ok to write */
	if (s->tx.ev != NULL)
		tle_event_raise(s->tx.ev);
	else if (s->tx.cb.func != NULL)
			s->tx.cb.func(s->tx.cb.data, &s->s);

	return 0;
}

uint32_t
tle_udp_stream_update_cfg(struct tle_stream *us[],
			  struct tle_udp_stream_param prm[], uint32_t num)
{
	int32_t rc;
	uint32_t i;

	for (i = 0; i != num; i++) {
		rc = stream_update_cfg(us[i], &prm[i]);
		if (rc != 0) {
			rte_errno = -rc;
			break;
		}
	}

	return i;
}

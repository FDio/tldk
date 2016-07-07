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

#include "udp_impl.h"
#include "misc.h"

#define	LPORT_START	0x8000
#define	LPORT_END	MAX_PORT_NUM

#define	LPORT_START_BLK	PORT_BLK(LPORT_START)
#define	LPORT_END_BLK	PORT_BLK(LPORT_END)

static const struct in6_addr tle_udp6_any = IN6ADDR_ANY_INIT;
static const struct in6_addr tle_udp6_none = {
	{
		.__u6_addr32 = {
			UINT32_MAX, UINT32_MAX, UINT32_MAX, UINT32_MAX
		},
	},
};

static int
check_dev_prm(const struct tle_udp_dev_param *dev_prm)
{
	/* no valid IPv4/IPv6 addresses provided. */
	if (dev_prm->local_addr4.s_addr == INADDR_ANY &&
			memcmp(&dev_prm->local_addr6, &tle_udp6_any,
			sizeof(tle_udp6_any)) == 0)
		return -EINVAL;

	return 0;
}

static void
unuse_stream(struct tle_udp_stream *s)
{
	s->type = TLE_UDP_VNUM;
	rte_atomic32_set(&s->rx.use, INT32_MIN);
	rte_atomic32_set(&s->tx.use, INT32_MIN);
}

/* calculate number of drbs per stream. */
static uint32_t
calc_stream_drb_num(const struct tle_udp_ctx *ctx, uint32_t obj_num)
{
	uint32_t num;

	num = (ctx->prm.max_stream_sbufs + obj_num - 1) / obj_num;
	num = num + num / 2;
	num = RTE_MAX(num, RTE_DIM(ctx->dev) + 1);
	return num;
}

static uint32_t
drb_nb_elem(const struct tle_udp_ctx *ctx)
{
	return (ctx->prm.send_bulk_size != 0) ?
		ctx->prm.send_bulk_size : MAX_PKT_BURST;
}

static int
init_stream(struct tle_udp_ctx *ctx, struct tle_udp_stream *s)
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
		return ENOMEM;
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
		return ENOMEM;
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

	s->ctx = ctx;
	unuse_stream(s);
	STAILQ_INSERT_TAIL(&ctx->streams.free, s, link);

	return 0;
}

static void
fini_stream(struct tle_udp_stream *s)
{
	rte_free(s->rx.q);
	rte_free(s->tx.drb.r);
}

struct tle_udp_ctx *
tle_udp_create(const struct tle_udp_ctx_param *ctx_prm)
{
	struct tle_udp_ctx *ctx;
	size_t sz;
	uint32_t i;

	if (ctx_prm == NULL) {
		rte_errno = EINVAL;
		return NULL;
	}

	sz = sizeof(*ctx);
	ctx = rte_zmalloc_socket(NULL, sz, RTE_CACHE_LINE_SIZE,
		ctx_prm->socket_id);
	if (ctx == NULL) {
		UDP_LOG(ERR, "allocation of %zu bytes for new udp_ctx "
			"on socket %d failed\n",
			sz, ctx_prm->socket_id);
		return NULL;
	}

	ctx->prm = *ctx_prm;

	sz = sizeof(*ctx->streams.buf) * ctx_prm->max_streams;
	ctx->streams.buf = rte_zmalloc_socket(NULL, sz, RTE_CACHE_LINE_SIZE,
		ctx_prm->socket_id);
	if (ctx->streams.buf == NULL) {
		UDP_LOG(ERR, "allocation of %zu bytes on socket %d "
			"for %u udp_streams failed\n",
			sz, ctx_prm->socket_id, ctx_prm->max_streams);
		tle_udp_destroy(ctx);
		return NULL;
	}

	STAILQ_INIT(&ctx->streams.free);
	for (i = 0; i != ctx_prm->max_streams &&
			init_stream(ctx, &ctx->streams.buf[i]) == 0;
			i++)
		;

	if (i != ctx_prm->max_streams) {
		UDP_LOG(ERR, "initalisation of %u-th stream failed", i);
		tle_udp_destroy(ctx);
		return NULL;
	}

	for (i = 0; i != RTE_DIM(ctx->use); i++)
		udp_pbm_init(ctx->use + i, LPORT_START_BLK);

	ctx->streams.nb_free = ctx->prm.max_streams;
	return ctx;
}

void
tle_udp_destroy(struct tle_udp_ctx *ctx)
{
	uint32_t i;

	if (ctx == NULL) {
		rte_errno = EINVAL;
		return;
	}

	for (i = 0; i != RTE_DIM(ctx->dev); i++)
		tle_udp_del_dev(ctx->dev + i);

	if (ctx->streams.buf != 0) {
		for (i = 0; i != ctx->prm.max_streams; i++)
			fini_stream(&ctx->streams.buf[i]);
		rte_free(ctx->streams.buf);
	}

	rte_free(ctx);
}

void
tle_udp_ctx_invalidate(struct tle_udp_ctx *ctx)
{
	RTE_SET_USED(ctx);
}

static int
init_dev_proto(struct tle_udp_dev *dev, uint32_t idx, int32_t socket_id)
{
	size_t sz;

	sz = sizeof(*dev->dp[idx]);
	dev->dp[idx] = rte_zmalloc_socket(NULL, sz, RTE_CACHE_LINE_SIZE,
		socket_id);

	if (dev->dp[idx] == NULL) {
		UDP_LOG(ERR, "allocation of %zu bytes on "
			"socket %d for %u-th device failed\n",
			sz, socket_id, idx);
		return ENOMEM;
	}

	udp_pbm_init(&dev->dp[idx]->use, LPORT_START_BLK);
	return 0;
}

static struct tle_udp_dev *
find_free_dev(struct tle_udp_ctx *ctx)
{
	uint32_t i;

	if (ctx->nb_dev < RTE_DIM(ctx->dev)) {
		for (i = 0; i != RTE_DIM(ctx->dev); i++) {
			if (ctx->dev[i].ctx != ctx)
				return ctx->dev + i;
		}
	}

	rte_errno = ENODEV;
	return NULL;
}

struct tle_udp_dev *
tle_udp_add_dev(struct tle_udp_ctx *ctx,
	const struct tle_udp_dev_param *dev_prm)
{
	int32_t rc;
	struct tle_udp_dev *dev;

	if (ctx == NULL || dev_prm == NULL || check_dev_prm(dev_prm) != 0) {
		rte_errno = EINVAL;
		return NULL;
	}

	dev = find_free_dev(ctx);
	if (dev == NULL)
		return NULL;
	rc = 0;

	/* device can handle IPv4 traffic */
	if (dev_prm->local_addr4.s_addr != INADDR_ANY)
		rc = init_dev_proto(dev, TLE_UDP_V4, ctx->prm.socket_id);

	/* device can handle IPv6 traffic */
	if (rc == 0 && memcmp(&dev_prm->local_addr6, &tle_udp6_any,
			sizeof(tle_udp6_any)) != 0)
		rc = init_dev_proto(dev, TLE_UDP_V6, ctx->prm.socket_id);

	if (rc != 0) {
		/* cleanup and return an error. */
		rte_free(dev->dp[TLE_UDP_V4]);
		rte_free(dev->dp[TLE_UDP_V6]);
		rte_errno = rc;
		return NULL;
	}

	/* setup RX data. */
	if (dev_prm->local_addr4.s_addr != INADDR_ANY &&
			(dev_prm->rx_offload & DEV_RX_OFFLOAD_IPV4_CKSUM) == 0)
		dev->rx.ol_flags[TLE_UDP_V4] |= PKT_RX_IP_CKSUM_BAD;
	if ((dev_prm->rx_offload & DEV_RX_OFFLOAD_UDP_CKSUM) == 0) {
		dev->rx.ol_flags[TLE_UDP_V4] |= PKT_RX_L4_CKSUM_BAD;
		dev->rx.ol_flags[TLE_UDP_V6] |= PKT_RX_L4_CKSUM_BAD;
	}

	/* setup TX data. */
	tle_dring_reset(&dev->tx.dr);

	if ((dev_prm->tx_offload & DEV_TX_OFFLOAD_UDP_CKSUM) != 0) {
		dev->tx.ol_flags[TLE_UDP_V4] |= PKT_TX_IPV4 | PKT_TX_UDP_CKSUM;
		dev->tx.ol_flags[TLE_UDP_V6] |= PKT_TX_IPV6 | PKT_TX_UDP_CKSUM;
	}
	if ((dev_prm->tx_offload & DEV_TX_OFFLOAD_IPV4_CKSUM) != 0)
		dev->tx.ol_flags[TLE_UDP_V4] |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM;

	dev->prm = *dev_prm;
	dev->ctx = ctx;
	ctx->nb_dev++;

	return dev;
}

static void
empty_dring(struct tle_dring *dr)
{
	uint32_t i, k, n;
	struct tle_udp_stream *s;
	struct rte_mbuf *pkt[MAX_PKT_BURST];
	struct tle_drb *drb[MAX_PKT_BURST];

	do {
		k = RTE_DIM(drb);
		n = tle_dring_sc_dequeue(dr, (const void **)(uintptr_t)pkt,
			RTE_DIM(pkt), drb, &k);

		/* free mbufs */
		for (i = 0; i != n; i++)
			rte_pktmbuf_free(pkt[i]);
		/* free drbs */
		for (i = 0; i != k; i++) {
			s = drb[i]->udata;
			rte_ring_enqueue(s->tx.drb.r, drb[i]);
		}
	} while (n != 0);
}

int
tle_udp_del_dev(struct tle_udp_dev *dev)
{
	uint32_t p;
	struct tle_udp_ctx *ctx;

	ctx = dev->ctx;

	if (dev == NULL || dev->ctx == NULL)
		return -EINVAL;

	p = dev - ctx->dev;

	if (p >= RTE_DIM(ctx->dev) ||
			(dev->dp[TLE_UDP_V4] == NULL &&
			dev->dp[TLE_UDP_V6] == NULL))
		return -EINVAL;

	/* emtpy TX queues. */
	empty_dring(&dev->tx.dr);

	rte_free(dev->dp[TLE_UDP_V4]);
	rte_free(dev->dp[TLE_UDP_V6]);
	memset(dev, 0, sizeof(*dev));
	ctx->nb_dev--;
	return 0;
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

static struct tle_udp_dev *
find_ipv4_dev(struct tle_udp_ctx *ctx, const struct in_addr *addr)
{
	uint32_t i;

	for (i = 0; i != RTE_DIM(ctx->dev); i++) {
		if (ctx->dev[i].prm.local_addr4.s_addr == addr->s_addr &&
				ctx->dev[i].dp[TLE_UDP_V4] != NULL)
			return ctx->dev + i;
	}

	return NULL;
}

static struct tle_udp_dev *
find_ipv6_dev(struct tle_udp_ctx *ctx, const struct in6_addr *addr)
{
	uint32_t i;

	for (i = 0; i != RTE_DIM(ctx->dev); i++) {
		if (memcmp(&ctx->dev[i].prm.local_addr6, addr,
				sizeof(*addr)) == 0 &&
				ctx->dev[i].dp[TLE_UDP_V6] != NULL)
			return ctx->dev + i;
	}

	return NULL;
}

static int
stream_fill_dev(struct tle_udp_ctx *ctx, struct tle_udp_stream *s)
{
	struct tle_udp_dev *dev;
	struct udp_pbm *pbm;
	struct sockaddr_in *lin4;
	struct sockaddr_in6 *lin6;
	uint32_t i, p, sp, t;

	if (s->prm.local_addr.ss_family == AF_INET) {
		lin4 = (struct sockaddr_in *)&s->prm.local_addr;
		t = TLE_UDP_V4;
		p = lin4->sin_port;
	} else if (s->prm.local_addr.ss_family == AF_INET6) {
		lin6 = (struct sockaddr_in6 *)&s->prm.local_addr;
		t = TLE_UDP_V6;
		p = lin6->sin6_port;
	} else
		return EINVAL;

	p = ntohs(p);

	/* if local address is not wildcard, find device it belongs to. */
	if (t == TLE_UDP_V4 && lin4->sin_addr.s_addr != INADDR_ANY) {
		dev = find_ipv4_dev(ctx, &lin4->sin_addr);
		if (dev == NULL)
			return ENODEV;
	} else if (t == TLE_UDP_V6 && memcmp(&tle_udp6_any, &lin6->sin6_addr,
			sizeof(tle_udp6_any)) != 0) {
		dev = find_ipv6_dev(ctx, &lin6->sin6_addr);
		if (dev == NULL)
			return ENODEV;
	} else
		dev = NULL;

	if (dev != NULL)
		pbm = &dev->dp[t]->use;
	else
		pbm = &ctx->use[t];

	/* try to acquire local port number. */
	if (p == 0) {
		p = udp_pbm_find_range(pbm, pbm->blk, LPORT_END_BLK);
		if (p == 0 && pbm->blk > LPORT_START_BLK)
			p = udp_pbm_find_range(pbm, LPORT_START_BLK, pbm->blk);
	} else if (udp_pbm_check(pbm, p) != 0)
		return EEXIST;

	if (p == 0)
		return ENFILE;

	/* fill socket's dst port and type */

	sp = htons(p);
	s->type = t;
	s->port.dst = sp;

	/* mark port as in-use */

	udp_pbm_set(&ctx->use[t], p);
	if (dev != NULL) {
		udp_pbm_set(pbm, p);
		dev->dp[t]->streams[sp] = s;
	} else {
		for (i = 0; i != RTE_DIM(ctx->dev); i++) {
			if (ctx->dev[i].dp[t] != NULL) {
				udp_pbm_set(&ctx->dev[i].dp[t]->use, p);
				ctx->dev[i].dp[t]->streams[sp] = s;
			}
		}
	}

	return 0;
}

static int
stream_clear_dev(struct tle_udp_ctx *ctx, struct tle_udp_stream *s)
{
	struct tle_udp_dev *dev;
	uint32_t i, p, sp, t;

	t = s->type;
	sp = s->port.dst;
	p = ntohs(sp);

	/* if local address is not wildcard, find device it belongs to. */
	if (t == TLE_UDP_V4 && s->ipv4.addr.dst != INADDR_ANY) {
		dev = find_ipv4_dev(ctx, (struct in_addr *)&s->ipv4.addr.dst);
		if (dev == NULL)
			return ENODEV;
	} else if (t == TLE_UDP_V6 && memcmp(&tle_udp6_any, &s->ipv6.addr.dst,
			sizeof(tle_udp6_any)) != 0) {
		dev = find_ipv6_dev(ctx, (struct in6_addr *)&s->ipv6.addr.dst);
		if (dev == NULL)
			return ENODEV;
	} else
		dev = NULL;

	udp_pbm_clear(&ctx->use[t], p);
	if (dev != NULL) {
		udp_pbm_clear(&dev->dp[t]->use, p);
		dev->dp[t]->streams[sp] = NULL;
	} else {
		for (i = 0; i != RTE_DIM(ctx->dev); i++) {
			if (ctx->dev[i].dp[t] != NULL) {
				udp_pbm_clear(&ctx->dev[i].dp[t]->use, p);
				ctx->dev[i].dp[t]->streams[sp] = NULL;
			}
		}
	}

	return 0;
}

static struct tle_udp_stream *
get_stream(struct tle_udp_ctx *ctx)
{
	struct tle_udp_stream *s;

	s = NULL;
	if (ctx->streams.nb_free == 0)
		return s;

	rte_spinlock_lock(&ctx->streams.lock);
	if (ctx->streams.nb_free != 0) {
		s = STAILQ_FIRST(&ctx->streams.free);
		STAILQ_REMOVE_HEAD(&ctx->streams.free, link);
		ctx->streams.nb_free--;
	}
	rte_spinlock_unlock(&ctx->streams.lock);
	return s;
}

static void
put_stream(struct tle_udp_ctx *ctx, struct tle_udp_stream *s, int32_t head)
{
	s->type = TLE_UDP_VNUM;
	rte_spinlock_lock(&ctx->streams.lock);
	if (head != 0)
		STAILQ_INSERT_HEAD(&ctx->streams.free, s, link);
	else
		STAILQ_INSERT_TAIL(&ctx->streams.free, s, link);
	ctx->streams.nb_free++;
	rte_spinlock_unlock(&ctx->streams.lock);
}

static void
fill_ipv4_am(const struct sockaddr_in *in, uint32_t *addr, uint32_t *mask)
{
	*addr = in->sin_addr.s_addr;
	*mask = (*addr == INADDR_ANY) ? INADDR_ANY : INADDR_NONE;
}

static void
fill_ipv6_am(const struct sockaddr_in6 *in, rte_xmm_t *addr, rte_xmm_t *mask)
{
	const struct in6_addr *pm;

	memcpy(addr, &in->sin6_addr, sizeof(*addr));
	if (memcmp(&tle_udp6_any, addr, sizeof(*addr)) == 0)
		pm = &tle_udp6_any;
	else
		pm = &tle_udp6_none;

	memcpy(mask, pm, sizeof(*mask));
}

static int
check_stream_prm(const struct tle_udp_stream_param *prm)
{
	if ((prm->local_addr.ss_family != AF_INET &&
			prm->local_addr.ss_family != AF_INET6) ||
			prm->local_addr.ss_family != prm->remote_addr.ss_family)
		return EINVAL;

	/* callback and event notifications mechanisms are mutually exclusive */
	if ((prm->recv_ev != NULL && prm->recv_cb.func != NULL) ||
			(prm->send_ev != NULL && prm->send_cb.func != NULL))
		return EINVAL;

	return 0;
}

struct tle_udp_stream *
tle_udp_stream_open(struct tle_udp_ctx *ctx,
	const struct tle_udp_stream_param *prm)
{
	struct tle_udp_stream *s;
	const struct sockaddr_in *rin;
	int32_t rc;

	if (ctx == NULL || prm == NULL || check_stream_prm(prm) != 0) {
		rte_errno = EINVAL;
		return NULL;
	}

	s = get_stream(ctx);
	if (s == NULL)	{
		rte_errno = ENFILE;
		return NULL;

	/* some TX still pending for that stream. */
	} else if (UDP_STREAM_TX_PENDING(s)) {
		put_stream(ctx, s, 0);
		rte_errno = EAGAIN;
		return NULL;
	}

	/* copy input parameters. */
	s->prm = *prm;

	/* setup ports and port mask fields (except dst port). */
	rin = (const struct sockaddr_in *)&prm->remote_addr;
	s->port.src = rin->sin_port;
	s->pmsk.src = (s->port.src == 0) ? 0 : UINT16_MAX;
	s->pmsk.dst = UINT16_MAX;

	/* setup src and dst addresses. */
	if (prm->local_addr.ss_family == AF_INET) {
		fill_ipv4_am((const struct sockaddr_in *)&prm->local_addr,
			&s->ipv4.addr.dst, &s->ipv4.mask.dst);
		fill_ipv4_am((const struct sockaddr_in *)&prm->remote_addr,
			&s->ipv4.addr.src, &s->ipv4.mask.src);
	} else if (prm->local_addr.ss_family == AF_INET6) {
		fill_ipv6_am((const struct sockaddr_in6 *)&prm->local_addr,
			&s->ipv6.addr.dst, &s->ipv6.mask.dst);
		fill_ipv6_am((const struct sockaddr_in6 *)&prm->remote_addr,
			&s->ipv6.addr.src, &s->ipv6.mask.src);
	}

	rte_spinlock_lock(&ctx->dev_lock);
	rc = stream_fill_dev(ctx, s);
	rte_spinlock_unlock(&ctx->dev_lock);

	if (rc != 0) {
		put_stream(ctx, s, 1);
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

	return s;
}

int
tle_udp_stream_close(struct tle_udp_stream *s)
{
	uint32_t i, n;
	int32_t rc;
	struct tle_udp_ctx *ctx;
	struct rte_mbuf *m[MAX_PKT_BURST];

	static const struct tle_udp_stream_cb zcb;

	if (s == NULL || s->type >= TLE_UDP_VNUM)
		return EINVAL;

	ctx = s->ctx;

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
	rte_spinlock_lock(&ctx->dev_lock);
	rc = stream_clear_dev(ctx, s);
	rte_spinlock_unlock(&ctx->dev_lock);

	/* empty stream's RX queue */
	do {
		n = rte_ring_dequeue_burst(s->rx.q, (void **)m, RTE_DIM(m));
		for (i = 0; i != n; i++)
			rte_pktmbuf_free(m[i]);
	} while (n != 0);

	/*
	 * mark the stream as free again.
	 * if there still are pkts queued for TX,
	 * then put this stream to the tail of free list.
	 */
	put_stream(ctx, s, UDP_STREAM_TX_FINISHED(s));
	return rc;
}

int
tle_udp_stream_get_param(const struct tle_udp_stream *s,
	struct tle_udp_stream_param *prm)
{
	struct sockaddr_in *lin4;
	struct sockaddr_in6 *lin6;

	if (prm == NULL || s == NULL || s->type >= TLE_UDP_VNUM)
		return EINVAL;

	prm[0] = s->prm;
	if (prm->local_addr.ss_family == AF_INET) {
		lin4 = (struct sockaddr_in *)&prm->local_addr;
		lin4->sin_port = s->port.dst;
	} else if (s->prm.local_addr.ss_family == AF_INET6) {
		lin6 = (struct sockaddr_in6 *)&prm->local_addr;
		lin6->sin6_port = s->port.dst;
	}

	return 0;
}

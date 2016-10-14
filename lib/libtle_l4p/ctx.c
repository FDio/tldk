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

#include "stream.h"
#include "misc.h"

#define	LPORT_START	0x8000
#define	LPORT_END	MAX_PORT_NUM

#define	LPORT_START_BLK	PORT_BLK(LPORT_START)
#define	LPORT_END_BLK	PORT_BLK(LPORT_END)

const struct in6_addr tle_ipv6_any = IN6ADDR_ANY_INIT;
const struct in6_addr tle_ipv6_none = {
	{
		.__u6_addr32 = {
			UINT32_MAX, UINT32_MAX, UINT32_MAX, UINT32_MAX
		},
	},
};

struct stream_ops tle_stream_ops[TLE_PROTO_NUM] = {};

static int
check_dev_prm(const struct tle_dev_param *dev_prm)
{
	/* no valid IPv4/IPv6 addresses provided. */
	if (dev_prm->local_addr4.s_addr == INADDR_ANY &&
			memcmp(&dev_prm->local_addr6, &tle_ipv6_any,
			sizeof(tle_ipv6_any)) == 0)
		return -EINVAL;

	if (dev_prm->bl4.nb_port > UINT16_MAX ||
			(dev_prm->bl4.nb_port != 0 &&
			dev_prm->bl4.port == NULL))
		return -EINVAL;

	if (dev_prm->bl6.nb_port > UINT16_MAX ||
			(dev_prm->bl6.nb_port != 0 &&
			dev_prm->bl6.port == NULL))
		return -EINVAL;

	return 0;
}

static int
check_ctx_prm(const struct tle_ctx_param *prm)
{
	if (prm->proto >= TLE_PROTO_NUM)
		return -EINVAL;
	return 0;
}

struct tle_ctx *
tle_ctx_create(const struct tle_ctx_param *ctx_prm)
{
	struct tle_ctx *ctx;
	size_t sz;
	uint32_t i;
	int32_t rc;

	if (ctx_prm == NULL || check_ctx_prm(ctx_prm) != 0) {
		rte_errno = EINVAL;
		return NULL;
	}

	sz = sizeof(*ctx);
	ctx = rte_zmalloc_socket(NULL, sz, RTE_CACHE_LINE_SIZE,
		ctx_prm->socket_id);
	if (ctx == NULL) {
		UDP_LOG(ERR, "allocation of %zu bytes for new ctx "
			"on socket %d failed\n",
			sz, ctx_prm->socket_id);
		return NULL;
	}

	ctx->prm = *ctx_prm;

	rc = tle_stream_ops[ctx_prm->proto].init_streams(ctx);
	if (rc != 0) {
		UDP_LOG(ERR, "init_streams(ctx=%p, proto=%u) failed "
			"with error code: %d;\n",
			ctx, ctx_prm->proto, rc);
		tle_ctx_destroy(ctx);
		rte_errno = -rc;
		return NULL;
	}

	for (i = 0; i != RTE_DIM(ctx->use); i++)
		tle_pbm_init(ctx->use + i, LPORT_START_BLK);

	ctx->streams.nb_free = ctx->prm.max_streams;
	return ctx;
}

void
tle_ctx_destroy(struct tle_ctx *ctx)
{
	uint32_t i;

	if (ctx == NULL) {
		rte_errno = EINVAL;
		return;
	}

	for (i = 0; i != RTE_DIM(ctx->dev); i++)
		tle_del_dev(ctx->dev + i);

	tle_stream_ops[ctx->prm.proto].fini_streams(ctx);
	rte_free(ctx);
}

void
tle_ctx_invalidate(struct tle_ctx *ctx)
{
	RTE_SET_USED(ctx);
}

static void
fill_pbm(struct tle_pbm *pbm, const struct tle_bl_port *blp)
{
	uint32_t i;

	for (i = 0; i != blp->nb_port; i++)
		tle_pbm_set(pbm, blp->port[i]);
}

static int
init_dev_proto(struct tle_dev *dev, uint32_t idx, int32_t socket_id,
	const struct tle_bl_port *blp)
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

	tle_pbm_init(&dev->dp[idx]->use, LPORT_START_BLK);
	fill_pbm(&dev->dp[idx]->use, blp);
	return 0;
}

static struct tle_dev *
find_free_dev(struct tle_ctx *ctx)
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

struct tle_dev *
tle_add_dev(struct tle_ctx *ctx, const struct tle_dev_param *dev_prm)
{
	int32_t rc;
	struct tle_dev *dev;

	if (ctx == NULL || dev_prm == NULL || check_dev_prm(dev_prm) != 0) {
		rte_errno = EINVAL;
		return NULL;
	}

	dev = find_free_dev(ctx);
	if (dev == NULL)
		return NULL;
	rc = 0;

	/* device can handle IPv4 traffic */
	if (dev_prm->local_addr4.s_addr != INADDR_ANY) {
		rc = init_dev_proto(dev, TLE_V4, ctx->prm.socket_id,
			&dev_prm->bl4);
		if (rc == 0)
			fill_pbm(&ctx->use[TLE_V4], &dev_prm->bl4);
	}

	/* device can handle IPv6 traffic */
	if (rc == 0 && memcmp(&dev_prm->local_addr6, &tle_ipv6_any,
			sizeof(tle_ipv6_any)) != 0) {
		rc = init_dev_proto(dev, TLE_V6, ctx->prm.socket_id,
			&dev_prm->bl6);
		if (rc == 0)
			fill_pbm(&ctx->use[TLE_V6], &dev_prm->bl6);
	}

	if (rc != 0) {
		/* cleanup and return an error. */
		rte_free(dev->dp[TLE_V4]);
		rte_free(dev->dp[TLE_V6]);
		rte_errno = rc;
		return NULL;
	}

	/* setup RX data. */
	if (dev_prm->local_addr4.s_addr != INADDR_ANY &&
			(dev_prm->rx_offload & DEV_RX_OFFLOAD_IPV4_CKSUM) == 0)
		dev->rx.ol_flags[TLE_V4] |= PKT_RX_IP_CKSUM_BAD;

	if (((dev_prm->rx_offload & DEV_RX_OFFLOAD_UDP_CKSUM) == 0 &&
			ctx->prm.proto == TLE_PROTO_UDP) ||
			((dev_prm->rx_offload &
			DEV_RX_OFFLOAD_TCP_CKSUM) == 0 &&
			ctx->prm.proto == TLE_PROTO_TCP)) {
		dev->rx.ol_flags[TLE_V4] |= PKT_RX_L4_CKSUM_BAD;
		dev->rx.ol_flags[TLE_V6] |= PKT_RX_L4_CKSUM_BAD;
	}

	/* setup TX data. */
	tle_dring_reset(&dev->tx.dr);

	if ((dev_prm->tx_offload & DEV_TX_OFFLOAD_UDP_CKSUM) != 0 &&
			ctx->prm.proto == TLE_PROTO_UDP) {
		dev->tx.ol_flags[TLE_V4] |= PKT_TX_IPV4 | PKT_TX_UDP_CKSUM;
		dev->tx.ol_flags[TLE_V6] |= PKT_TX_IPV6 | PKT_TX_UDP_CKSUM;
	} else if ((dev_prm->tx_offload & DEV_TX_OFFLOAD_TCP_CKSUM) != 0 &&
			ctx->prm.proto == TLE_PROTO_TCP) {
		dev->tx.ol_flags[TLE_V4] |= PKT_TX_IPV4 | PKT_TX_TCP_CKSUM;
		dev->tx.ol_flags[TLE_V6] |= PKT_TX_IPV6 | PKT_TX_TCP_CKSUM;
	}

	if ((dev_prm->tx_offload & DEV_TX_OFFLOAD_IPV4_CKSUM) != 0)
		dev->tx.ol_flags[TLE_V4] |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM;

	dev->prm = *dev_prm;
	dev->ctx = ctx;
	ctx->nb_dev++;

	return dev;
}

static void
empty_dring(struct tle_dring *dr, uint32_t proto)
{
	uint32_t i, k, n;
	struct tle_stream *s;
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
			tle_stream_ops[proto].free_drbs(s, drb + i, 1);
		}
	} while (n != 0);
}

int
tle_del_dev(struct tle_dev *dev)
{
	uint32_t p;
	struct tle_ctx *ctx;

	if (dev == NULL || dev->ctx == NULL)
		return -EINVAL;

	ctx = dev->ctx;
	p = dev - ctx->dev;

	if (p >= RTE_DIM(ctx->dev) ||
			(dev->dp[TLE_V4] == NULL &&
			dev->dp[TLE_V6] == NULL))
		return -EINVAL;

	/* emtpy TX queues. */
	empty_dring(&dev->tx.dr, ctx->prm.proto);

	rte_free(dev->dp[TLE_V4]);
	rte_free(dev->dp[TLE_V6]);
	memset(dev, 0, sizeof(*dev));
	ctx->nb_dev--;
	return 0;
}

static struct tle_dev *
find_ipv4_dev(struct tle_ctx *ctx, const struct in_addr *addr)
{
	uint32_t i;

	for (i = 0; i != RTE_DIM(ctx->dev); i++) {
		if (ctx->dev[i].prm.local_addr4.s_addr == addr->s_addr &&
				ctx->dev[i].dp[TLE_V4] != NULL)
			return ctx->dev + i;
	}

	return NULL;
}

static struct tle_dev *
find_ipv6_dev(struct tle_ctx *ctx, const struct in6_addr *addr)
{
	uint32_t i;

	for (i = 0; i != RTE_DIM(ctx->dev); i++) {
		if (memcmp(&ctx->dev[i].prm.local_addr6, addr,
				sizeof(*addr)) == 0 &&
				ctx->dev[i].dp[TLE_V6] != NULL)
			return ctx->dev + i;
	}

	return NULL;
}

static int
stream_fill_dev(struct tle_ctx *ctx, struct tle_stream *s,
	const struct sockaddr *addr)
{
	struct tle_dev *dev;
	struct tle_pbm *pbm;
	const struct sockaddr_in *lin4;
	const struct sockaddr_in6 *lin6;
	uint32_t i, p, sp, t;

	if (addr->sa_family == AF_INET) {
		lin4 = (const struct sockaddr_in *)addr;
		t = TLE_V4;
		p = lin4->sin_port;
	} else if (addr->sa_family == AF_INET6) {
		lin6 = (const struct sockaddr_in6 *)addr;
		t = TLE_V6;
		p = lin6->sin6_port;
	} else
		return EINVAL;

	p = ntohs(p);

	/* if local address is not wildcard, find device it belongs to. */
	if (t == TLE_V4 && lin4->sin_addr.s_addr != INADDR_ANY) {
		dev = find_ipv4_dev(ctx, &lin4->sin_addr);
		if (dev == NULL)
			return ENODEV;
	} else if (t == TLE_V6 && memcmp(&tle_ipv6_any, &lin6->sin6_addr,
			sizeof(tle_ipv6_any)) != 0) {
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
		p = tle_pbm_find_range(pbm, pbm->blk, LPORT_END_BLK);
		if (p == 0 && pbm->blk > LPORT_START_BLK)
			p = tle_pbm_find_range(pbm, LPORT_START_BLK, pbm->blk);
	} else if (tle_pbm_check(pbm, p) != 0)
		return EEXIST;

	if (p == 0)
		return ENFILE;

	/* fill socket's dst port and type */

	sp = htons(p);
	s->type = t;
	s->port.dst = sp;

	/* mark port as in-use */

	tle_pbm_set(&ctx->use[t], p);
	if (dev != NULL) {
		tle_pbm_set(pbm, p);
		dev->dp[t]->streams[sp] = s;
	} else {
		for (i = 0; i != RTE_DIM(ctx->dev); i++) {
			if (ctx->dev[i].dp[t] != NULL) {
				tle_pbm_set(&ctx->dev[i].dp[t]->use, p);
				ctx->dev[i].dp[t]->streams[sp] = s;
			}
		}
	}

	return 0;
}

static int
stream_clear_dev(struct tle_ctx *ctx, const struct tle_stream *s)
{
	struct tle_dev *dev;
	uint32_t i, p, sp, t;

	t = s->type;
	sp = s->port.dst;
	p = ntohs(sp);

	/* if local address is not wildcard, find device it belongs to. */
	if (t == TLE_V4 && s->ipv4.addr.dst != INADDR_ANY) {
		dev = find_ipv4_dev(ctx,
			(const struct in_addr *)&s->ipv4.addr.dst);
		if (dev == NULL)
			return ENODEV;
	} else if (t == TLE_V6 && memcmp(&tle_ipv6_any, &s->ipv6.addr.dst,
			sizeof(tle_ipv6_any)) != 0) {
		dev = find_ipv6_dev(ctx,
			(const struct in6_addr *)&s->ipv6.addr.dst);
		if (dev == NULL)
			return ENODEV;
	} else
		dev = NULL;

	tle_pbm_clear(&ctx->use[t], p);
	if (dev != NULL) {
		if (dev->dp[t]->streams[sp] == s) {
			tle_pbm_clear(&dev->dp[t]->use, p);
			dev->dp[t]->streams[sp] = NULL;
		}
	} else {
		for (i = 0; i != RTE_DIM(ctx->dev); i++) {
			if (ctx->dev[i].dp[t] != NULL &&
					ctx->dev[i].dp[t]->streams[sp] == s) {
				tle_pbm_clear(&ctx->dev[i].dp[t]->use, p);
				ctx->dev[i].dp[t]->streams[sp] = NULL;
			}
		}
	}

	return 0;
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
	if (memcmp(&tle_ipv6_any, addr, sizeof(*addr)) == 0)
		pm = &tle_ipv6_any;
	else
		pm = &tle_ipv6_none;

	memcpy(mask, pm, sizeof(*mask));
}

int
stream_fill_ctx(struct tle_ctx *ctx, struct tle_stream *s,
	const struct sockaddr *laddr, const struct sockaddr *raddr)
{
	const struct sockaddr_in *rin;
	int32_t rc;

	/* setup ports and port mask fields (except dst port). */
	rin = (const struct sockaddr_in *)raddr;
	s->port.src = rin->sin_port;
	s->pmsk.src = (s->port.src == 0) ? 0 : UINT16_MAX;
	s->pmsk.dst = UINT16_MAX;

	/* setup src and dst addresses. */
	if (laddr->sa_family == AF_INET) {
		fill_ipv4_am((const struct sockaddr_in *)laddr,
			&s->ipv4.addr.dst, &s->ipv4.mask.dst);
		fill_ipv4_am((const struct sockaddr_in *)raddr,
			&s->ipv4.addr.src, &s->ipv4.mask.src);
	} else if (laddr->sa_family == AF_INET6) {
		fill_ipv6_am((const struct sockaddr_in6 *)laddr,
			&s->ipv6.addr.dst, &s->ipv6.mask.dst);
		fill_ipv6_am((const struct sockaddr_in6 *)raddr,
			&s->ipv6.addr.src, &s->ipv6.mask.src);
	}

	rte_spinlock_lock(&ctx->dev_lock);
	rc = stream_fill_dev(ctx, s, laddr);
	rte_spinlock_unlock(&ctx->dev_lock);

	return rc;
}

/* free stream's destination port */
int
stream_clear_ctx(struct tle_ctx *ctx, struct tle_stream *s)
{
	int32_t rc;

	rte_spinlock_lock(&ctx->dev_lock);
	rc = stream_clear_dev(ctx, s);
	rte_spinlock_unlock(&ctx->dev_lock);

	return rc;
}

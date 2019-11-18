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

#include <string.h>
#include <rte_malloc.h>
#include <rte_errno.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_ip.h>

#include "stream.h"
#include "stream_table.h"
#include "misc.h"
#include <halfsiphash.h>

struct tle_mib default_mib;

RTE_DEFINE_PER_LCORE(struct tle_mib *, mib) = &default_mib;

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
	if (prm->hash_alg >= TLE_HASH_NUM)
		return -EINVAL;
	return 0;
}

struct tle_ctx *
tle_ctx_create(const struct tle_ctx_param *ctx_prm)
{
	struct tle_ctx *ctx;
	size_t sz;
	uint64_t ms;
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

	/* caclulate closest shift to convert from cycles to ms (approximate) */
	ms = (rte_get_tsc_hz() + MS_PER_S - 1) / MS_PER_S;
	ctx->cycles_ms_shift = sizeof(ms) * CHAR_BIT - __builtin_clzll(ms) - 1;

	ctx->prm = *ctx_prm;

	rc = bhash_init(ctx);
	if (rc != 0) {
		UDP_LOG(ERR, "create bhash table (ctx=%p, proto=%u) failed "
			"with error code: %d;\n",
			ctx, ctx_prm->proto, rc);
		tle_ctx_destroy(ctx);
		rte_errno = -rc;
		return NULL;
	}

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
		tle_psm_init(ctx->use + i);

	ctx->streams.nb_free = ctx->prm.min_streams;
	ctx->streams.nb_cur = ctx->prm.min_streams;

	/* Initialization of siphash state is done here to speed up the
	 * fastpath processing.
	 */
	if (ctx->prm.hash_alg == TLE_SIPHASH)
		siphash_initialization(&ctx->prm.secret_key,
					&ctx->prm.secret_key);

	rte_spinlock_init(&ctx->dev_lock);
	rte_spinlock_init(&ctx->bhash_lock[TLE_V4]);
	rte_spinlock_init(&ctx->bhash_lock[TLE_V6]);

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

	bhash_fini(ctx);

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
	uint32_t df;
	struct tle_dev *dev;

	if (ctx == NULL || dev_prm == NULL || check_dev_prm(dev_prm) != 0) {
		rte_errno = EINVAL;
		return NULL;
	}

	dev = find_free_dev(ctx);
	if (dev == NULL)
		return NULL;
	rc = 0;

	if (rc != 0) {
		/* cleanup and return an error. */
		rte_errno = rc;
		return NULL;
	}

	/* setup TX data. */
	df = ((ctx->prm.flags & TLE_CTX_FLAG_ST) == 0) ? 0 :
		RING_F_SP_ENQ | RING_F_SC_DEQ;
	tle_dring_reset(&dev->tx.dr, df);

	if ((dev_prm->tx_offload & DEV_TX_OFFLOAD_UDP_CKSUM) != 0 &&
			ctx->prm.proto == TLE_PROTO_UDP) {
		dev->tx.ol_flags[TLE_V4] |= PKT_TX_UDP_CKSUM;
		dev->tx.ol_flags[TLE_V6] |= PKT_TX_UDP_CKSUM;
	} else if ((dev_prm->tx_offload & DEV_TX_OFFLOAD_TCP_CKSUM) != 0 &&
			ctx->prm.proto == TLE_PROTO_TCP) {
		dev->tx.ol_flags[TLE_V4] |= PKT_TX_TCP_CKSUM;
		dev->tx.ol_flags[TLE_V6] |= PKT_TX_TCP_CKSUM;
	}

	if ((dev_prm->tx_offload & DEV_TX_OFFLOAD_IPV4_CKSUM) != 0)
		dev->tx.ol_flags[TLE_V4] |= PKT_TX_IP_CKSUM;

	dev->tx.ol_flags[TLE_V4] |= PKT_TX_IPV4;
	dev->tx.ol_flags[TLE_V6] |= PKT_TX_IPV6;

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

	if (p >= RTE_DIM(ctx->dev))
		return -EINVAL;

	/* emtpy TX queues. */
	empty_dring(&dev->tx.dr, ctx->prm.proto);

	memset(dev, 0, sizeof(*dev));
	ctx->nb_dev--;
	return 0;
}

int
stream_fill_ctx(struct tle_ctx *ctx, struct tle_stream *s,
	const struct sockaddr *laddr, const struct sockaddr *raddr)
{
	struct sockaddr_storage addr;
	int32_t rc = 0;

	if (laddr->sa_family == AF_INET) {
		s->type = TLE_V4;
	} else if (laddr->sa_family == AF_INET6) {
		s->type = TLE_V6;
	}

	uint16_t p = ((const struct sockaddr_in *)laddr)->sin_port;
	p = ntohs(p);
	struct tle_psm *psm = &ctx->use[s->type];
	/* try to acquire local port number. */
	rte_spinlock_lock(&ctx->dev_lock);
	if (p == 0) {
		if (s->type == TLE_V6 && is_empty_addr(laddr) && !s->option.ipv6only)
			p = tle_psm_alloc_dual_port(&ctx->use[TLE_V4], psm);
		else
			p = tle_psm_alloc_port(psm);
		if (p == 0) {
			rte_spinlock_unlock(&ctx->dev_lock);
			return ENFILE;
		}
		rte_memcpy(&addr, laddr, sizeof(struct sockaddr_storage));
		((struct sockaddr_in *)&addr)->sin_port = htons(p);
		laddr = (const struct sockaddr*)&addr;
	}

	if (tle_psm_set(psm, p, s->option.reuseport) != 0) {
		rte_spinlock_unlock(&ctx->dev_lock);
		return EADDRINUSE;
	}

	if (is_empty_addr(laddr)) {
		if (s->type == TLE_V6 && !s->option.ipv6only) {
			rc = tle_psm_set(&ctx->use[TLE_V4], p, s->option.reuseport);
			if (rc != 0) {
				tle_psm_clear(psm, p);
				rte_spinlock_unlock(&ctx->dev_lock);
				return EADDRINUSE;
			}
		}
	}

	if (is_empty_addr(raddr))
		rc = bhash_add_entry(ctx, laddr, s);

	if (rc) {
		tle_psm_clear(psm, p);
	}

	rte_spinlock_unlock(&ctx->dev_lock);
	/* fill socket's dst (src actually) port */
	s->port.dst = htons(p);

	if (rc)
		return rc;

	/* setup src, dst addresses, and src port. */
	if (laddr->sa_family == AF_INET) {
		fill_ipv4_am((const struct sockaddr_in *)laddr,
			&s->ipv4.addr.dst, &s->ipv4.mask.dst);
		fill_ipv4_am((const struct sockaddr_in *)raddr,
			&s->ipv4.addr.src, &s->ipv4.mask.src);
		s->port.src = ((const struct sockaddr_in *)raddr)->sin_port;
	} else if (laddr->sa_family == AF_INET6) {
		fill_ipv6_am((const struct sockaddr_in6 *)laddr,
			&s->ipv6.addr.dst, &s->ipv6.mask.dst);
		fill_ipv6_am((const struct sockaddr_in6 *)raddr,
			&s->ipv6.addr.src, &s->ipv6.mask.src);
		s->port.src = ((const struct sockaddr_in6 *)raddr)->sin6_port;
	}

	/* setup port mask fields. */
	s->pmsk.src = (s->port.src == 0) ? 0 : UINT16_MAX;
	s->pmsk.dst = UINT16_MAX;

	return rc;
}

/* free stream's destination port */
int
stream_clear_ctx(struct tle_ctx *ctx, struct tle_stream *s)
{
	bool is_any = false;
	struct sockaddr_storage addr;
	struct sockaddr_in *addr4;
	struct sockaddr_in6 *addr6;

	if (s->type == TLE_V4) {
		if (s->ipv4.addr.src == INADDR_ANY) {
			is_any = true;
			addr4 = (struct sockaddr_in *)&addr;
			addr4->sin_addr.s_addr = s->ipv4.addr.dst;
			addr4->sin_port = s->port.dst;
			addr.ss_family = AF_INET;
			bhash_del_entry(ctx, s, (struct sockaddr*)&addr);
		}
	} else {
		if (IN6_IS_ADDR_UNSPECIFIED(&s->ipv6.addr.src)) {
			is_any = true;
			addr6 = (struct sockaddr_in6 *)&addr;
			memcpy(&addr6->sin6_addr, &s->ipv6.addr.dst,
					sizeof(tle_ipv6_any));
			addr6->sin6_port = s->port.dst;
			addr.ss_family = AF_INET6;
			bhash_del_entry(ctx, s, (struct sockaddr*)&addr);
		}
	}

	rte_spinlock_lock(&ctx->dev_lock);
	/* strange behaviour to match linux stack */
	if (is_any) {
		if (s->type == TLE_V6 && !s->option.ipv6only)
			tle_psm_clear(&ctx->use[TLE_V4], ntohs(s->port.dst));
	}

	tle_psm_clear(&ctx->use[s->type], ntohs(s->port.dst));
	rte_spinlock_unlock(&ctx->dev_lock);

	return 0;
}

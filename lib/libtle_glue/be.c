/*
 * Copyright (c) 2018 Ant Financial Services Group.
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

#include <rte_ethdev.h>
#include <rte_ip.h>

#include <tle_tcp.h>
#include <tle_udp.h>

#include "config.h"
#include "log.h"
#include "util.h"
#include "internal.h"

static inline void
rte_pktmbuf_copy_seg(struct rte_mbuf *dst, struct rte_mbuf* src)
{
	size_t offset = offsetof(struct rte_mbuf, data_off);
	rte_memcpy((char*)dst + offset, (char*)src + offset,
		   sizeof(struct rte_mbuf) - offset);
	rte_mbuf_refcnt_set(dst, 1);
	dst->ol_flags &= ~IND_ATTACHED_MBUF;
	rte_memcpy(rte_pktmbuf_mtod(dst, void*), rte_pktmbuf_mtod(src, void*),
		   src->data_len);
}

static inline struct rte_mbuf*
rte_pktmbuf_copy(struct rte_mbuf *md, struct rte_mempool* mp)
{
	struct rte_mbuf *mc, *mi, **prev;
	uint32_t pktlen;
	uint16_t nseg;

	if (unlikely ((mc = rte_pktmbuf_alloc(mp)) == NULL))
		return NULL;

	mi = mc;
	prev = &mi->next;
	pktlen = md->pkt_len;
	nseg = 0;

	do {
		nseg++;
		rte_pktmbuf_copy_seg(mi, md);
		*prev = mi;
		prev = &mi->next;
	} while ((md = md->next) != NULL &&
	    (mi = rte_pktmbuf_alloc(mp)) != NULL);

	*prev = NULL;
	mc->nb_segs = nseg;
	mc->pkt_len = pktlen;

	/* Allocation of new indirect segment failed */
	if (unlikely(mi == NULL)) {
		rte_pktmbuf_free(mc);
		return NULL;
	}

	__rte_mbuf_sanity_check(mc, 1);
	return mc;
}

static inline int
process_rx_pkts(struct glue_ctx *ctx, struct rte_mbuf *pkts[],
		uint32_t n, uint8_t from_loopback)
{
	uint32_t i, j, k, jt, ju, jd;
	struct rte_mbuf *tcp[MAX_PKTS_BURST];
	struct rte_mbuf *udp[MAX_PKTS_BURST];
	struct rte_mbuf *drop[MAX_PKTS_BURST];
	int32_t rc[MAX_PKTS_BURST];
	struct tle_dev *tcp_dev, *udp_dev;
	struct rte_mempool *mp;
	struct rte_mbuf *tmp;
	uint64_t ts;

	if (n == 0)
		return 0;

	if (unlikely(from_loopback)) {
		tcp_dev = ctx->lb_tcp_dev;
		udp_dev = ctx->lb_udp_dev;
		mp = pkts[0]->pool;
		for (i = 0; i < n; i++) {
			tmp = rte_pktmbuf_copy(pkts[i], mp);
			if (tmp != NULL) {
				rte_pktmbuf_free(pkts[i]);
				pkts[i] = tmp;
				pkts[i]->ol_flags |= PKT_RX_IP_CKSUM_GOOD;
				pkts[i]->ol_flags |= PKT_RX_L4_CKSUM_GOOD;
			} else {
				k = i;
				for (; i < n; i++) {
					rte_pktmbuf_free(pkts[i]);
				}
				n = k;
			}
		}
	} else {
		tcp_dev = ctx->tcp_dev;
		udp_dev = ctx->udp_dev;
	}

	ts = rte_get_tsc_cycles() >> (ctx->cycles_ms_shift - 10);

	for (j = 0, jt = 0, ju = 0, jd = 0; j < n; j++) {
		pkts[j]->timestamp = ts;
		switch (pkts[j]->packet_type & RTE_PTYPE_L4_MASK) {
		case RTE_PTYPE_L4_TCP:
			tcp[jt++] = pkts[j];
			break;
		case RTE_PTYPE_L4_UDP:
			udp[ju++] = pkts[j];
			break;
		case RTE_PTYPE_L4_ICMP:
			/* TODO */
		case RTE_PTYPE_L4_FRAG:
			/* TODO */
		default:
			drop[jd++] = pkts[j];
		}
	}

	if (jt > 0) {
		k = tle_tcp_rx_bulk(tcp_dev, tcp, drop + jd, rc, jt);
		jd += jt - k;

		TRACE("(port=%u, queue=%u), %u/%u (TCP) pkts are received",
		      port_id, queue_id, k, n);
	}

	if (ju > 0) {
		k = tle_udp_rx_bulk(udp_dev, udp, drop + jd, rc, ju);
		jd += ju - k;

		TRACE("(port=%u, queue=%u), %u/%u (UDP) pkts are received",
		      port_id, queue_id, k, n);
	}

	for (j = 0; j < jd; j++)
		rte_pktmbuf_free(drop[j]);

	return jt + ju - jd;
}

static inline int
be_rx(struct glue_ctx *ctx)
{
	int ret;
	uint32_t n;
	struct rte_mbuf *pkts[MAX_PKTS_BURST];
	uint16_t port_id = ctx->port_id;
	uint16_t queue_id = ctx->queue_id;

	n = rte_eth_rx_burst(port_id, queue_id, pkts, RTE_DIM(pkts));
	ret = process_rx_pkts(ctx, pkts, n, 0);

	return ret;
}

int
be_tx(struct glue_ctx *ctx)
{
	uint32_t n, j, k, s, ret;
	const uint16_t max_pkts = MAX_PKTS_BURST;
	struct rte_mbuf *pkts[max_pkts];
	struct rte_mbuf *_pkts[max_pkts];
	uint16_t port_id = ctx->port_id;
	uint16_t queue_id = ctx->queue_id;

	ret = 0;
	tle_tcp_process(ctx->tcp_ctx, TCP_MAX_PROCESS);

	n = tle_tcp_tx_bulk(ctx->lb_tcp_dev, pkts, max_pkts);
	n += tle_udp_tx_bulk(ctx->lb_udp_dev, pkts + n, max_pkts - n);
	if (n > 0) {
		ret += n;
		rte_eth_tx_burst(ctx->lb_port_id, 0, pkts, n);
		/* loopback device could receive after transmit immediately */
		n = rte_eth_rx_burst(ctx->lb_port_id, 0, pkts, RTE_DIM(pkts));
		process_rx_pkts(ctx, pkts, n, 1);

		/* wake up look-aside backend */
		wake_lookaside_backend(ctx);
	}

	n = tle_tcp_tx_bulk(ctx->tcp_dev, pkts, max_pkts);
	n += tle_udp_tx_bulk(ctx->udp_dev, pkts + n, max_pkts - n);
	if (n == 0)
		return 0;

	ret += n;
	s = 0;
	for (j = 0; j != n; j++) {
		if (mac_fill(ctx, pkts[j]) == 0) {
			PKT_DUMP(pkts[j]);
			_pkts[s++] = pkts[j];
			continue;
		}

		pkts[j]->next_pkt = ctx->arp_wait;
		ctx->arp_wait = pkts[j];
	}

	/* For virtio-user/vhost-kernel test case, it's normal that vhost
	 * kthread cannot catch up with packets generation speed in stack.
	 * Shall we drop those packets immdiately or retry some times to
	 * keep those packets? We find dropping packets here is not a good
	 * idea, which leads to lots of retrans and inefficiency of vhost
	 * kthread. Even below code does not work well:
	 *
	 * for (k = 0, retry = 0; k < s && retry < 10000; retry++)
	 *	k += rte_eth_tx_burst(port_id, queue_id, _pkts + k, s - k);
	 * 
	 * So we choose to blockingly send out packes.
	 */
	k = 0;
	while (k < s)
		k += rte_eth_tx_burst(port_id, queue_id, _pkts + k, s - k);

	for (j = k; j != s; j++)
		rte_pktmbuf_free(_pkts[j]);

	TRACE("(port=%u, queue=%u), %u/%u pkts are sent",
		port_id, queue_id, k, s);

	return ret;
}

int
be_process(struct glue_ctx *ctx)
{
	int ret;

	if (unlikely(stopped))
		return 0;

	ret = be_rx(ctx);
	mac_timeout(ctx);
	ret += be_tx(ctx);

	return ret;
}

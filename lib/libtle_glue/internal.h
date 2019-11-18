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

#ifndef _TLE_GLUE_INTERNAL_H_
#define _TLE_GLUE_INTERNAL_H_

#include <rte_mbuf.h>
#include <rte_atomic.h>

#include <tle_ctx.h>

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>

#include "ctx.h"
#include "sym.h"
#include <rte_mempool.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int stopped;

extern uint64_t rx_offload;
extern uint64_t tx_offload;

void port_reconfig(void);

uint16_t create_loopback(uint32_t socket_id);

struct rte_mempool * get_mempool_by_socket(int32_t socket_id);

int be_process(struct glue_ctx *ctx);

int be_tx(struct glue_ctx *ctx);

struct rte_mbuf * arp_recv(struct glue_ctx *ctx,
			   struct rte_mbuf *m, uint32_t l2len);

struct rte_mbuf * ndp_recv(struct glue_ctx *ctx,
			   struct rte_mbuf *m, uint32_t l2len, uint32_t l3len);


void mac_check(struct glue_ctx *ctx, const struct sockaddr* addr);

int arp_ipv4_dst_lookup(void *data, const struct in_addr *addr,
			struct tle_dest *res, int proto);

int arp_ipv6_dst_lookup(void *data, const struct in6_addr *addr,
			struct tle_dest *res, int proto);

int mac_fill(struct glue_ctx *ctx, struct rte_mbuf *m);

void mac_timeout(struct glue_ctx *ctx);

int setup_rx_cb(uint16_t port_id, uint16_t qid);

int epoll_kernel_wait(struct glue_ctx *ctx, int efd,
		      struct epoll_event *events,
		      int maxevents, int timeout, int *rx);

int poll_common(struct glue_ctx *ctx, struct epoll_event *events,
		int maxevents, int timeout, int shadow_efd);

int dev_rxq_wakeup(uint16_t port_id);

struct rte_mbuf * icmp_recv(struct glue_ctx *ctx, struct rte_mbuf *pkt,
			    uint32_t l2len, uint32_t l3len);

struct rte_mbuf * icmp6_recv(struct glue_ctx *ctx, struct rte_mbuf *pkt,
			     uint32_t l2len, uint32_t l3len);

uint16_t typen_rx_callback(uint16_t port, uint16_t queue,
			   struct rte_mbuf *pkt[], uint16_t nb_pkts,
			   uint16_t max_pkts, void *user_param);

void ipv4_dst_add(struct glue_ctx *ctx, const struct in_addr *addr,
		  struct ether_addr *e_addr);

void ipv6_dst_add(struct glue_ctx *ctx, const struct in6_addr *addr,
		  struct ether_addr *e_addr);

#ifdef LOOK_ASIDE_BACKEND
extern rte_atomic32_t flag_sleep;

enum {
	IOTHREAD_BUSY = 0, /* io thread is busy */
	IOTHREAD_SLEEP,    /* io thread is sleeping */
	IOTHREAD_PREEMPT,  /* io thread is preempted by another worker thread */
};

static inline int
sleep_with_lock(int efd, struct epoll_event *events, int max, int to)
{
	int rc;

	rte_atomic32_set(&flag_sleep, IOTHREAD_SLEEP);
	rc = k_epoll_pwait(efd, events, max, to, NULL);
	while (rte_atomic32_cmpset((volatile uint32_t *)&flag_sleep,
				   IOTHREAD_SLEEP, IOTHREAD_BUSY) == 0);

	return rc;
}

static inline void
be_tx_with_lock(struct glue_ctx *ctx)
{
	if (rte_atomic32_cmpset((volatile uint32_t *)&flag_sleep,
				IOTHREAD_SLEEP, IOTHREAD_PREEMPT)) {
		while (be_tx(ctx) > 0) {};
		rte_atomic32_set(&flag_sleep, IOTHREAD_SLEEP);
	}
}

static inline void
wake_lookaside_backend(struct glue_ctx *ctx)
{
	if (rte_atomic32_read(&flag_sleep) == IOTHREAD_PREEMPT)
		dev_rxq_wakeup(ctx->port_id);
}

static inline bool
io_thread_in_sleep(void)
{
	return rte_atomic32_read(&flag_sleep) == IOTHREAD_SLEEP;
}
#else
#define sleep_with_lock k_epoll_wait
#define be_tx_with_lock(ctx) do {} while(0)
#define wake_lookaside_backend(ctx) do {} while(0)
#endif

#ifdef __cplusplus
}
#endif

#endif /* _TLE_GLUE_INTERNAL_H_ */

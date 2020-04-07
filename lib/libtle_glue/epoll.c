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

#include <errno.h>

#include <rte_common.h>
#include <rte_spinlock.h>
#include <rte_malloc.h>
#include <rte_ethdev.h>
#include <rte_atomic.h>
#include <rte_eal_interrupts.h>

#include "fd.h"
#include "ctx.h"
#include "sym.h"
#include "log.h"
#include "util.h"
#include "sock.h"
#include "internal.h"
#include "tle_glue.h"
#include "../libtle_l4p/udp_stream.h"
#include "../libtle_l4p/tcp_stream.h"

#define EPOLL_DATA_SPECIAL	0xFFFFFFFFFFFFFF01

/* We don't use rte_eth_dev_rx_intr_ctl_q as it has its
 * own way to specify event.data
 */
int
dev_rx_intr_ctl_q(uint16_t port_id, uint16_t queue_id, int efd, int op, int rx)
{
	int fd, ret;
	uint32_t vec, efd_idx;
	struct rte_eth_dev *dev;
	struct rte_intr_handle *intr_handle;
	static struct epoll_event ev = {
		.events = EPOLLIN | EPOLLPRI | EPOLLET,
		.data = {
			.u64 = EPOLL_DATA_SPECIAL,
		},
	};
	char buf[32];

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port_id, -ENODEV);

	dev = &rte_eth_devices[port_id];
	if (queue_id >= dev->data->nb_rx_queues)
		return -EINVAL;

	if (!dev->intr_handle)
		return -ENOTSUP;

	intr_handle = dev->intr_handle;
	if (!intr_handle->intr_vec)
		return -EPERM;

	vec = intr_handle->intr_vec[queue_id];

	efd_idx = (vec >= RTE_INTR_VEC_RXTX_OFFSET) ?
                (vec - RTE_INTR_VEC_RXTX_OFFSET) : vec;

	fd = intr_handle->efds[efd_idx];

	if (rx) {
		/* almost all devices use eventfd, we shall read out */
		ret = read(fd, buf, sizeof(uint64_t));
		RTE_SET_USED(ret);
	}

	return k_epoll_ctl(efd, op, fd, &ev);
}

int
PRE(epoll_create)(int size)
{
	int epfd;
	struct sock *so;
	
	if (!fd_table_initialized)
		return k_epoll_create(size);

	epfd = get_unused_fd();
	if (epfd == -1) {
		errno = EMFILE;
		return -1;
	}


	so = fd2sock(epfd);
	so->cid = glue_ctx_alloc();

	so->shadow_efd = k_epoll_create(1);
	if (so->shadow_efd < 0)
		rte_panic("Failed to create shadow efd");

	if (dev_rx_intr_ctl_q(CTX(so)->port_id, CTX(so)->queue_id,
			      so->shadow_efd, RTE_INTR_EVENT_ADD, 0) < 0)
		rte_panic("Failed to epoll_ctl rxq interrupt fd");

	so->epoll = 1;

	return epfd;
}

int
PRE(epoll_create1)(int flags __rte_unused)
{
	return PRE(epoll_create)(1);
}

int
PRE(epoll_ctl)(int epfd, int op, int fd, struct epoll_event *event)
{
	struct sock *so_ep;
	struct sock *so;

	if (is_kernel_fd(epfd)) {
		if (!is_kernel_fd(fd))
			rte_panic("kernel epoll (%d) on an userspace fd: %d",
				  epfd, fd);

		return k_epoll_ctl(epfd, op, fd, event);
	}

	so_ep = fd2sock(epfd);

	if (is_kernel_fd(fd)) {
		/* Use a shadow epoll fd for possible kernel I/O events. */
		return k_epoll_ctl(so_ep->shadow_efd, op, fd, event);
	}

	so = fd2sock(fd);

	if (unlikely(so->cid != so_ep->cid))
		rte_panic("Different ctx %d and %d for epoll fd and socket fd",
			  so_ep->cid, so->cid);

	GLUE_DEBUG("epoll_ctl: op = %x, fd = %d, event = %x",
		   op, fd, event->events);
	switch (op) {
	case EPOLL_CTL_ADD:
		if (so->event.events) {
			errno = EEXIST;
			return -1;
		}

#ifdef LOOK_ASIDE_BACKEND
		if (event->events & EPOLLIN)
			tle_event_active(&so->rxev, TLE_SEV_DOWN);
		if (event->events & EPOLLOUT)
			tle_event_active(&so->txev, TLE_SEV_DOWN);
#endif
		so->event = *event;

		break;
	case EPOLL_CTL_MOD:
		if (so->event.events == 0) {
			errno = ENOENT;
			return -1;
		}

#ifdef LOOK_ASIDE_BACKEND
		if (event->events & EPOLLIN)
			tle_event_active(&so->rxev, TLE_SEV_DOWN);
		else
			tle_event_idle(&so->rxev);
		if (event->events & EPOLLOUT)
			tle_event_active(&so->txev, TLE_SEV_DOWN);
		else
			tle_event_idle(&so->txev);
#endif
		so->event = *event;
		break;
	case EPOLL_CTL_DEL:
		if (so->event.events == 0) {
			errno = ENOENT;
			return -1;
		}

#ifdef LOOK_ASIDE_BACKEND
		if (so->event.events & EPOLLIN)
			tle_event_idle(&so->rxev);
		if (so->event.events & EPOLLOUT)
			tle_event_idle(&so->txev);
#endif
		so->event.events = 0;
		break;
	default:
		errno = EINVAL;
		return -1;
	}

	return 0;
}

static inline int32_t
tle_evq_fetch(struct tle_evq *evq, const void *evd[],
	      uint32_t num, uint32_t event)
{
	uint32_t i, k;
	uint32_t polled;
	struct tle_event *ev;
	struct tle_event *next;

	if (evq->nb_armed == 0)
		return 0;

	rte_compiler_barrier();

	rte_spinlock_lock(&evq->lock);
	ev = TAILQ_FIRST(&evq->armed);
	for (i = 0, k = 0; i != evq->nb_armed; i++) {
		next = TAILQ_NEXT(ev, ql);
		polled = ((const struct sock *)ev->data)->event.events;
		/* Always report EPOLLHUP, see man epoll_ctl(2) */
		if (polled && ((polled | EPOLLHUP) & event)) {
			evd[k++] = ev->data;
			TAILQ_REMOVE(&evq->armed, ev, ql);
			/* don't down erev; and assign NULL to data means this
			 * ev is already removed from the queue, refer to
			 * tle_event_idle_err().
			 */
			if (event != EPOLLHUP)
				ev->state = TLE_SEV_DOWN;
			else
				ev->data = NULL;
		}
		if (k == num)
			break;
		ev = next;
	}
	evq->nb_armed -= k;
	rte_spinlock_unlock(&evq->lock);
	return k;
}

static int
evq_drain(struct tle_evq *q, uint32_t event,
	  struct epoll_event *events, int maxevents)
{
	uint32_t i, n;
	struct sock *socks[maxevents];

	n = tle_evq_fetch(q, (const void **)(uintptr_t)socks, maxevents, event);
	for (i = 0; i < n; ++i) {
		events[i].events = event;
		events[i].data = socks[i]->event.data;

		/* when EPOLLHUP happens, also return EPOLLIN and EPOLLOUT
		 * if they are registered. So as to emulate behaviour of linux
		 * kernel.
		 * Some applications (e.g. redis) need these events to determine
		 * following works.
		 */
		if (event & EPOLLHUP)
			events[i].events |= (socks[i]->event.events &
					     (EPOLLIN | EPOLLOUT));

		/* if multiple events of single socket are triggered,
		 * return single event with multiple event types rather than
		 * multiple events.
		 *
		 * we drain evq in order of EPOLLOUT -> EPOLLIN -> EPOLLHUP,
		 * so only need to check event in evq that has not been drained.
		 */
		switch (event) {
		case EPOLLOUT:
			if ((socks[i]->event.events & EPOLLIN) &&
			    tle_event_state(&socks[i]->rxev) == TLE_SEV_UP) {
				tle_event_down(&socks[i]->rxev);
				events[i].events |= EPOLLIN;
			}
			/* fallthrough */
		case EPOLLIN:
			if (tle_event_state(&socks[i]->erev) == TLE_SEV_UP) {
				rte_spinlock_lock(&socks[i]->erev.head->lock);
				if (socks[i]->erev.data != NULL &&
				    tle_event_state(&socks[i]->erev) == TLE_SEV_UP) {
					TAILQ_REMOVE(&socks[i]->erev.head->armed,
						     &socks[i]->erev, ql);
					socks[i]->erev.head->nb_armed--;
					socks[i]->erev.data = NULL;
				}
				rte_spinlock_unlock(&socks[i]->erev.head->lock);
				events[i].events |= EPOLLHUP;
			}
		}

		GLUE_DEBUG("event for fd = %d, event = %x",
			   socks[i]->event.data.fd, event);
	}
	return n;
}

#ifdef LOOK_ASIDE_BACKEND
rte_atomic32_t flag_sleep;

int
epoll_kernel_wait(struct glue_ctx *ctx, int efd,
		  struct epoll_event *events,
		  int maxevents, int timeout, int *rx)
{
	struct epoll_event event;
	uint16_t port_id = ctx->port_id;
	uint16_t queue_id = ctx->queue_id;

	RTE_SET_USED(events);
	RTE_SET_USED(maxevents);
	RTE_SET_USED(rx);

	rte_eth_dev_rx_intr_enable(port_id, queue_id);

	/* TODO: timeout shall be limited by the latest tcp timer */

	if (be_process(ctx) > 0) /* use this way to avoid concurrency */ {
		/* Do nothing */
	} else
		sleep_with_lock(efd, &event, 1, timeout);

	rte_eth_dev_rx_intr_disable(port_id, queue_id);
	/* We don't have kernel events for report, so just return zero */
	return 0;
}
#else
int
epoll_kernel_wait(struct glue_ctx *ctx, int efd,
		  struct epoll_event *events,
		  int maxevents, int timeout, int *rx)
{
	int i, j, rc;
	int flag_tmp = 0;
	uint16_t port_id = ctx->port_id;
	uint16_t queue_id = ctx->queue_id;
#define LEAST_EVENTS 8
	struct epoll_event s_events[LEAST_EVENTS];
	struct epoll_event *r_events;
	int r_maxevents;
	int fastpath = 0;

	*rx = 0;

	if (efd == -1) {
		flag_tmp = 1;
		efd = k_epoll_create(1);
		if (efd < 0)
			rte_panic("Failed to create tmp efd");
	}

	if (stopped) {
		rc = k_epoll_pwait(efd, events, maxevents, timeout, NULL);
		goto check;
	}

	if (maxevents < LEAST_EVENTS) {
		r_events = s_events;
		r_maxevents = maxevents + 1;
	} else {
		r_events = events;
		r_maxevents = maxevents;
	}

	if (flag_tmp &&
	    dev_rx_intr_ctl_q(port_id, queue_id, efd, RTE_INTR_EVENT_ADD, 0) < 0)
		/* TODO: fall back to busy polling */
		rte_panic("Failed to enable rxq interrupt");

	rte_eth_dev_rx_intr_enable(port_id, queue_id);

	/* TODO: timeout shall be limited by the latest tcp timer */

	if (timeout != 0 && be_process(ctx) > 0) {
		/* use this way to avoid concurrency */
		rc = 0;
		fastpath = 1;
	} else
		rc = sleep_with_lock(efd, r_events, r_maxevents, timeout);

	rte_eth_dev_rx_intr_disable(port_id, queue_id);

	/* filter out rxq event */
	for (i = 0, j = 0; i < rc; ++i) {
		if (r_events[i].data.u64 == EPOLL_DATA_SPECIAL) {
			*rx = true;
			if (i + 1 < rc) {
				memcpy(&r_events[j], &r_events[i+1],
				       (rc-i-1) * sizeof(*events));
			}
			rc -= 1;
			break;
		} else {
			if (i != j)
				r_events[j] = r_events[i];
			j++;
		}
	}

	if (rc > 0 && maxevents < LEAST_EVENTS)
		memcpy(events, r_events, rc * sizeof(*events));

	if (flag_tmp)
		dev_rx_intr_ctl_q(port_id, queue_id, efd,
				  RTE_INTR_EVENT_DEL, *rx);

	if (fastpath)
		*rx = true;
check:
	if (flag_tmp)
		close(efd);

	return rc;
}
#endif

/* If only there are some packets to process, we don't sleep; we will poll
 * for some number of iterations to check packets.
 *
 * TODO: change to wait for a period of time?
 */
#define IDLE_ITERATIONS	5

int
poll_common(struct glue_ctx *ctx, struct epoll_event *events,
	    int maxevents, int timeout, int shadow_efd)
{
	int rx;
	int total = 0;
	int idle = IDLE_ITERATIONS;

again:
	/* We will start with send, then recv, and last err queue, as we want
	 * to serve exiting connections firstly, then new connections, and
	 * lastly, the wrong connections.
	 */

	/* 0. send evq */
	total += evq_drain(ctx->txeq, EPOLLOUT,
			   events + total, maxevents-total);
	if (total == maxevents)
		return total;

	/* 1. recv evq */
	total += evq_drain(ctx->rxeq, EPOLLIN,
			   events + total, maxevents-total);
	if (total == maxevents)
		return total;

	/* 2. err evq */
	total += evq_drain(ctx->ereq, EPOLLHUP,
			   events + total, maxevents-total);

	if (total > 0)
		return total;

	if (idle > 0) {
		if (be_process(ctx) == 0)
			idle--;
		else
			idle = IDLE_ITERATIONS;
		goto again;
	}

	if (timeout == 0)
		return 0;

	/* Setup rxq interrupt mode, and check kernel I/O events */
	total = epoll_kernel_wait(ctx, shadow_efd, events,
				  maxevents, timeout, &rx);

	/* Kernel I/O events are available (total > 0) or
	 * timeout (total < 0) or something bad happens.
	 */
	if (total != 0)
		return total;

	/* Check userspace I/O events */
	idle = IDLE_ITERATIONS;
	be_process(ctx);
	goto again;
}

int
PRE(epoll_wait)(int epfd, struct epoll_event *events,
		int maxevents, int timeout)
{
	struct sock *so;

	if (is_kernel_fd(epfd))
		return k_epoll_pwait(epfd, events, maxevents, timeout, NULL);

	so = fd2sock(epfd);

	/* thread <> context binding happens here */
	if (RTE_PER_LCORE(glue_ctx) == NULL)
		RTE_PER_LCORE(glue_ctx) = CTX(so);

	return poll_common(CTX(so), events, maxevents, timeout, so->shadow_efd);
}

int
PRE(epoll_pwait)(int epfd, struct epoll_event *events,
	    int maxevents, int timeout, const sigset_t *sigmask)
{
	if (sigmask != NULL) {
		rte_panic("epoll_pwait with signal is not supported");
	}

	return epoll_wait(epfd, events, maxevents, timeout);
}

int
fd_ready(int fd, int events)
{
	int ret = 0;
	struct sock *so = fd2sock(fd);

	if (unlikely(!so->s)) {
		if (tle_event_state(&so->erev) == TLE_SEV_UP)
		/* socket has been shutdown */
			return events | EPOLLHUP;
		else /* socket is not set up yet */
			return 0;
	}

	if (unlikely(IS_TCP(so) &&
		     TCP_STREAM(so->s)->tcb.state == TCP_ST_CLOSED)) {
		return events | EPOLLHUP | EPOLLERR;
	}

	if (tle_event_state(&so->erev) == TLE_SEV_UP)
		ret |= EPOLLHUP;

	if (events & EPOLLIN) {
		if (so->rx_left ||
		    (IS_TCP(so) && rte_ring_count(TCP_STREAM(so->s)->rx.q) > 0) ||
		    (IS_UDP(so) && rte_ring_count(UDP_STREAM(so->s)->rx.q) > 0))
			ret |= EPOLLIN;
	}

	if (events & EPOLLOUT) {
		if ((IS_TCP(so) &&
		     TCP_STREAM(so->s)->tcb.state >= TCP_ST_ESTABLISHED &&
		     rte_ring_free_count(TCP_STREAM(so->s)->tx.q) > 0) ||
		    (IS_UDP(so) &&
		     rte_ring_count(UDP_STREAM(so->s)->tx.drb.r) > 0))
			ret |= EPOLLOUT;
	}

	return ret;
}

void
v_get_stats_snmp(unsigned long mibs[])
{
	int i, j, k;

	memcpy(mibs, &default_mib, sizeof(default_mib));

	for (i = 0; i < nb_ctx; ++i) {
		for (j = 0; j < TCP_MIB_MAX; ++j)
			mibs[j] += ctx_array[i].mib.tcp.mibs[j];

		for (k = 0; k < UDP_MIB_MAX; ++k)
			mibs[j+k] += ctx_array[i].mib.udp.mibs[k];
	}
}

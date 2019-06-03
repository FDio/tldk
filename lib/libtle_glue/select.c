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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <signal.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "fd.h"
#include "ctx.h"
#include "sym.h"
#include "log.h"
#include "util.h"
#include "internal.h"
#include "tle_glue.h"

#define FD_ZERO_N(s, n) do { memset((s)->fds_bits, 0, n/sizeof(long)); } while(0)

static int
fdset_to_events_user(int nfds, fd_set *fdset, int *total, int event)
{
	int i, num = 0;
	struct sock *so;
	const struct tle_event *ev;

	for (i = fd_table.fd_base; i < nfds; ++i) {
		if (!FD_ISSET(i, fdset))
			continue;

		so = fd2sock(i); /* fix me: check if fd is opened */

		switch (event) {
		case EPOLLIN:
			ev = so->rxev;
			break;
		case EPOLLOUT:
			ev = so->txev;
			break;
		case EPOLLERR:
			ev = so->erev;
			break;
		default:
			rte_panic("non-sense value\n");
		}
		/* Check event is ready */
		if (TLE_SEV_UP == tle_event_state(ev)) {
			*total = *total + 1;
		} else {
			FD_CLR(i, fdset);
			num++;
		}

		/* We fill sock->event here as we need this when
		 * we filter events in poll_common(). But it was
		 * originally set by epoll_ctl(). Now we have to
		 * assume that there are no application which
		 * uses epoll/poll/select at the same time.
		 */
		so->event.events |= event;
		so->event.data.u32 = i;
	}

	return num;
}

static int
fdset_to_events_kernel(int nfds, fd_set *fdset, int efd, int event)
{
	int i, num = 0;
	struct epoll_event k_ev;

	for (i = 0; i < nfds; ++i) {
		if (!FD_ISSET(i, fdset))
			continue;

		k_ev.events = event;
		k_ev.data.u32 = i;
		k_epoll_ctl(efd, EPOLL_CTL_ADD, i, &k_ev);
		num++;
	}

	return num;
}

int
PRE(select)(int nfds, fd_set *readfds, fd_set *writefds,
	    fd_set *exceptfds, struct timeval *timeout)
{
	int to;
	struct glue_ctx *ctx;
	int j, efd, total = 0, max = 0;

	/* thread <> context binding happens here */
	if (RTE_PER_LCORE(glue_ctx) == NULL) {
		ctx = &ctx_array[glue_ctx_alloc()];
		RTE_PER_LCORE(glue_ctx) = ctx;
	} else
		ctx = RTE_PER_LCORE(glue_ctx);

	/* step 0, process some packets */
	be_process(ctx);

	/* step 1, check if any userspace events are ready */

	if (readfds)
		max += fdset_to_events_user(nfds, readfds,
					    &total, EPOLLIN);
	if (writefds)
		max += fdset_to_events_user(nfds, writefds,
					    &total, EPOLLOUT);
	if (exceptfds)
		max += fdset_to_events_user(nfds, writefds,
					    &total, EPOLLERR);
	if (total > 0) {
		/* userspace events go firstly */
		if (readfds)
			FD_ZERO_N(readfds, fd_table.fd_base);
		if (writefds)
			FD_ZERO_N(writefds, fd_table.fd_base);
		if (exceptfds)
			FD_ZERO_N(exceptfds, fd_table.fd_base);

		return total;
	}

	/* step 2, only wait for kernel events? */
	if (max == 0)
		return k_select(nfds, readfds, writefds, exceptfds, timeout);

	/* step 3, slow path: wait for I/O and kernel events */
	efd = k_epoll_create(1);
	if (efd < 0)
		rte_panic("k_epoll_create failed %d", errno);

	nfds = RTE_MIN(nfds, fd_table.fd_base);
	if (readfds)
		max += fdset_to_events_kernel(nfds, readfds,
					      efd, EPOLLIN);
	if (writefds)
		max += fdset_to_events_kernel(nfds, writefds,
					      efd, EPOLLOUT);
	if (exceptfds)
		max += fdset_to_events_kernel(nfds, exceptfds,
					      efd, EPOLLERR);

	struct epoll_event events[max];

	if (timeout)
		to = timeout->tv_sec * 1000 + timeout->tv_usec / 1000;
	else
		to = -1;
	total = poll_common(ctx, events, max, to, efd);

	k_close(efd);
	for (j = 0; j < total; ++j) {
		if (events[j].events & EPOLLIN)
			FD_SET(events[j].data.fd, readfds);

		if (events[j].events & EPOLLOUT)
			FD_SET(events[j].data.fd, writefds);

		if ((events[j].events & (EPOLLHUP | EPOLLERR)) && exceptfds)
			FD_SET(events[j].data.fd, exceptfds);
	}
	return total;
}

int
PRE(pselect)(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
	     const struct timespec *timeout, const sigset_t *sigmask)
{
	struct timeval tv, *tv_to;

	if (sigmask != NULL)
		rte_panic("pselect with signal is not supported");

	if (timeout) {
		tv.tv_usec = timeout->tv_nsec / 1000;
		tv.tv_sec = timeout->tv_sec;
		tv_to = &tv;
	} else
		tv_to = NULL;

	return select(nfds, readfds, writefds, exceptfds, tv_to);
}

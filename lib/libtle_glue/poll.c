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
#include <poll.h>

#include "fd.h"
#include "ctx.h"
#include "sym.h"
#include "log.h"
#include "util.h"
#include "internal.h"
#include "tle_glue.h"

int
PRE(poll)(struct pollfd *fds, nfds_t nfds, int timeout)
{
	int efd;
	int total = 0, j;
	int tmp_ev;
	uint32_t i;
	uint32_t k_n = 0;
	int k_fds[nfds];
	struct sock *so;
	struct glue_ctx *ctx;
	struct epoll_event k_ev;
	struct epoll_event events[nfds];

	for (i = 0; i < nfds; ++i) {
		if (is_kernel_fd(fds[i].fd)) {
			k_fds[k_n++] = i;
			continue;
		}

		so = fd2sock(fds[i].fd);
		if (!so->valid)
			continue;

		fds[i].revents = fd_ready(fds[i].fd, fds[i].events);
		if (fds[i].revents) {
			total++;
			continue;
		}

		/* We fill sock->event here as we need this when
		 * we filter events in poll_common(). But it was
		 * originally set by epoll_ctl(). Now we have to
		 * assume that there are no application which
		 * uses epoll and poll at the same time.
		 */
		so->event.events = fds[i].events;
		so->event.data.u32 = i; /* store idx */
	}

	if (k_n == nfds)
		return k_poll(fds, nfds, timeout);

	if (total > 0)
		return total;

	/* thread <> context binding happens here */
	if (RTE_PER_LCORE(glue_ctx) == NULL) {
		ctx = &ctx_array[glue_ctx_alloc()];
		RTE_PER_LCORE(glue_ctx) = ctx;
	} else
		ctx = RTE_PER_LCORE(glue_ctx);

	total = poll_common(ctx, events, nfds, 0, -1);

	/* We assume kernel I/O events are not as important as user ones */
	if (total > 0)
		goto format;

	efd = k_epoll_create(1);
	if (efd < 0)
		rte_panic("k_epoll_create failed %d", errno);

	for (i = 0; i < k_n; ++i) {
		k_ev.events = fds[k_fds[i]].events;
		k_ev.data.u32 = k_fds[i]; /* store idx */
		k_epoll_ctl(efd, EPOLL_CTL_ADD, fds[k_fds[i]].fd, &k_ev);
	}

	total = poll_common(ctx, events, nfds, timeout, efd);
	k_close(efd);
format:
	for (j = 0; j < total; ++j) {
		tmp_ev = events[j].events;
		if (tmp_ev == POLLHUP) {
			tmp_ev |= POLLERR | (fds[events[j].data.u32].events &
				  (POLLIN | POLLOUT));
		}
		fds[events[j].data.u32].revents = tmp_ev;
	}

	return total;
}

int
PRE(ppoll)(struct pollfd *fds, nfds_t nfds,
	const struct timespec *tmo_p, const sigset_t *sigmask)
{
	int timeout;

	if (sigmask != NULL)
		rte_panic("ppoll with signal is not supported");

	if (tmo_p == NULL)
		timeout = -1;
	else
		timeout = tmo_p->tv_sec * 1000 + tmo_p->tv_nsec / 1000000;

	return poll(fds, nfds, timeout);
}

extern int __poll_chk(struct pollfd *fds, nfds_t nfds, int timeout,
		__SIZE_TYPE__ fdslen);
int
__poll_chk(struct pollfd *fds, nfds_t nfds, int timeout,
	   __SIZE_TYPE__ fdslen __rte_unused)
{
	return poll(fds, nfds, timeout);
}

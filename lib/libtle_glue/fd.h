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

#ifndef _TLE_GLUE_FD_H_
#define _TLE_GLUE_FD_H_

#include <stdbool.h>
#include <sys/epoll.h>
#include <fcntl.h>

#include <rte_mempool.h>
#include <rte_malloc.h>

#include <tle_event.h>
#include <tle_ctx.h>
#include <tle_tcp.h>

#include "log.h"
#include "sock.h"

#ifdef __cplusplus
extern "C" {
#endif

struct fd_table {
	int fd_base; /* The mininum fd, 64 aligned */
	int fd_num;  /* The number of fds, 64 aligned */
	struct rte_mempool *mp; /* O(1) get and put */
	struct sock **socks;
};

extern bool fd_table_initialized;
extern struct fd_table fd_table;

static inline struct sock *
fd2sock(int fd)
{
	return fd_table.socks[fd - fd_table.fd_base];
}

static inline int
sock2fd(struct sock *so)
{
	return so->fd;
}

static inline int
get_unused_fd(void)
{
	struct sock *so;

	if (unlikely(rte_mempool_get(fd_table.mp, (void **)&so) < 0)) {
		GLUE_LOG(ERR, "FDs have been exhausted");
		return -1;
	}

	so->valid = 1;
	return sock2fd(so);
}

static inline void
tle_event_idle_err(struct tle_event *ev)
{
	struct tle_evq *q;

	if (ev->state == TLE_SEV_IDLE)
		return;

	q = ev->head;
	rte_compiler_barrier();

	rte_spinlock_lock(&q->lock);
	if (ev->state == TLE_SEV_UP && ev->data) {
		TAILQ_REMOVE(&q->armed, ev, ql);
		q->nb_armed--;
	}
	ev->state = TLE_SEV_IDLE;
	rte_spinlock_unlock(&q->lock);
}

static inline void
put_free_fd(int fd)
{
	struct sock *so = fd2sock(fd);

	rte_mempool_put(fd_table.mp, so);
}

static inline bool
is_kernel_fd(int fd)
{
	return fd < fd_table.fd_base;
}

void fd_init(void);

#ifdef __cplusplus
}
#endif

#endif /* _TLE_GLUE_FD_H_ */

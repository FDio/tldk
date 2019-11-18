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

#include <sys/time.h>
#include <sys/resource.h>
#include <string.h>

#include "fd.h"
#include "log.h"
#include "util.h"
#include "config.h"

bool fd_table_initialized;

struct fd_table fd_table = { .fd_base = INT_MAX, };

static int
get_ulimit_nofile(void)
{
	struct rlimit rlim;

#define GLUE_BASE_FD 1024
	if (getrlimit(RLIMIT_NOFILE, &rlim) < 0)
		return GLUE_BASE_FD;

	return rlim.rlim_cur; /* soft limit, rlim_max is the hard limit */
}

static void
fd_num_set(int *fd_base, int *fd_num)
{
	int limit = get_ulimit_nofile();

	/* fix me: alignment of power of two */
	/* fix me: use dup2 to occupy these fds */
	*fd_num = limit / 2;
	*fd_num = RTE_MIN(MAX_STREAMS_PER_CORE * 2 * MAX_NB_CTX, *fd_num);

	*fd_base = limit - *fd_num;
	GLUE_LOG(INFO, "fd_base = %d, fd_num = %d", *fd_base, *fd_num);
}

static void
add_fd(struct rte_mempool *mp __rte_unused, void *opaque __rte_unused,
       void *obj, unsigned obj_idx)
{
	((struct sock *)obj)->fd = obj_idx + fd_table.fd_base;
	fd_table.socks[obj_idx] = obj;
}

void
fd_init(void)
{
	int ret;
	size_t sz;
	uint32_t socket_id;
	int fd_base, fd_num;
	struct rte_mempool *mp = NULL;
	char name[RTE_MEMPOOL_NAMESIZE];

	socket_id = get_socket_id();

	fd_num_set(&fd_base, &fd_num);

	sz = sizeof(fd_table.socks[0]) * fd_num;
	fd_table.socks = rte_zmalloc_socket("fdtable", sz,
				RTE_CACHE_LINE_SIZE, socket_id);
	if (fd_table.socks == NULL) {
		GLUE_LOG(ERR, "Failed to malloc fd table");
		goto err;
	}

	snprintf(name, RTE_MEMPOOL_NAMESIZE, "mp_fd_%d_%d", fd_base, fd_num);
	mp = rte_mempool_create_empty(name, fd_num - 1, sizeof(struct sock),
				      32, 0, socket_id, MEMPOOL_F_DYNAMIC);
	if (mp == NULL) {
		GLUE_LOG(ERR, "Failed to create mp for fd table");
		goto err;
	}

	GLUE_LOG(INFO, "sizeof(struct sock): %lu, elt_size of fd table = %u",
		 sizeof(struct sock), mp->elt_size);

	ret = rte_mempool_set_ops_byname(mp, "ring_mp_mc", NULL);
	if (ret != 0) {
		GLUE_LOG(ERR, "Failed to set mp ops: %d", ret);
		goto err;
	}

	rte_mempool_set_dynamic_size(mp, 1024);
	rte_mempool_set_dynamic_cb(mp, add_fd);

	fd_table.mp = mp;
	fd_table.fd_base = fd_base;
	fd_table.fd_num = fd_num;

	/* should populate after fd_table is set */
	ret = rte_mempool_populate_default(mp);
	if (ret < 0) {
		GLUE_LOG(ERR, "Failed to populate mp: %d", ret);
		goto err;
	}

	fd_table_initialized = true;

	return;
err:
	rte_mempool_free(mp);
	rte_panic("Failed to init fd_table");
}

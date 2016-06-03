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

#include <rte_errno.h>
#include <rte_malloc.h>
#include <rte_log.h>

#include "buf_cage.h"
#include "osdep.h"

struct bcg_store *
bcg_create(const struct bcg_store_prm *prm)
{
	struct buf_cage *bc;
	struct bcg_store *st;
	uintptr_t end, p;
	size_t sz, tsz;
	uint32_t n;

	if (prm == NULL || (prm->cage_align != 0 &&
			rte_is_power_of_2(prm->cage_align) == 0)) {
		rte_errno = EINVAL;
		return NULL;
	}

	/* number of cages required. */
	n = (prm->max_bufs + prm->cage_bufs - 1) / prm->cage_bufs;
	n = RTE_MAX(n, prm->min_cages);

	/* size of each cage. */
	sz = prm->cage_bufs * sizeof(bc->bufs[0]) + sizeof(*bc);
	sz = RTE_ALIGN_CEIL(sz, prm->cage_align);

	/* total number of bytes required. */
	tsz = n * sz + RTE_ALIGN_CEIL(sizeof(*st), prm->cage_align);

	st = rte_zmalloc_socket(NULL, tsz, RTE_CACHE_LINE_SIZE, prm->socket_id);
	if (st == NULL) {
		UDP_LOG(ERR, "%s: allocation of %zu bytes on "
			"socket %d failed\n",
			__func__, tsz, prm->socket_id);
		return NULL;
	}

	st->prm = prm[0];
	bcg_queue_reset(&st->free);

	p = (uintptr_t)RTE_PTR_ALIGN_CEIL((st + 1), prm->cage_align);
	end = p + n * sz;

	for (; p != end; p += sz) {
		bc = (struct buf_cage *)p;
		bc->st = st;
		bc->num = prm->cage_bufs;
		STAILQ_INSERT_TAIL(&st->free.queue, bc, ql);
	}

	st->free.num = n;
	st->nb_cages = n;
	st->cage_sz = sz;
	st->total_sz = tsz;
	return st;
}

void
bcg_destroy(struct bcg_store *st)
{
	rte_free(st);
}

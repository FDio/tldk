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

#ifndef _BUF_CAGE_H_
#define _BUF_CAGE_H_

#include <rte_common.h>
#include <rte_atomic.h>
#include <rte_spinlock.h>
#include <sys/queue.h>

#ifdef __cplusplus
extern "C" {
#endif

struct bcg_store;

struct buf_cage {
	struct bcg_store *st;
	STAILQ_ENTRY(buf_cage) ql;
	uint32_t num;
	uint32_t rp;
	uint32_t wp;
	const void *bufs[0];
};

struct bcg_queue {
	rte_spinlock_t lock;
	uint32_t num;
	STAILQ_HEAD(, buf_cage) queue;
};

struct bcg_store_prm {
	void *user_data;
	int32_t socket_id;     /* NUMA socket to allocate memory from. */
	uint32_t max_bufs;     /* total number of bufs to cage. */
	uint32_t min_cages;    /* min number of cages per store. */
	uint32_t cage_bufs;    /* min number of bufs per cage. */
	uint32_t cage_align;   /* each cage to be aligned (power of 2). */
};

struct bcg_store {
	struct bcg_queue free;
	uint32_t nb_cages;
	size_t cage_sz;
	size_t total_sz;
	struct bcg_store_prm prm;
} __rte_cache_aligned;

struct bcg_store *bcg_create(const struct bcg_store_prm *prm);
void bcg_destroy(struct bcg_store *st);

static inline int
bcg_store_full(const struct bcg_store *st)
{
	return st->nb_cages == st->free.num;
}

static inline void
bcg_queue_reset(struct bcg_queue *bq)
{
	STAILQ_INIT(&bq->queue);
	bq->num = 0;
	rte_spinlock_init(&bq->lock);
}

static inline void
bcg_reset(struct buf_cage *bc)
{
	bc->rp = 0;
	bc->wp = 0;
}

static inline void *
bcg_get_udata(struct buf_cage *bc)
{
	return bc->st->prm.user_data;
}

static inline struct buf_cage *
__bcg_dequeue_head(struct bcg_queue *bq)
{
	struct buf_cage *bc;

	bc = STAILQ_FIRST(&bq->queue);
	if (bc != NULL) {
		STAILQ_REMOVE_HEAD(&bq->queue, ql);
		bq->num--;
	}
	return bc;
}

static inline struct buf_cage *
bcg_dequeue_head(struct bcg_queue *bq)
{
	struct buf_cage *bc;

	if (bq->num == 0)
		return NULL;

	rte_compiler_barrier();

	rte_spinlock_lock(&bq->lock);
	bc = __bcg_dequeue_head(bq);
	rte_spinlock_unlock(&bq->lock);
	return bc;
}

static inline uint32_t
__bcg_enqueue_head(struct bcg_queue *bq, struct buf_cage *bc)
{
	STAILQ_INSERT_HEAD(&bq->queue, bc, ql);
	return ++bq->num;
}

static inline uint32_t
bcg_enqueue_head(struct bcg_queue *bq, struct buf_cage *bc)
{
	uint32_t n;

	rte_spinlock_lock(&bq->lock);
	n = __bcg_enqueue_head(bq, bc);
	rte_spinlock_unlock(&bq->lock);
	return n;
}

static inline uint32_t
__bcg_enqueue_tail(struct bcg_queue *bq, struct buf_cage *bc)
{
	STAILQ_INSERT_TAIL(&bq->queue, bc, ql);
	return ++bq->num;
}

static inline uint32_t
bcg_enqueue_tail(struct bcg_queue *bq, struct buf_cage *bc)
{
	uint32_t n;

	rte_spinlock_lock(&bq->lock);
	n = __bcg_enqueue_tail(bq, bc);
	rte_spinlock_unlock(&bq->lock);
	return n;
}

static inline uint32_t
bcg_queue_append(struct bcg_queue *dst, struct bcg_queue *src)
{
	rte_spinlock_lock(&src->lock);
	STAILQ_CONCAT(&dst->queue, &src->queue);
	dst->num += src->num;
	src->num = 0;
	rte_spinlock_unlock(&src->lock);
	return dst->num;
}

static inline uint32_t
bcg_free_count(const struct buf_cage *bc)
{
	return bc->num - bc->wp;
}


static inline uint32_t
bcg_fill_count(const struct buf_cage *bc)
{
	return bc->wp - bc->rp;
}

/* !!! if going to keep it - try to unroll copying stuff. !!! */
static inline uint32_t
bcg_get(struct buf_cage *bc, const void *bufs[], uint32_t num)
{
	uint32_t i, n, r;

	r = bc->rp;
	n = RTE_MIN(num, bc->wp - r);
	for (i = 0; i != n; i++)
		bufs[i] = bc->bufs[r + i];

	bc->rp = r + n;
	return n;
}

static inline uint32_t
bcg_put(struct buf_cage *bc, const void *bufs[], uint32_t num)
{
	uint32_t i, n, w;

	w = bc->wp;
	n = RTE_MIN(num, bc->num - w);
	for (i = 0; i != n; i++)
		bc->bufs[w + i] = bufs[i];

	bc->wp = w + n;
	return n;
}


static inline struct buf_cage *
bcg_alloc(struct bcg_store *st)
{
	return bcg_dequeue_head(&st->free);
}

static inline uint32_t
bcg_free(struct buf_cage *bc)
{
	struct bcg_store *st;

	st = bc->st;
	bcg_reset(bc);
	return bcg_enqueue_head(&st->free, bc);
}

#ifdef __cplusplus
}
#endif

#endif /* _BUF_CAGE_H_ */

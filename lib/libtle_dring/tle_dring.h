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

#ifndef _TLE_DRING_H_
#define _TLE_DRING_H_

#include <string.h>

#include <rte_common.h>
#include <rte_atomic.h>
#include <rte_memory.h>
#include <rte_debug.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * TLE dring
 *
 * The Dynamic Ring (dring) is a implementation of unbounded FIFO queue,
 * that supports lockless bulk enqueue/dequeue for multiple producers/consumers.
 * Internally it is represented by linked list of Dynamic Ring Blocks (drb).
 * Each drb contains some metadata plus array of pointers to queued objects.
 * It is a caller responsibility to provide sufficient number of drbs for
 * enqueue operation, and manage unused drbs returned by dequeue operation.
 * dring features:
 *
 * - FIFO (First In First Out)
 * - Lockless implementation.
 * - Multi- or single-consumer dequeue.
 * - Multi- or single-producer enqueue.
 * - Bulk dequeue.
 * - Bulk enqueue.
 */

/*
 * RTE_ASSERT was introduced in DPDK 16.07.
 * For older versions, use RTE_VERIFY.
 */
#ifdef RTE_ASSERT
#define TLE_DRING_ASSERT(exp)	RTE_ASSERT(exp)
#else
#define TLE_DRING_ASSERT(exp)	RTE_VERIFY(exp)
#endif

struct tle_drb {
	struct tle_drb *next;
	void *udata;          /**< user data. */
	uint32_t size;        /**< number of objects in that buffer. */
	uint32_t start;       /**< start index for that block. */
	const void *objs[0];
} __rte_cache_aligned;

struct tle_dring {
	uint32_t flags;
	struct  {
		volatile uint32_t head;         /**< producer head */
		volatile uint32_t tail;         /**< producer tail */
		struct tle_drb * volatile crb;  /**< block to enqueue to */
	} prod __rte_cache_aligned;
	struct  {
		volatile uint32_t head;         /**< consumer head */
		volatile uint32_t tail;         /**< consumer tail */
		struct tle_drb * volatile crb;  /**< block to dequeue from */
	} cons __rte_cache_aligned;

	struct tle_drb dummy;  /**< dummy block */
};

static inline uint32_t
tle_dring_count(const struct tle_dring *dr)
{
	return dr->prod.tail - dr->cons.tail;
}

/*
 * helper routine, to copy objects to/from the ring.
 */
static inline void __attribute__((always_inline))
__tle_dring_copy_objs(const void *dst[], const void * const src[], uint32_t num)
{
	uint32_t i;

	for (i = 0; i != RTE_ALIGN_FLOOR(num, 4); i += 4) {
		dst[i] = src[i];
		dst[i + 1] = src[i + 1];
		dst[i + 2] = src[i + 2];
		dst[i + 3] = src[i + 3];
	}
	switch (num % 4) {
	case 3:
		dst[i + 2] = src[i + 2];
	case 2:
		dst[i + 1] = src[i + 1];
	case 1:
		dst[i] = src[i];
	}
}

/*
 * helper routine, to enqueue objects into the ring.
 */
static inline uint32_t __attribute__((always_inline))
__tle_dring_enqueue(struct tle_dring *dr, uint32_t head,
	const void * const objs[], uint32_t nb_obj,
	struct tle_drb *drbs[], uint32_t nb_drb)
{
	uint32_t i, j, k, n;
	struct tle_drb *pb;

	pb = dr->prod.crb;
	i = 0;

	/* fill the current producer block */
	if (pb->size != 0) {
		n = head - pb->start;
		k = RTE_MIN(pb->size - n, nb_obj);
		__tle_dring_copy_objs(pb->objs + n, objs, k);
		i += k;
	}

	/* fill new blocks, if any */
	j = 0;
	if (i != nb_obj && nb_drb != 0) {

		do {
			pb->next = drbs[j];
			pb = drbs[j];
			pb->start = head + i;
			k = RTE_MIN(pb->size, nb_obj - i);
			__tle_dring_copy_objs(pb->objs, objs + i, k);
			i += k;
		} while (++j != nb_drb && i != nb_obj);

		pb->next = NULL;

		/* new procucer current block. */
		dr->prod.crb = pb;
	}

	/* we have to enqueue all requested objects. */
	TLE_DRING_ASSERT(nb_obj == i);

	/* return number of unused blocks. */
	return nb_drb - j;
}

/**
 * Enqueue several objects on the dring (multi-producers safe).
 * Note that it is a caller responsibility to provide enough drbs
 * to enqueue all requested objects.
 *
 * @param dr
 *   A pointer to the ring structure.
 * @param objs
 *   An array of pointers to objects to enqueue.
 * @param nb_obj
 *   The number of objects to add to the dring from the objs[].
 * @param drbs
 *   An array of pointers to the drbs that can be used by the dring
 *   to perform enqueue operation.
 * @param nb_drb
 *   at input: number of elements in the drbs[] array.
 *   at output: number of unused by the dring elements in the drbs[] array.
 * @return
 *   - number of enqueued objects.
 */
static inline uint32_t
tle_dring_mp_enqueue(struct tle_dring *dr, const void * const objs[],
	uint32_t nb_obj, struct tle_drb *drbs[], uint32_t *nb_drb)
{
	uint32_t head, next;

	if (nb_obj == 0)
		return 0;

	/* reserve position inside the ring. */
	do {
		head = dr->prod.head;
		next = head + nb_obj;
	} while (rte_atomic32_cmpset(&dr->prod.head, head, next) == 0);

	/*
	 * If there are other enqueues in progress that preceded that one,
	 * then wait for them to complete
	 */
	while (dr->prod.tail != head)
		rte_pause();

	/* make sure that changes from previous updates are visible. */
	rte_smp_rmb();

	/* now it is safe to enqueue into the ring. */
	*nb_drb = __tle_dring_enqueue(dr, head, objs, nb_obj, drbs, *nb_drb);

	/* make new objects visible to the consumer. */
	rte_smp_wmb();
	dr->prod.tail = next;

	return nb_obj;
}

/**
 * Enqueue several objects on the dring (NOT multi-producers safe).
 * Note that it is a caller responsibility to provide enough drbs
 * to enqueue all requested objects.
 *
 * @param dr
 *   A pointer to the ring structure.
 * @param objs
 *   An array of pointers to objects to enqueue.
 * @param nb_obj
 *   The number of objects to add to the dring from the objs[].
 * @param drbs
 *   An array of pointers to the drbs that can be used by the dring
 *   to perform enqueue operation.
 * @param nb_drb
 *   at input: number of elements in the drbs[] array.
 *   at output: number of unused by the dring elements in the drbs[] array.
 * @return
 *   - number of enqueued objects.
 */
static inline uint32_t
tle_dring_sp_enqueue(struct tle_dring *dr, const void * const objs[],
	uint32_t nb_obj, struct tle_drb *drbs[], uint32_t *nb_drb)
{
	uint32_t head, next;

	if (nb_obj == 0)
		return 0;

	head = dr->prod.head;
	next = head + nb_obj;

	/* update producer head value. */
	dr->prod.head = next;

	/* enqueue into the ring. */
	*nb_drb = __tle_dring_enqueue(dr, head, objs, nb_obj, drbs, *nb_drb);

	/* make new objects visible to the consumer. */
	rte_smp_wmb();
	dr->prod.tail = next;

	return nb_obj;
}

/*
 * helper routine, to dequeue objects from the ring.
 */
static inline uint32_t __attribute__((always_inline))
__tle_dring_dequeue(struct tle_dring *dr, uint32_t head,
	const void *objs[], uint32_t nb_obj,
	struct tle_drb *drbs[], uint32_t nb_drb)
{
	uint32_t i, j, k, n;
	struct tle_drb *pb;

	pb = dr->cons.crb;
	i = 0;

	/* copy from the current consumer block */
	if (pb->size != 0) {
		n = head - pb->start;
		k = RTE_MIN(pb->size - n, nb_obj);
		__tle_dring_copy_objs(objs, pb->objs + n, k);
		i += k;
	}

	/* copy from other blocks */
	j = 0;
	if (i != nb_obj && nb_drb != 0) {

		do {
			/* current block is empty, put it into the free list. */
			if (pb != &dr->dummy)
				drbs[j++] = pb;

			/* proceed to the next block. */
			pb = pb->next;
			k = RTE_MIN(pb->size, nb_obj - i);
			__tle_dring_copy_objs(objs + i, pb->objs, k);
			i += k;
		} while (j != nb_drb && i != nb_obj);

		/* new consumer currect block. */
		dr->cons.crb = pb;
	}

	/* we have to dequeue all requested objects. */
	TLE_DRING_ASSERT(nb_obj == i);

	/* return number of blocks to free. */
	return j;
}

/**
 * Dequeue several objects from the dring (multi-consumers safe).
 * Note, that it is a caller responsibility to provide drbs[] large
 * enough to store pointers to all drbs that might become unused
 * after that dequeue operation. It is a caller responsibility to manage
 * unused drbs after the dequeue operation is completed
 * (i.e mark them as free/reusable again, etc.).
 *
 * @param dr
 *   A pointer to the ring structure.
 * @param objs
 *   An array of pointers to objects that will be dequeued.
 * @param nb_obj
 *   The number of objects to dequeue from the dring.
 * @param drbs
 *   An array of pointers to the drbs that will become unused after that
 *   dequeue operation.
 * @param nb_drb
 *   at input: number of elements in the drbs[] array.
 *   at output: number of filled entries in the drbs[] array.
 * @return
 *   - number of dequeued objects.
 */
static inline uint32_t
tle_dring_mc_dequeue(struct tle_dring *dr, const void *objs[], uint32_t nb_obj,
	struct tle_drb *drbs[], uint32_t *nb_drb)
{
	uint32_t head, next, num, tail;

	/* move cons.head atomically */
	do {
		head = dr->cons.head;
		tail = dr->prod.tail;

		num = RTE_MIN(tail - head, nb_obj);

		/* no objects to dequeue */
		if (num == 0) {
			*nb_drb = 0;
			return 0;
		}

		next = head + num;
	} while (rte_atomic32_cmpset(&dr->cons.head, head, next) == 0);

	/*
	 * If there are other dequeues in progress that preceded that one,
	 * then wait for them to complete
	 */
	 while (dr->cons.tail != head)
		rte_pause();

	/* make sure that changes from previous updates are visible. */
	rte_smp_rmb();

	/* now it is safe to dequeue from the ring. */
	*nb_drb = __tle_dring_dequeue(dr, head, objs, num, drbs, *nb_drb);

	/* update consumer tail value. */
	rte_smp_wmb();
	dr->cons.tail = next;

	return num;
}

/**
 * Dequeue several objects from the dring (NOT multi-consumers safe).
 * Note, that it is a caller responsibility to provide drbs[] large
 * enough to store pointers to all drbs that might become unused
 * after that dequeue operation. It is a caller responsibility to manage
 * unused drbs after the dequeue operation is completed
 * (i.e mark them as free/reusable again, etc.).
 *
 * @param dr
 *   A pointer to the ring structure.
 * @param objs
 *   An array of pointers to objects that will be dequeued.
 * @param nb_obj
 *   The number of objects to dequeue from the dring.
 * @param drbs
 *   An array of pointers to the drbs that will become unused after that
 *   dequeue operation.
 * @param nb_drb
 *   at input: number of elements in the drbs[] array.
 *   at output: number of filled entries in the drbs[] array.
 * @return
 *   - number of dequeued objects.
 */
static inline uint32_t
tle_dring_sc_dequeue(struct tle_dring *dr, const void *objs[], uint32_t nb_obj,
	struct tle_drb *drbs[], uint32_t *nb_drb)
{
	uint32_t head, next, num, tail;

	head = dr->cons.head;
	tail = dr->prod.tail;

	num = RTE_MIN(tail - head, nb_obj);

	/* no objects to dequeue */
	if (num == 0) {
		*nb_drb = 0;
		return 0;
	}

	next = head + num;

	/* update consumer head value. */
	dr->cons.head = next;

	/* dequeue from the ring. */
	*nb_drb = __tle_dring_dequeue(dr, head, objs, num, drbs, *nb_drb);

	/* update consumer tail value. */
	rte_smp_wmb();
	dr->cons.tail = next;

	return num;
}

/**
 * Reset given dring to the initial state.
 * Note, that information about all queued objects will be lost.
 *
 * @param dr
 *   A pointer to the dring structure.
 */
static inline void
tle_dring_reset(struct tle_dring *dr)
{
	memset(dr, 0, sizeof(*dr));
	dr->prod.crb = &dr->dummy;
	dr->cons.crb = &dr->dummy;
}

/**
 * Calculate required size for drb to store up to *num* objects.
 *
 * @param num
 *   Number of objects drb should be able to store.
 * @return
 *   - required size of the drb.
 */
static inline size_t
tle_drb_calc_size(uint32_t num)
{
	size_t sz;

	sz = offsetof(struct tle_drb, objs[num]);
	return RTE_ALIGN_CEIL(sz, RTE_CACHE_LINE_SIZE);
}

/**
 * Dump information about the dring to the file.
 *
 * @param f
 *   A pointer to the file.
 * @param verb
 *   Verbosity level (currently only 0 or 1).
 * @param dr
 *   A pointer to the dring structure.
 */
extern void tle_dring_dump(FILE *f, int32_t verb, const struct tle_dring *dr);

#ifdef __cplusplus
}
#endif

#endif /* _TLE_DRING_H_ */

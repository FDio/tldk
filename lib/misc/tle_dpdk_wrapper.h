/*
 * Copyright (c) 2017  Intel Corporation.
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

#ifndef TLE_DPDK_WRAPPER_H_
#define TLE_DPDK_WRAPPER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_version.h>

#if RTE_VERSION < RTE_VERSION_NUM(21, 11, 0, 0)
#error "TLDK requires DPDK version 21.11 or newer is required"
#endif

static inline uint32_t
_rte_ring_mp_enqueue_bulk(struct rte_ring *r, void * const *obj_table,
	uint32_t n)
{
	uint32_t rc;

	rc = rte_ring_mp_enqueue_bulk(r, (void * const *)obj_table, n, NULL);
	if (rc == n)
		return 0;
	else
		return -ENOSPC;
}

static inline uint32_t
_rte_ring_mp_enqueue_burst(struct rte_ring *r, void * const *obj_table,
	uint32_t n)
{
	return rte_ring_mp_enqueue_burst(r, (void * const *)obj_table, n, NULL);
}

static inline uint32_t
_rte_ring_mc_dequeue_burst(struct rte_ring *r, void **obj_table, uint32_t n)
{
	return rte_ring_mc_dequeue_burst(r, (void **)obj_table, n, NULL);
}

static inline uint32_t
_rte_ring_enqueue_burst(struct rte_ring *r, void * const *obj_table, uint32_t n)
{
	return rte_ring_enqueue_burst(r, (void * const *)obj_table, n, NULL);
}

static inline uint32_t
_rte_ring_enqueue_bulk(struct rte_ring *r, void * const *obj_table, uint32_t n)
{
	uint32_t rc;

	rc = rte_ring_enqueue_bulk(r, (void * const *)obj_table, n, NULL);
	if (rc == n)
		return 0;
	else
		return -ENOSPC;
}

static inline uint32_t
_rte_ring_dequeue_burst(struct rte_ring *r, void **obj_table, uint32_t n)
{
	return rte_ring_dequeue_burst(r, (void **)obj_table, n, NULL);
}

static inline uint32_t
_rte_ring_get_size(struct rte_ring *r)
{
	return r->size;
}

static inline uint32_t
_rte_ring_get_mask(struct rte_ring *r)
{
	return r->mask;
}

static inline uint32_t
_rte_ring_get_free_count(struct rte_ring *r)
{
	return rte_ring_free_count(r);
}

static inline uint32_t
_rte_ring_get_capacity(struct rte_ring *r)
{
	return rte_ring_get_capacity(r);
}

static inline void **
_rte_ring_get_data(struct rte_ring *r)
{
	return (void **)(&r[1]);
}

static inline void
_rte_ring_dequeue_ptrs(struct rte_ring *r, void **obj_table, uint32_t num)
{
	uint32_t tail;

	tail = r->cons.tail;
	__rte_ring_dequeue_elems(r, tail, obj_table, sizeof(obj_table[0]), num);
}

/*
 * Serialized variation of DPDK rte_ring dequeue mechanism.
 * At any given moment, only one consumer is allowed to dequeue
 * objects from the ring.
 */

static inline __attribute__((always_inline)) uint32_t
_rte_ring_mcs_dequeue_start(struct rte_ring *r, uint32_t num)
{
	uint32_t n, end, head, tail;
	int32_t rc;

	rc = 0;
	do {
		head = r->cons.head;
		tail = r->cons.tail;
		end = r->prod.tail;

		if (head != tail) {
			rte_pause();
			continue;
		}

		n = end - head;
		n = RTE_MIN(num, n);
		if (n == 0)
			return 0;

		rc = rte_atomic32_cmpset(&r->cons.head, head, head + n);
	} while (rc == 0);

	return n;
}

static inline __attribute__((always_inline)) void
_rte_ring_mcs_dequeue_finish(struct rte_ring *r, uint32_t num)
{
	uint32_t n, head, tail;

	head = r->cons.head;
	rte_smp_rmb();
	tail = r->cons.tail;
	n = head - tail;
	RTE_ASSERT(n >= num);
	RTE_SET_USED(n);
	head = tail + num;
	r->cons.head = head;
	r->cons.tail = head;
}

static inline __attribute__((always_inline)) void
_rte_ring_mcs_dequeue_abort(struct rte_ring *r)
{
	r->cons.head = r->cons.tail;
}

static inline uint32_t
_rte_ring_mcs_dequeue_burst(struct rte_ring *r, void **obj_table, uint32_t num)
{
	uint32_t n;

	n = _rte_ring_mcs_dequeue_start(r, num);
	_rte_ring_dequeue_ptrs(r, obj_table, n);
	_rte_ring_mcs_dequeue_finish(r, n);
	return n;
}

#ifdef __cplusplus
}
#endif


#endif /* TLE_DPDK_WRAPPER_H_ */

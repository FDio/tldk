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

#if RTE_VERSION >= RTE_VERSION_NUM(17, 5, 0, 0)

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

static inline void **
_rte_ring_get_data(struct rte_ring *r)
{
	return (void **)(&r[1]);
}

#else

static inline uint32_t
_rte_ring_mp_enqueue_bulk(struct rte_ring *r, void * const *obj_table,
	uint32_t n)
{
	return rte_ring_mp_enqueue_bulk(r, (void * const *)obj_table, n);
}

static inline uint32_t
_rte_ring_mp_enqueue_burst(struct rte_ring *r, void * const *obj_table,
	uint32_t n)
{
	return rte_ring_mp_enqueue_burst(r, (void * const *)obj_table, n);
}

static inline uint32_t
_rte_ring_mc_dequeue_burst(struct rte_ring *r, void **obj_table, uint32_t n)
{
	return rte_ring_mc_dequeue_burst(r, (void **)obj_table, n);
}

static inline uint32_t
_rte_ring_enqueue_burst(struct rte_ring *r, void * const *obj_table, uint32_t n)
{
	return rte_ring_enqueue_burst(r, (void * const *)obj_table, n);
}

static inline uint32_t
_rte_ring_dequeue_burst(struct rte_ring *r, void **obj_table, uint32_t n)
{
	return rte_ring_dequeue_burst(r, (void **)obj_table, n);
}

static inline uint32_t
_rte_ring_get_size(struct rte_ring *r)
{
	return r->prod.size;
}

static inline uint32_t
_rte_ring_get_mask(struct rte_ring *r)
{
	return r->prod.mask;
}

static inline void **
_rte_ring_get_data(struct rte_ring *r)
{
	return (void **)r->ring;
}

#endif

#ifdef __cplusplus
}
#endif

#endif /* TLE_DPDK_WRAPPER_H_ */

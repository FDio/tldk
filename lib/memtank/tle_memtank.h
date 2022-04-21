/*
 * Copyright (c) 2019  Intel Corporation.
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

#ifndef _TLE_MEMTANK_H_
#define _TLE_MEMTANK_H_

#include <string.h>

#include <rte_common.h>
#include <rte_memory.h>
#include <rte_atomic.h>
#include <rte_spinlock.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * TLE memtank
 *
 * Same a s mempool it allows to alloc/free objects of fixed size
 * in a lightweight manner (probably not as lightweight as mempool,
 * but hopefully close enough).
 * But in addition it can grow/shrink dynamically plus provides extra
 * additional API for higher flexibility:
 *	- manual grow()/shrink() functions
 *	- different alloc/free policies
 *        (can be specified by user via flags parameter).
 * Internally it consists of:
 *	- LIFO queue (fast allocator/deallocator)
 *	- lists of memchunks (USED, FREE).
 *
 * For perfomance reasons memtank tries to allocate memory in
 * relatively big chunks (memchunks) and then split each memchunk
 * in dozens (or hundreds) of objects.
 * There are two thresholds:
 *	- min_free (grow threshold)
 *	- max_free (shrink threshold)
 */

struct tle_memtank;

/** generic memtank behavior flags */
enum {
	TLE_MTANK_OBJ_DBG = 1,
};

struct tle_memtank_prm {
	/** min number of free objs in the ring (grow threshold). */
	uint32_t min_free;
	uint32_t max_free;  /**< max number of free objs (empty threshold) */
	uint32_t max_obj; /**< max number of objs (grow limit) */
	uint32_t obj_size;  /**< size of each mem object */
	uint32_t obj_align;  /**< alignment of each mem object */
	uint32_t nb_obj_chunk; /**< number of objects per chunk */
	uint32_t flags; /**< behavior flags */
	/** user provided function to alloc chunk of memory */
	void * (*alloc)(size_t, void *);
	/** user provided function to free chunk of memory */
	void (*free)(void *, void *);
	/** user provided function to initialiaze an object */
	void (*init)(void *[], uint32_t, void *);
	void *udata;        /**< opaque user data for alloc/free/init */
};

/**
 * Allocate and intitialize new memtank instance, based on the
 * parameters provided. Note that it uses user-provided *alloc()* function
 * to allocate space for the memtank metadata.
 * @param prm
 *   Parameters used to create and initialise new memtank.
 * @return
 *   - Pointer to new memtank insteance created, if operation completed
 *     successfully.
 *   - NULL on error with rte_errno set appropriately.
 */
struct tle_memtank *
tle_memtank_create(const struct tle_memtank_prm *prm);

/**
 * Destroy the memtank and free all memory referenced by the memtank.
 * The objects must not be used by other cores as they will be freed.
 *
 * @param t
 *   A pointer to the memtank instance.
 */
void
tle_memtank_destroy(struct tle_memtank *t);


/** alloc flags */
enum {
	TLE_MTANK_ALLOC_CHUNK = 1,
	TLE_MTANK_ALLOC_GROW = 2,
};

/**
 * Allocate up to requested number of objects from the memtank.
 * Note that depending on *alloc* behavior (flags) some new memory chunks
 * can be allocated from the underlying memory subsystem.
 *
 * @param t
 *   A pointer to the memtank instance.
 * @param obj
 *   An array of void * pointers (objects) that will be filled.
 * @param num
 *   Number of objects to allocate from the memtank.
 * @param flags
 *   Flags that control allocation behavior.
 * @return
 *   Number of allocated objects.
 */
static inline uint32_t
tle_memtank_alloc(struct tle_memtank *t, void *obj[], uint32_t num,
		uint32_t flags);

/**
 * Allocate up to requested number of objects from the memtank.
 * Note that this function bypasses *free* cache(s) and tries to allocate
 * objects straight from the memory chunks.
 * Note that depending on *alloc* behavior (flags) some new memory chunks
 * can be allocated from the underlying memory subsystem.
 *
 * @param t
 *   A pointer to the memtank instance.
 * @param obj
 *   An array of void * pointers (objects) that will be filled.
 * @param nb_obj
 *   Number of objects to allocate from the memtank.
 * @param flags
 *   Flags that control allocation behavior.
 * @return
 *   Number of allocated objects.
 */
uint32_t
tle_memtank_chunk_alloc(struct tle_memtank *t, void *obj[], uint32_t nb_obj,
		uint32_t flags);

/** free flags */
enum {
	TLE_MTANK_FREE_SHRINK = 1,
};

/**
 * Free (put) provided objects back to the memtank.
 * Note that depending on *free* behavior (flags) some memory chunks can be
 * returned (freed) to the underlying memory subsystem.
 *
 * @param t
 *   A pointer to the memtank instance.
 * @param obj
 *   An array of object pointers to be freed.
 * @param num
 *   Number of objects to free.
 * @param flags
 *   Flags that control free behavior.
 */
static inline void
tle_memtank_free(struct tle_memtank *t, void * const obj[],  uint32_t num,
		uint32_t flags);

/**
 * Free (put) provided objects back to the memtank.
 * Note that this function bypasses *free* cache(s) and tries to put
 * objects straight to the memory chunks.
 * Note that depending on *free* behavior (flags) some memory chunks can be
 * returned (freed) to the underlying memory subsystem.
 *
 * @param t
 *   A pointer to the memtank instance.
 * @param obj
 *   An array of object pointers to be freed.
 * @param nb_obj
 *   Number of objects to allocate from the memtank.
 * @param flags
 *   Flags that control allocation behavior.
 */
void
tle_memtank_chunk_free(struct tle_memtank *t, void * const obj[],
		uint32_t nb_obj, uint32_t flags);

/**
 * Check does number of objects in *free* cache is below memtank grow
 * threshold (min_free). If yes, then tries to allocate memory for new
 * objects from the underlying memory subsystem.
 *
 * @param t
 *   A pointer to the memtank instance.
 * @return
 *   Number of newly allocated memory chunks.
 */
int
tle_memtank_grow(struct tle_memtank *t);

/**
 * Check does number of objects in *free* cache have reached memtank shrink
 * threshold (max_free). If yes, then tries to return excessive memory to
 * the the underlying memory subsystem.
 *
 * @param t
 *   A pointer to the memtank instance.
 * @return
 *   Number of freed memory chunks.
 */
int
tle_memtank_shrink(struct tle_memtank *t);

/* dump flags */
enum {
	TLE_MTANK_DUMP_FREE_STAT = 1,
	TLE_MTANK_DUMP_CHUNK_STAT = 2,
	TLE_MTANK_DUMP_CHUNK = 4,
	/* first not used power of two */
	TLE_MTANK_DUMP_END,

	/* dump all stats */
	TLE_MTANK_DUMP_STAT =
		(TLE_MTANK_DUMP_FREE_STAT | TLE_MTANK_DUMP_CHUNK_STAT),
	/* dump everything */
	TLE_MTANK_DUMP_ALL = TLE_MTANK_DUMP_END - 1,
};

/**
 * Dump information about the memtank to the file.
 * Note that depending of *flags* value it might cause some internal locks
 * grabbing, and might affect perfomance of others threads that
 * concurently use same memtank.
 *
 * @param f
 *   A pinter to the file.
 * @param t
 *   A pointer to the memtank instance.
 * @param flags
 *   Flags that control dump behavior.
 */
void
tle_memtank_dump(FILE *f, const struct tle_memtank *t, uint32_t flags);

/**
 * Check the consistency of the given memtank instance.
 * Dumps error messages to the RTE log subsystem, if some inconsitency
 * is detected.
 *
 * @param t
 *   A pointer to the memtank instance.
 * @param ct
 *   Value greater then zero, if some other threads do concurently use
 *   that memtank.
 * @return
 *   Zero on success, or negaive value otherwise.
 */
int
tle_memtank_sanity_check(const struct tle_memtank *t, int32_t ct);

#ifdef __cplusplus
}
#endif

#include <tle_memtank_pub.h>

#endif /* _TLE_MEMTANK_H_ */

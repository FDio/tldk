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

struct tle_memtank *
tle_memtank_create(const struct tle_memtank_prm *prm);

void
tle_memtank_destroy(struct tle_memtank *t);


/** alloc flags */
enum {
	TLE_MTANK_ALLOC_CHUNK = 1,
	TLE_MTANK_ALLOC_GROW = 2,
};

uint32_t
tle_memtank_chunk_alloc(struct tle_memtank *t, void *obj[], uint32_t nb_obj,
	uint32_t flags);

/** free flags */
enum {
	TLE_MTANK_FREE_SHRINK = 1,
};

void
tle_memtank_chunk_free(struct tle_memtank *t, void * const obj[],
	uint32_t nb_obj, uint32_t flags);

int
tle_memtank_grow(struct tle_memtank *t);

int
tle_memtank_shrink(struct tle_memtank *t);

/* dump flags */
enum {
	TLE_MTANK_DUMP_CHUNK = 1,
	/* first not used power of two */
	TLE_MTANK_DUMP_END,
	TLE_MTANK_DUMP_ALL = TLE_MTANK_DUMP_END - 1,
};

void
tle_memtank_dump(FILE *f, const struct tle_memtank *t, uint32_t flags);


#ifdef __cplusplus
}
#endif

#include <tle_memtank_pub.h>

#endif /* _TLE_MEMTANK_H_ */

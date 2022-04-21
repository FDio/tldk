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

#ifndef	_MEMTANK_H_
#define	_MEMTANK_H_

#include <tle_memtank.h>
#include <stdalign.h>

struct memobj {
	uint64_t red_zone1;
	struct memchunk *chunk; /* ptr to the chunk it belongs to */
	struct {
		uint32_t nb_alloc;
		uint32_t nb_free;
	} dbg;
	uint64_t red_zone2;
};

#define RED_ZONE_V1	UINT64_C(0xBADECAFEBADECAFE)
#define RED_ZONE_V2	UINT64_C(0xDEADBEEFDEADBEEF)

struct memchunk {
	TAILQ_ENTRY(memchunk) link;  /* link to the next chunk in the tank */
	void *raw;		     /* un-aligned ptr returned by alloc() */
	uint32_t nb_total;           /* total number of objects in the chunk */
	uint32_t nb_free;            /*  number of free object in the chunk */
	void *free[];                /* array of free objects */
} __rte_cache_aligned;


TAILQ_HEAD(mchunk_head, memchunk);

struct mchunk_list {
	rte_spinlock_t lock;
	struct mchunk_head chunk;  /* list of chunks */
} __rte_cache_aligned;

enum {
	MC_FULL,  /* all memchunk objs are free */
	MC_USED,  /* some of memchunk objs are allocated */
	MC_NUM,
};

struct memtank {
	/* user provided data */
	struct tle_memtank_prm prm;

	/*run-time data */
	void *raw;		     /* un-aligned ptr returned by alloc() */
	size_t chunk_size;           /* full size of each memchunk */
	uint32_t obj_size;	     /* full size of each memobj */
	uint32_t max_chunk;          /* max allowed number of chunks */
	uint32_t flags;              /* behavior flags */
	rte_atomic32_t nb_chunks;    /* number of allocated chunks */

	struct mchunk_list chl[MC_NUM];  /* lists of memchunks */

	struct tle_memtank pub;
};

/*
 * Obtain pointer to interal memtank struct from public one
 */
static inline struct memtank *
tank_pub_full(const void *p)
{
	uintptr_t v;

	v = (uintptr_t)p - offsetof(struct memtank, pub);
	return (struct memtank *)v;
}

/*
 * Obtain pointer to interal memobj struct from public one
 */
static inline struct memobj *
obj_pub_full(uintptr_t p, uint32_t obj_sz)
{
	uintptr_t v;

	v = p + obj_sz - sizeof(struct memobj);
	return (struct memobj *)v;
}

static inline int
memobj_verify(const struct memobj *mo, uint32_t finc)
{
	if (mo->red_zone1 != RED_ZONE_V1 || mo->red_zone2 != RED_ZONE_V2 ||
			mo->dbg.nb_alloc != mo->dbg.nb_free + finc)
		return -EINVAL;
	return 0;
}

#endif	/* _MEMTANK_H_ */

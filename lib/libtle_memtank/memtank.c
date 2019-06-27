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

#include <tle_memtank.h>
#include <rte_errno.h>
#include <stdalign.h>

struct memobj {
	struct memchunk *chunk; /* ptr to the chunk it belongs to */
	uint8_t buf[] __rte_cache_min_aligned; /* memory buffer */
} __rte_cache_min_aligned;

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
	rte_atomic32_t nb_chunks;    /* number of allocated chunks */

	struct mchunk_list chl[MC_NUM];  /* lists of memchunks */

	struct tle_memtank pub;
};

#define	ALIGN_MUL_CEIL(v, mul)	\
	(((v) + (typeof(v))(mul) - 1) / ((typeof(v))(mul)))

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
obj_pub_full(void *p)
{
	uintptr_t v;

	v = (uintptr_t)p - offsetof(struct memobj, buf);
	return (struct memobj *)v;
}

static inline void *
obj_full_pub(struct memobj *obj)
{
	uintptr_t v;

	v = (uintptr_t)obj + offsetof(struct memobj, buf);
	return (void *)v;
}

static inline size_t
memtank_meta_size(uint32_t nb_free)
{
	size_t sz;
	static const struct memtank *mt;

	sz = sizeof(*mt) + nb_free * sizeof(mt->pub.free[0]);
	sz = RTE_ALIGN_CEIL(sz, alignof(*mt));
	return sz;
}

static inline size_t
memchunk_meta_size(uint32_t nb_obj)
{
	size_t sz;
	static const struct memchunk *ch;

	sz = sizeof(*ch) +  nb_obj * sizeof(ch->free[0]);
	sz = RTE_ALIGN_CEIL(sz, alignof(*ch));
	return sz;
}

static inline size_t
memobj_size(uint32_t obj_sz)
{
	size_t sz;
	static const struct memobj *obj;

	sz = sizeof(*obj) + obj_sz;
	sz = RTE_ALIGN_CEIL(sz, alignof(*obj));
	return sz;
}

static inline size_t
memchunk_size(uint32_t nb_obj, uint32_t obj_sz)
{
	size_t sz;

	sz = memchunk_meta_size(nb_obj);
	sz += nb_obj * memobj_size(obj_sz);
	return sz;
}

static void
init_chunk(struct memtank *mt, struct memchunk *ch)
{
	uint32_t i, n, sz;
	struct memobj *obj;

	n = mt->prm.nb_obj_chunk;
	sz = mt->obj_size;

	/* get start of memobj array */
	obj = (struct memobj *)((uintptr_t)ch + memchunk_meta_size(n));

	for (i = 0; i != n; i++) {
		obj->chunk = ch;
		ch->free[i] = obj_full_pub(obj);
		obj = (struct memobj *)((uintptr_t)obj + sz);
	}

	ch->nb_total = n;
	ch->nb_free = n;

	if (mt->prm.init != NULL)
		mt->prm.init(ch->free, n, mt->prm.udata);
}

static void
put_chunk(struct memtank *mt, struct memchunk *ch, void * const obj[],
	uint32_t num)
{
	uint32_t k, n;
	struct mchunk_list *ls;

	/* chunk should be in the *used* list */
	k = MC_USED;
	ls = &mt->chl[k];
	rte_spinlock_lock(&ls->lock);

	n = ch->nb_free;
	RTE_ASSERT(n + num <= ch->nb_total);

	_copy_objs(ch->free, obj, num);
	ch->nb_free = n + num;

	/* chunk is full now */
	if (ch->nb_free == ch->nb_total) {
		TAILQ_REMOVE(&ls->chunk, ch, link);
		k = MC_FULL;
	/* chunk is not empty anymore, move it to the head */
	} else if (n == 0) {
		TAILQ_REMOVE(&ls->chunk, ch, link);
		TAILQ_INSERT_HEAD(&ls->chunk, ch, link);
	}

	rte_spinlock_unlock(&ls->lock);

	/* insert this chunk into the *full* list */
	if (k == MC_FULL) {
		ls = &mt->chl[k];
		rte_spinlock_lock(&ls->lock);
		TAILQ_INSERT_HEAD(&ls->chunk, ch, link);
		rte_spinlock_unlock(&ls->lock);
	}
}

static uint32_t
shrink_chunk(struct memtank *mt, uint32_t num)
{
	uint32_t i, k;
	struct mchunk_list *ls;
	struct memchunk *ch[num];

	ls = &mt->chl[MC_FULL];
	rte_spinlock_lock(&ls->lock);

	for (k = 0; k != num; k++) {
		ch[k] = TAILQ_LAST(&ls->chunk, mchunk_head);
		if (ch[k] == NULL)
			break;
		TAILQ_REMOVE(&ls->chunk, ch[k], link);
	}

	rte_spinlock_unlock(&ls->lock);

	rte_atomic32_sub(&mt->nb_chunks, k);

	for (i = 0; i != k; i++)
		mt->prm.free(ch[i]->raw, mt->prm.udata);

	return k;
}

static struct memchunk *
alloc_chunk(struct memtank *mt)
{
	size_t sz;
	void *p;
	struct memchunk *ch;

	sz = mt->chunk_size + alignof(*ch);
	p = mt->prm.alloc(sz, mt->prm.udata);
	if (p == NULL)
		return NULL;
	ch = RTE_PTR_ALIGN_CEIL(p, alignof(*ch));
	ch->raw = p;
	return ch;
}

/* Determine by how many chunks we can actually grow */
static inline uint32_t
grow_num(struct memtank *mt, uint32_t num)
{
	uint32_t k, n, max;

	max = mt->prm.max_chunk;
	n = rte_atomic32_add_return(&mt->nb_chunks, num);

	if (n <= max)
		return num;

	k = n - max;
	return (k >= num) ? 0 : num - k;
}

static uint32_t
grow_chunk(struct memtank *mt, uint32_t num)
{
	uint32_t i, k, n;
	struct mchunk_list *fls;
	struct mchunk_head ls;
	struct memchunk *ch[num];

	/* check can we grow further */
	k = grow_num(mt, num);

	for (n = 0; n != k; n++) {
		ch[n] = alloc_chunk(mt);
		if (ch[n] == NULL)
			break;
	}

	TAILQ_INIT(&ls);

	for (i = 0; i != n; i++) {
		init_chunk(mt, ch[i]);
		TAILQ_INSERT_HEAD(&ls, ch[i], link);
	}

	if (n != 0) {
		fls = &mt->chl[MC_FULL];
		rte_spinlock_lock(&fls->lock);
		TAILQ_CONCAT(&fls->chunk, &ls, link);
		rte_spinlock_unlock(&fls->lock);
	}

	if (n != num)
		rte_atomic32_sub(&mt->nb_chunks, num - n);

	return n;
}


void
tle_memtank_chunk_free(struct tle_memtank *t, void * const obj[],
	uint32_t nb_obj, uint32_t flags)
{
	uint32_t i, j, k;
	struct memtank *mt;
	struct memobj *mo;
	struct memchunk *ch[nb_obj];

	mt = tank_pub_full(t);

	for (i = 0; i != nb_obj; i++) {
		mo = obj_pub_full(obj[i]);
		ch[i] = mo->chunk;
	}

	k = 0;
	for (i = 0; i != nb_obj; i += j) {

		/* find number of consequtive objs from the same chunk */
		for (j = i + 1; j != nb_obj && ch[j] == ch[i]; j++)
			;

		put_chunk(mt, ch[i], obj + i, j - i);
		k++;
	}

	if (flags & TLE_MTANK_FREE_SHRINK)
		shrink_chunk(mt, k);
}

static uint32_t
get_chunk(struct mchunk_list *ls, struct mchunk_head *els,
	struct mchunk_head *uls, void *obj[], uint32_t nb_obj)
{
	uint32_t l, k, n;
	struct memchunk *ch, *nch;

	rte_spinlock_lock(&ls->lock);

	n = 0;
	for (ch = TAILQ_FIRST(&ls->chunk);
			n != nb_obj && ch != NULL && ch->nb_free != 0;
			ch = nch, n += k) {

		k = RTE_MIN(nb_obj - n, ch->nb_free);
		l = ch->nb_free - k;
		_copy_objs(obj + n, ch->free + l, k);
		ch->nb_free = l;

		nch = TAILQ_NEXT(ch, link);

		/* chunk is empty now */
		if (l == 0) {
			TAILQ_REMOVE(&ls->chunk, ch, link);
			TAILQ_INSERT_TAIL(els, ch, link);
		} else if (uls != NULL) {
			TAILQ_REMOVE(&ls->chunk, ch, link);
			TAILQ_INSERT_HEAD(uls, ch, link);
		}
	}

	rte_spinlock_unlock(&ls->lock);
	return n;
}

uint32_t
tle_memtank_chunk_alloc(struct tle_memtank *t, void *obj[], uint32_t nb_obj,
	uint32_t flags)
{
	uint32_t k, n;
	struct memtank *mt;
	struct mchunk_head els, uls;

	mt = tank_pub_full(t);

	/* walk though the the *used* list first */
	n = get_chunk(&mt->chl[MC_USED], &mt->chl[MC_USED].chunk, NULL,
		obj, nb_obj);

	if (n != nb_obj) {

		TAILQ_INIT(&els);
		TAILQ_INIT(&uls);

		/* walk though the the *full* list */
		n += get_chunk(&mt->chl[MC_FULL], &els, &uls,
			obj + n, nb_obj - n);

		if (n != nb_obj && (flags & TLE_MTANK_ALLOC_GROW) != 0) {

			/* try to allocate extra memchunks */
			k = ALIGN_MUL_CEIL(nb_obj - n,
				mt->prm.nb_obj_chunk);
			k = grow_chunk(mt, k);

			/* walk through the *full* list again */
			if (k != 0)
				n += get_chunk(&mt->chl[MC_FULL], &els, &uls,
					obj + n, nb_obj - n);
		}

		/* concatenate with *used* list our temporary lists */
		rte_spinlock_lock(&mt->chl[MC_USED].lock);

		/* put new non-emtpy elems at head of the *used* list */
		TAILQ_CONCAT(&uls, &mt->chl[MC_USED].chunk, link);
		TAILQ_CONCAT(&mt->chl[MC_USED].chunk, &uls, link);

		/* put new emtpy elems at tail of the *used* list */
		TAILQ_CONCAT(&mt->chl[MC_USED].chunk, &els, link);

		rte_spinlock_unlock(&mt->chl[MC_USED].lock);
	}

	return n;
}

int
tle_memtank_grow(struct tle_memtank *t)
{
	uint32_t k, n, num;
	struct memtank *mt;

	mt = tank_pub_full(t);

	/* how many chunks we need to grow */
	k = t->min_free - t->nb_free;
	if ((int32_t)k <= 0)
		return 0;

	num = ALIGN_MUL_CEIL(k, mt->prm.nb_obj_chunk);

	/* try to grow and refill the *free* */
	n = grow_chunk(mt, num);
	if (n != 0)
		_fill_free(t, k, 0);

	return n;
}

int
tle_memtank_shrink(struct tle_memtank *t)
{
	uint32_t n;
	struct memtank *mt;

	mt = tank_pub_full(t);

	/* how many chunks we need to shrink */
	if (t->nb_free < t->max_free)
		return 0;

	/* how many chunks we need to free */
	n = ALIGN_MUL_CEIL(t->min_free, mt->prm.nb_obj_chunk);

	/* free up to *num* chunks */
	return shrink_chunk(mt, n);
}

static int
check_param(const struct tle_memtank_prm *prm)
{
	if (prm->alloc == NULL || prm->free == NULL ||
			prm->min_free > prm->max_free)
		return -EINVAL;
	return 0;
}

struct tle_memtank *
tle_memtank_create(const struct tle_memtank_prm *prm)
{
	int32_t rc;
	size_t sz;
	void *p;
	struct memtank *mt;

	rc = check_param(prm);
	if (rc != 0) {
		rte_errno = -rc;
		return NULL;
	}

	sz = memtank_meta_size(prm->max_free);
	p = prm->alloc(sz, prm->udata);
	if (p == NULL) {
		rte_errno = ENOMEM;
		return NULL;
	}

	mt = RTE_PTR_ALIGN_CEIL(p, alignof(*mt));

	memset(mt, 0, sizeof(*mt));
	mt->prm = *prm;

	mt->raw = p;
	mt->chunk_size = memchunk_size(prm->nb_obj_chunk, prm->obj_size);
	mt->obj_size = memobj_size(prm->obj_size);

	mt->pub.min_free = prm->min_free;
	mt->pub.max_free = prm->max_free;

	TAILQ_INIT(&mt->chl[MC_FULL].chunk);
	TAILQ_INIT(&mt->chl[MC_USED].chunk);

	return &mt->pub;
}

static void
free_mchunk_list(struct memtank *mt, struct mchunk_list *ls)
{
	struct memchunk *ch;

	for (ch = TAILQ_FIRST(&ls->chunk); ch != NULL;
			ch =  TAILQ_FIRST(&ls->chunk)) {
		TAILQ_REMOVE(&ls->chunk, ch, link);
		mt->prm.free(ch->raw, mt->prm.udata);
	}
}

void
tle_memtank_destroy(struct tle_memtank *t)
{
	struct memtank *mt;

	if (t != NULL) {
		mt = tank_pub_full(t);
		free_mchunk_list(mt, &mt->chl[MC_FULL]);
		free_mchunk_list(mt, &mt->chl[MC_USED]);
		mt->prm.free(mt->raw, mt->prm.udata);
	}
}

static void
mchunk_list_dump(FILE *f, const struct mchunk_list *ls)
{
	const struct memchunk *ch;

	for (ch = TAILQ_FIRST(&ls->chunk); ch != NULL;
			ch = TAILQ_NEXT(ch, link)) {
		fprintf(f, "\t\tmemchunk@%p={\n", ch);
		fprintf(f, "\t\t\traw=%p,\n", ch->raw);
		fprintf(f, "\t\t\tnb_total=%u,\n", ch->nb_total);
		fprintf(f, "\t\t\tnb_free=%u,\n", ch->nb_free);
		fprintf(f, "\t\t},\n");
	}
}

void
tle_memtank_dump(FILE *f, const struct tle_memtank *t, uint32_t flags)
{
	const struct memtank *mt;

	if (f == NULL || t == NULL)
		return;

	mt = tank_pub_full(t);

	fprintf(f, "tle_memtank@%p={\n", t);
	fprintf(f, "\tmin_free=%u,\n", t->min_free);
	fprintf(f, "\tmax_free=%u,\n", t->max_free);
	fprintf(f, "\tnb_free=%u,\n", t->nb_free);
	fprintf(f, "\tchunk_size=%zu,\n", mt->chunk_size);
	fprintf(f, "\tobj_size=%u,\n", mt->obj_size);
	fprintf(f, "\tnb_chunks=%u,\n", rte_atomic32_read(&mt->nb_chunks));
	if (flags & TLE_MTANK_DUMP_CHUNK) {
		fprintf(f, "\tFULL={,\n");
		mchunk_list_dump(f, &mt->chl[MC_FULL]);
		fprintf(f, "},\n");
		fprintf(f, "\tUSED={,\n");
		mchunk_list_dump(f, &mt->chl[MC_USED]);
		fprintf(f, "\t},\n");
	}
	fprintf(f, "};\n");
}

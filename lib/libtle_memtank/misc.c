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

#include "memtank.h"
#include <inttypes.h>

#define CHUNK_OBJ_LT_NUM	4

struct mchunk_stat {
	uint32_t nb_empty;
	uint32_t nb_full;
	struct {
		uint32_t nb_chunk;
		uint32_t nb_obj;
		struct {
			uint32_t val;
			uint32_t num;
		} chunk_obj_lt[CHUNK_OBJ_LT_NUM];
	} used;
};

struct mfree_stat {
	uint32_t nb_chunk;
	struct mchunk_stat chunk;
};

#define	MTANK_LOG(lvl, fmt, args...)	RTE_LOG(lvl, USER1, fmt, ##args)


static void
mchunk_stat_dump(FILE *f, const struct mchunk_stat *st)
{
	uint32_t i;

	fprintf(f, "\t\tstat={\n");
	fprintf(f, "\t\t\tnb_empty=%u,\n", st->nb_empty);
	fprintf(f, "\t\t\tnb_full=%u,\n", st->nb_full);
	fprintf(f, "\t\t\tused={\n");
	fprintf(f, "\t\t\t\tnb_chunk=%u,\n", st->used.nb_chunk);
	fprintf(f, "\t\t\t\tnb_obj=%u,\n", st->used.nb_obj);

	for (i = 0; i != RTE_DIM(st->used.chunk_obj_lt); i++) {
		if (st->used.chunk_obj_lt[i].num != 0)
			fprintf(f, "\t\t\t\tnb_chunk_obj_lt_%u=%u,\n",
				st->used.chunk_obj_lt[i].val,
				st->used.chunk_obj_lt[i].num);
	}

	fprintf(f, "\t\t\t},\n");
	fprintf(f, "\t\t},\n");
}

static void
mchunk_stat_init(struct mchunk_stat *st, uint32_t nb_obj_chunk)
{
	uint32_t i;

	memset(st, 0, sizeof(*st));
	for (i = 0; i != RTE_DIM(st->used.chunk_obj_lt); i++) {
		st->used.chunk_obj_lt[i].val = (i + 1) * nb_obj_chunk /
			RTE_DIM(st->used.chunk_obj_lt);
	}
}

static void
mchunk_stat_collect(struct mchunk_stat *st, const struct memchunk *ch)
{
	uint32_t i, n;

	n = ch->nb_total - ch->nb_free;

	if (ch->nb_free == 0)
		st->nb_empty++;
	else if (n == 0)
		st->nb_full++;
	else {
		st->used.nb_chunk++;
		st->used.nb_obj += n;

		for (i = 0; i != RTE_DIM(st->used.chunk_obj_lt); i++) {
			if (n < st->used.chunk_obj_lt[i].val) {
				st->used.chunk_obj_lt[i].num++;
				break;
			}
		}
	}
}

static void
mchunk_list_dump(FILE *f, struct memtank *mt, uint32_t idx, uint32_t flags)
{
	struct mchunk_list *ls;
	const struct memchunk *ch;
	struct mchunk_stat mcs;

	ls = &mt->chl[idx];
	mchunk_stat_init(&mcs, mt->prm.nb_obj_chunk);

	rte_spinlock_lock(&ls->lock);

	for (ch = TAILQ_FIRST(&ls->chunk); ch != NULL;
			ch = TAILQ_NEXT(ch, link)) {

		/* collect chunk stats */
		if (flags & TLE_MTANK_DUMP_CHUNK_STAT)
			mchunk_stat_collect(&mcs, ch);

		/* dump chunk metadata */
		if (flags & TLE_MTANK_DUMP_CHUNK) {
			fprintf(f, "\t\tmemchunk@%p={\n", ch);
			fprintf(f, "\t\t\traw=%p,\n", ch->raw);
			fprintf(f, "\t\t\tnb_total=%u,\n", ch->nb_total);
			fprintf(f, "\t\t\tnb_free=%u,\n", ch->nb_free);
			fprintf(f, "\t\t},\n");
		}
	}

	rte_spinlock_unlock(&ls->lock);

	/* print chunk stats */
	if (flags & TLE_MTANK_DUMP_CHUNK_STAT)
		mchunk_stat_dump(f, &mcs);
}

static void
mfree_stat_init(struct mfree_stat *st, uint32_t nb_obj_chunk)
{
	st->nb_chunk = 0;
	mchunk_stat_init(&st->chunk, nb_obj_chunk);
}

static int
ptr_cmp(const void *p1, const void *p2)
{
	const intptr_t *v1, *v2;

	v1 = p1;
	v2 = p2;
	return v1[0] - v2[0];
}

static void
mfree_stat_collect(struct mfree_stat *st, struct memtank *mt)
{
	uint32_t i, j, n, sz;
	uintptr_t *p;
	const struct memobj *mo;

	sz = mt->obj_size;

	p = malloc(mt->pub.max_free * sizeof(*p));
	if (p == NULL)
		return;

	/**
	 * grab free lock and keep it till we analyze related memchunks,
	 * to make sure none of these memchunks will be freed untill
	 * we are finished.
	 */
	rte_spinlock_lock(&mt->pub.lock);

	/* collect chunks for all objects in free[] */
	n = mt->pub.nb_free;
	memcpy(p, mt->pub.free, n * sizeof(*p));
	for (i = 0; i != n; i++) {
		mo = obj_pub_full(p[i], sz);
		p[i] = (uintptr_t)mo->chunk;
	}

	/* sort chunk pointers */
	qsort(p, n, sizeof(*p), ptr_cmp);

	/* for each chunk collect stats */
	for (i = 0; i != n; i = j) {

		st->nb_chunk++;
		mchunk_stat_collect(&st->chunk, (const struct memchunk *)p[i]);
		for (j = i + 1; j != n && p[i] == p[j]; j++)
			;
	}

	rte_spinlock_unlock(&mt->pub.lock);
	free(p);
}

static void
mfree_stat_dump(FILE *f, const struct mfree_stat *st)
{
	fprintf(f, "\tfree_stat={\n");
	fprintf(f, "\t\tnb_chunk=%u,\n", st->nb_chunk);
	mchunk_stat_dump(f, &st->chunk);
	fprintf(f, "\t},\n");
}

void
tle_memtank_dump(FILE *f, const struct tle_memtank *t, uint32_t flags)
{
	struct memtank *mt;

	if (f == NULL || t == NULL)
		return;

	mt = tank_pub_full(t);

	fprintf(f, "tle_memtank@%p={\n", t);
	fprintf(f, "\tmin_free=%u,\n", t->min_free);
	fprintf(f, "\tmax_free=%u,\n", t->max_free);
	fprintf(f, "\tnb_free=%u,\n", t->nb_free);
	fprintf(f, "\tchunk_size=%zu,\n", mt->chunk_size);
	fprintf(f, "\tobj_size=%u,\n", mt->obj_size);
	fprintf(f, "\tmax_chunk=%u,\n", mt->max_chunk);
	fprintf(f, "\tflags=%#x,\n", mt->flags);
	fprintf(f, "\tnb_chunks=%u,\n", rte_atomic32_read(&mt->nb_chunks));

	if (flags & TLE_MTANK_DUMP_FREE_STAT) {
		struct mfree_stat mfs;
		mfree_stat_init(&mfs, mt->prm.nb_obj_chunk);
		mfree_stat_collect(&mfs, mt);
		mfree_stat_dump(f, &mfs);
	}

	if (flags & (TLE_MTANK_DUMP_CHUNK | TLE_MTANK_DUMP_CHUNK_STAT)) {

		fprintf(f, "\t[FULL]={\n");
		mchunk_list_dump(f, mt, MC_FULL, flags);
		fprintf(f, "\t},\n");

		fprintf(f, "\t[USED]={,\n");
		mchunk_list_dump(f, mt, MC_USED, flags);
		fprintf(f, "\t},\n");
	}
	fprintf(f, "};\n");
}

static int
mobj_bulk_check(const char *fname, const struct memtank *mt,
	const uintptr_t p[], uint32_t num, uint32_t fmsk)
{
	int32_t ret;
	uintptr_t align;
	uint32_t i, k, sz;
	const struct memobj *mo;

	k = ((mt->flags & TLE_MTANK_OBJ_DBG) != 0) & fmsk;
	sz = mt->obj_size;
	align = mt->prm.obj_align - 1;

	ret = 0;
	for (i = 0; i != num; i++) {

		if (p[i] == (uintptr_t)NULL) {
			ret--;
			MTANK_LOG(ERR,
				"%s(mt=%p, %p[%u]): NULL object\n",
				fname, mt, p, i);
		} else if ((p[i] & align) != 0) {
			ret--;
			MTANK_LOG(ERR,
				"%s(mt=%p, %p[%u]): object %#zx violates "
				"expected alignment %#zx\n",
				fname, mt, p, i, p[i], align);
		} else {
			mo = obj_pub_full(p[i], sz);
			if (memobj_verify(mo, k) != 0) {
				ret--;
				MTANK_LOG(ERR,
					"%s(mt=%p, %p[%u]): "
					"invalid object header @%#zx={"
					"red_zone1=%#" PRIx64 ","
					"dbg={nb_alloc=%u,nb_free=%u},"
					"red_zone2=%#" PRIx64
					"}\n",
					fname, mt, p, i, p[i],
					mo->red_zone1,
					mo->dbg.nb_alloc, mo->dbg.nb_free,
					mo->red_zone2);
			}
		}
	}

	return ret;
}

/* grab free lock and check objects in free[] */
static int
mfree_check(struct memtank *mt)
{
	int32_t rc;

	rte_spinlock_lock(&mt->pub.lock);
	rc = mobj_bulk_check(__func__, mt, (const uintptr_t *)mt->pub.free,
		mt->pub.nb_free, 1);
	rte_spinlock_unlock(&mt->pub.lock);
	return rc;
}

static int
mchunk_check(const struct memtank *mt, const struct memchunk *mc, uint32_t tc)
{
	int32_t n, rc;

	rc = 0;
	n = mc->nb_total - mc->nb_free;

	rc -= (mc->nb_total != mt->prm.nb_obj_chunk);
	rc -= (tc == MC_FULL) ? (n != 0) : (n <= 0);
	rc -= (RTE_PTR_ALIGN_CEIL(mc->raw, alignof(*mc)) != mc);

	if (rc != 0)
		MTANK_LOG(ERR, "%s(mt=%p, tc=%u): invalid memchunk @%p={"
			"raw=%p, nb_total=%u, nb_free=%u}\n",
			__func__, mt, tc, mc,
			mc->raw, mc->nb_total, mc->nb_free);

	rc += mobj_bulk_check(__func__, mt, (const uintptr_t *)mc->free,
		mc->nb_free, 0);
	return rc;
}

static int
mchunk_list_check(struct memtank *mt, uint32_t tc, uint32_t *nb_chunk)
{
	int32_t rc;
	uint32_t n;
	struct mchunk_list *ls;
	const struct memchunk *ch;

	ls = &mt->chl[tc];
	rte_spinlock_lock(&ls->lock);

	rc = 0;
	for (n = 0, ch = TAILQ_FIRST(&ls->chunk); ch != NULL;
			ch = TAILQ_NEXT(ch, link), n++)
		rc += mchunk_check(mt, ch, tc);

	rte_spinlock_unlock(&ls->lock);

	*nb_chunk = n;
	return rc;
}

int
tle_memtank_sanity_check(const struct tle_memtank *t, int32_t ct)
{
	int32_t rc;
	uint32_t n, nf, nu;
	struct memtank *mt;

	mt = tank_pub_full(t);
	rc = mfree_check(mt);

	nf = 0, nu = 0;
	rc += mchunk_list_check(mt, MC_FULL, &nf);
	rc += mchunk_list_check(mt, MC_USED, &nu);

	/*
	 * if some other threads concurently do alloc/free/grow/shrink
	 * these numbers can still not match.
	 */
	n = rte_atomic32_read(&mt->nb_chunks);
	if (nf + nu != n && ct == 0) {
		MTANK_LOG(ERR,
			"%s(mt=%p) nb_chunks: expected=%u, full=%u, used=%u\n",
			__func__, mt, n, nf, nu);
		rc--;
	}

	return rc;
}

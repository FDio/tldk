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

#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_errno.h>
#include <rte_launch.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ring.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_random.h>
#include <rte_hexdump.h>

#include <tle_memtank.h>

struct memstat {
	struct {
		rte_atomic64_t nb_call;
		rte_atomic64_t nb_fail;
		rte_atomic64_t sz;
	} alloc;
	struct {
		rte_atomic64_t nb_call;
		rte_atomic64_t nb_fail;
	} free;
};

struct memtank_stat {
	uint64_t nb_cycle;
	struct {
		uint64_t nb_call;
		uint64_t nb_req;
		uint64_t nb_alloc;
		uint64_t nb_cycle;
	} alloc;
	struct {
		uint64_t nb_call;
		uint64_t nb_free;
		uint64_t nb_cycle;
	} free;
	struct {
		uint64_t nb_call;
		uint64_t nb_chunk;
		uint64_t nb_cycle;
	} grow;
	struct {
		uint64_t nb_call;
		uint64_t nb_chunk;
		uint64_t nb_cycle;
	} shrink;
};

struct master_args {
	uint64_t run_cycles;
	uint32_t delay_us;
};

struct worker_args {
	uint32_t max_obj;
	uint32_t obj_size;
	uint32_t alloc_flags;
	uint32_t free_flags;
};

struct memtank_arg {
	struct tle_memtank *mt;
	union {
		struct master_args master;
		struct worker_args worker;
	};
	struct memtank_stat stats;
};

#define BULK_NUM	32

#define TEST_TIME	30

enum {
	WRK_CMD_STOP,
	WRK_CMD_RUN,
};

static uint32_t wrk_cmd __rte_cache_aligned;

static struct tle_memtank_prm mtnk_prm = {
	.min_free = 4 * BULK_NUM,
	.max_free = 32 * BULK_NUM,
	.max_chunk = UINT32_MAX,
	.obj_size = 4 * RTE_CACHE_LINE_SIZE,
	.nb_obj_chunk = BULK_NUM,
};

static void *
test_alloc1(size_t sz, void *p)
{
	struct memstat *ms;
	void *buf;

	ms = p;
	buf = malloc(sz);
	rte_atomic64_inc(&ms->alloc.nb_call);
	if (buf != NULL) {
		memset(buf, 0, sz);
		rte_atomic64_add(&ms->alloc.sz, sz);
	} else
		rte_atomic64_inc(&ms->alloc.nb_fail);

	return buf;
}

static void
test_free1(void *buf, void *p)
{
	struct memstat *ms;

	ms = p;

	free(buf);
	rte_atomic64_inc(&ms->free.nb_call);
	if (buf == NULL)
		rte_atomic64_inc(&ms->free.nb_fail);
}

static void
memstat_dump(FILE *f, struct memstat *ms)
{
	fprintf(f, "%s(%p)={\n", __func__, ms);
	fprintf(f, "\talloc={\n");
	fprintf(f, "\t\tnb_call=%" PRIu64 ",\n",
		rte_atomic64_read(&ms->alloc.nb_call));
	fprintf(f, "\t\tnb_fail=%" PRIu64 ",\n",
		rte_atomic64_read(&ms->alloc.nb_fail));
	fprintf(f, "\t\tsz=%" PRIu64 ",\n",
		rte_atomic64_read(&ms->alloc.sz));
	fprintf(f, "\t},\n");
	fprintf(f, "\tfree={\n");
	fprintf(f, "\t\tnb_call=%" PRIu64 ",\n",
		rte_atomic64_read(&ms->free.nb_call));
	fprintf(f, "\t\tnb_fail=%" PRIu64 ",\n",
		rte_atomic64_read(&ms->free.nb_fail));
	fprintf(f, "\t},\n");
	fprintf(f, "};\n");

}

static void
mentank_stat_dump(FILE *f, uint32_t lc, const struct memtank_stat *ms)
{
	uint64_t t;

	fprintf(f, "%s(lc=%u)={\n", __func__, lc);
	fprintf(f, "\tnb_cycle=%" PRIu64 ",\n", ms->nb_cycle);
	if (ms->alloc.nb_call != 0) {
		fprintf(f, "\talloc={\n");
		fprintf(f, "\t\tnb_call=%" PRIu64 ",\n", ms->alloc.nb_call);
		fprintf(f, "\t\tnb_req=%" PRIu64 ",\n", ms->alloc.nb_req);
		fprintf(f, "\t\tnb_alloc=%" PRIu64 ",\n", ms->alloc.nb_alloc);
		fprintf(f, "\t\tnb_cycle=%" PRIu64 ",\n", ms->alloc.nb_cycle);

		t = ms->alloc.nb_req - ms->alloc.nb_alloc;
		fprintf(f, "\t\tfailed req: %"PRIu64 "(%.2Lf %%)\n",
			t, (long double)t * 100 /  ms->alloc.nb_req);
		fprintf(f, "\t\tcycles/alloc: %.2Lf\n",
			(long double)ms->alloc.nb_cycle / ms->alloc.nb_alloc);
		fprintf(f, "\t\tobj/call(avg): %.2Lf\n",
			(long double)ms->alloc.nb_alloc /  ms->alloc.nb_call);

		fprintf(f, "\t},\n");
	}
	if (ms->free.nb_call != 0) {
		fprintf(f, "\tfree={\n");
		fprintf(f, "\t\tnb_call=%" PRIu64 ",\n", ms->free.nb_call);
		fprintf(f, "\t\tnb_free=%" PRIu64 ",\n", ms->free.nb_free);
		fprintf(f, "\t\tnb_cycle=%" PRIu64 ",\n", ms->free.nb_cycle);

		fprintf(f, "\t\tcycles/free: %.2Lf\n",
			(long double)ms->free.nb_cycle / ms->free.nb_free);
		fprintf(f, "\t\tobj/call(avg): %.2Lf\n",
			(long double)ms->free.nb_free /  ms->free.nb_call);

		fprintf(f, "\t},\n");
	}
	if (ms->grow.nb_call != 0) {
		fprintf(f, "\tgrow={\n");
		fprintf(f, "\t\tnb_call=%" PRIu64 ",\n", ms->grow.nb_call);
		fprintf(f, "\t\tnb_chunk=%" PRIu64 ",\n", ms->grow.nb_chunk);
		fprintf(f, "\t\tnb_cycle=%" PRIu64 ",\n", ms->grow.nb_cycle);

		fprintf(f, "\t\tcycles/chunk: %.2Lf\n",
			(long double)ms->grow.nb_cycle / ms->grow.nb_chunk);
		fprintf(f, "\t\tobj/call(avg): %.2Lf\n",
			(long double)ms->grow.nb_chunk /  ms->grow.nb_call);

		fprintf(f, "\t},\n");
	}
	if (ms->shrink.nb_call != 0) {
		fprintf(f, "\tshrink={\n");
		fprintf(f, "\t\tnb_call=%" PRIu64 ",\n", ms->shrink.nb_call);
		fprintf(f, "\t\tnb_chunk=%" PRIu64 ",\n", ms->shrink.nb_chunk);
		fprintf(f, "\t\tnb_cycle=%" PRIu64 ",\n", ms->shrink.nb_cycle);

		fprintf(f, "\t\tcycles/chunk: %.2Lf\n",
			(long double)ms->shrink.nb_cycle / ms->shrink.nb_chunk);
		fprintf(f, "\t\tobj/call(avg): %.2Lf\n",
			(long double)ms->shrink.nb_chunk /  ms->shrink.nb_call);

		fprintf(f, "\t},\n");
	}
	fprintf(f, "};\n");
}

static int32_t
check_fill_objs(void *obj[], uint32_t sz, uint32_t num,
	uint8_t check, uint8_t fill)
{
	uint32_t i;
	uint8_t buf[sz];

	static rte_spinlock_t dump_lock;

	memset(buf, check, sz);

	for (i = 0; i != num; i++) {
		if (memcmp(buf, obj[i], sz) != 0) {
			rte_spinlock_lock(&dump_lock);
			printf ("%s(%u, %u, %hu, %hu) failed at %u-th iter, "
				"offendig object: %p\n",
				__func__, sz, num, check, fill, i, obj[i]);
			rte_memdump(stdout, "expected", buf, sz);
			rte_memdump(stdout, "result", obj[i], sz);
			rte_spinlock_unlock(&dump_lock);
			return -EINVAL;
		}
		memset(obj[i], fill, sz);
	}
	return 0;
}

static int
test_memtank_worker(void *arg)
{
	int32_t rc;
	size_t sz;
	uint32_t lc, n, num;
	uint64_t cl, tm0, tm1;
	struct memtank_arg *ma;
	struct rte_ring *ring;
	void *obj[BULK_NUM];

	ma = arg;
	lc = rte_lcore_id();

	sz = rte_ring_get_memsize(ma->worker.max_obj);
	ring = alloca(sz);
	if (ring == NULL) {
		printf("%s(%u): alloca(%zu) for FIFO with %u elems failed",
			__func__, lc, sz, ma->worker.max_obj);
		return -ENOMEM;
	}
	rc = rte_ring_init(ring, "", ma->worker.max_obj,
		RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (rc != 0) {
		printf("%s(%u): rte_ring_init(%p, %u) failed, error: %d(%s)\n",
			__func__, lc, ring, ma->worker.max_obj,
			rc, strerror(-rc));
		return rc;
	}

	while (wrk_cmd != WRK_CMD_RUN) {
		rte_smp_rmb();
		rte_pause();
	}

	cl = rte_rdtsc_precise();

	do {
		num = rte_rand() % RTE_DIM(obj);
		n = rte_ring_free_count(ring);
		num = RTE_MIN(num, n);

		/* perform alloc*/
		if (num != 0) {
			tm0 = rte_rdtsc_precise();
			n = tle_memtank_alloc(ma->mt, obj, num,
				ma->worker.alloc_flags);
			tm1 = rte_rdtsc_precise();

			/* check and fill contents of allocated objects */
			rc = check_fill_objs(obj, ma->worker.obj_size, n,
				0, lc);
			if (rc != 0)
				break;

			/* collect alloc stat */
			ma->stats.alloc.nb_call++;
			ma->stats.alloc.nb_req += num;
			ma->stats.alloc.nb_alloc += n;
			ma->stats.alloc.nb_cycle += tm1 - tm0;

			/* store allocated objects */
			rte_ring_enqueue_bulk(ring, obj, n, NULL);
		}

		/* get some objects to free */
		num = rte_rand() % RTE_DIM(obj);
		n = rte_ring_count(ring);
		num = RTE_MIN(num, n);

		/* perform free*/
		if (num != 0) {

			/* retrieve objects to free */
			rte_ring_dequeue_bulk(ring, obj, num, NULL);

			/* check and fill contents of freeing objects */
			rc = check_fill_objs(obj, ma->worker.obj_size, num,
				lc, 0);
			if (rc != 0)
				break;

			tm0 = rte_rdtsc_precise();
			tle_memtank_free(ma->mt, obj, num,
				ma->worker.free_flags);
			tm1 = rte_rdtsc_precise();

			/* collect free stat */
			ma->stats.free.nb_call++;
			ma->stats.free.nb_free += num;
			ma->stats.free.nb_cycle += tm1 - tm0;
		}

		rte_smp_mb();
	} while (wrk_cmd == WRK_CMD_RUN);

	ma->stats.nb_cycle = rte_rdtsc_precise() - cl;

	return rc;
}

static int
test_memtank_master(void *arg)
{
	struct memtank_arg *ma;
	uint64_t cl, tm0, tm1, tm2;
	uint32_t i, n;

	ma = (struct memtank_arg *)arg;

	for (cl = 0, i = 0; cl < ma->master.run_cycles;
			cl += tm2 - tm0, i++)  {

		tm0 = rte_rdtsc_precise();
		n = tle_memtank_shrink(ma->mt);
		tm1 = rte_rdtsc_precise();
		ma->stats.shrink.nb_call++;
		ma->stats.shrink.nb_chunk += n;
		if (n != 0)
			ma->stats.shrink.nb_cycle += tm1 - tm0;

		tm1 = rte_rdtsc_precise();
		n = tle_memtank_grow(ma->mt);
		tm2 = rte_rdtsc_precise();
		ma->stats.grow.nb_call++;
		ma->stats.grow.nb_chunk += n;
		if (n != 0)
			ma->stats.grow.nb_cycle += tm2 - tm1;

		wrk_cmd = WRK_CMD_RUN;
		rte_smp_mb();

		rte_delay_us(ma->master.delay_us);
		tm2 = rte_rdtsc_precise();
	}

	ma->stats.nb_cycle = cl;

	rte_smp_mb();
	wrk_cmd = WRK_CMD_STOP;

	return 0;
}

static void
fill_worker_args(struct worker_args *wa)
{
	wa->max_obj = 2 * BULK_NUM;
	wa->obj_size = mtnk_prm.obj_size;
}

static void
fill_master_args(struct master_args *ma)
{
	uint64_t tm;

	tm = TEST_TIME * rte_get_timer_hz();

	ma->run_cycles = tm;
	ma->delay_us = US_PER_S / MS_PER_S;
}

/*
 * alloc/free by workers threads.
 * grow/shrink by master
 */
static int
test_memtank_mt(void)
{
	int32_t rc;
	uint32_t lc;
	struct tle_memtank *mt;
	struct tle_memtank_prm prm;
	struct memstat ms;
	struct memtank_arg arg[RTE_MAX_LCORE];

	printf("%s start\n", __func__);

	memset(&prm, 0, sizeof(prm));
	memset(&ms, 0, sizeof(ms));

	prm = mtnk_prm;
	prm.alloc = test_alloc1;
	prm.free = test_free1;
	prm.udata = &ms;

	mt = tle_memtank_create(&prm);
	if (mt == NULL) {
		printf("%s: memtank_create() failed\n", __func__);
		return -ENOMEM;
	}

	memset(arg, 0, sizeof(arg));

	/* launch on all slaves */
	RTE_LCORE_FOREACH_SLAVE(lc) {
		arg[lc].mt = mt;
		fill_worker_args(&arg[lc].worker);
		rte_eal_remote_launch(test_memtank_worker, &arg[lc], lc);
	}

	/* launch on master */
	lc = rte_lcore_id();
	arg[lc].mt = mt;
	fill_master_args(&arg[lc].master);
	test_memtank_master(&arg[lc]);

	/* wait for slaves and collect stats. */
	rc = 0;
	RTE_LCORE_FOREACH_SLAVE(lc) {
		rc |= rte_eal_wait_lcore(lc);
		mentank_stat_dump(stdout, lc, &arg[lc].stats);
	}

	lc = rte_lcore_id();
	mentank_stat_dump(stdout, lc, &arg[lc].stats);


	tle_memtank_destroy(mt);
	memstat_dump(stdout, &ms);
	return rc;
}

int
main(int argc, char *argv[])
{
	int32_t rc;

	rc = rte_eal_init(argc, argv);
	if (rc < 0)
		rte_exit(EXIT_FAILURE,
			"%s: rte_eal_init failed with error code: %d\n",
			__func__, rc);

	rc = test_memtank_mt();
	if (rc != 0)
		printf("TEST FAILED\n");
	else
		printf("TEST OK\n");

	return rc;
}

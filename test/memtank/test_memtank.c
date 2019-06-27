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
#include <unistd.h>

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
#include <rte_malloc.h>

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
	uint64_t nb_alloc_obj;
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
	uint32_t flags;
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
#define	MAX_OBJ		0x100000

#define	OBJ_SZ_MIN	1
#define	OBJ_SZ_MAX	0x100000
#define	OBJ_SZ_DEF	(4 * RTE_CACHE_LINE_SIZE + 1)

#define TEST_TIME	10

#define FREE_THRSH_MIN	0
#define FREE_THRSH_MAX	100

enum {
	WRK_CMD_STOP,
	WRK_CMD_RUN,
};

enum {
	MASTER_FLAG_GROW = 1,
	MASTER_FLAG_SHRINK = 2,
};

enum {
	MEM_FUNC_SYS,
	MEM_FUNC_RTE,
};

static uint32_t wrk_cmd __rte_cache_aligned;

static struct tle_memtank_prm mtnk_prm = {
	.min_free = 4 * BULK_NUM,
	.max_free = 32 * BULK_NUM,
	.max_obj = MAX_OBJ,
	.obj_size = OBJ_SZ_DEF,
	.obj_align = RTE_CACHE_LINE_SIZE,
	.nb_obj_chunk = BULK_NUM,
	.flags = TLE_MTANK_OBJ_DBG,
};

static struct {
	uint32_t run_time;       /* test run-time in seconds */
	uint32_t wrk_max_obj;    /* max alloced objects per worker */
	uint32_t wrk_free_thrsh; /* wrk free thresh % (0-100) */
	int32_t mem_func;        /* memory subsystem to use for alloc/free */
} global_cfg = {
	.run_time = TEST_TIME,
	.wrk_max_obj = 2 * BULK_NUM,
	.wrk_free_thrsh = FREE_THRSH_MIN,
	.mem_func = MEM_FUNC_SYS,
};

static void *
alloc_func(size_t sz)
{
	switch (global_cfg.mem_func) {
	case MEM_FUNC_SYS:
		return malloc(sz);
	case MEM_FUNC_RTE:
		return rte_malloc(NULL, sz, 0);
	}

	return NULL;
}

static void
free_func(void *p)
{
	switch (global_cfg.mem_func) {
	case MEM_FUNC_SYS:
		return free(p);
	case MEM_FUNC_RTE:
		return rte_free(p);
	}
}

static void *
test_alloc1(size_t sz, void *p)
{
	struct memstat *ms;
	void *buf;

	ms = p;
	buf = alloc_func(sz);
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

	free_func(buf);
	rte_atomic64_inc(&ms->free.nb_call);
	if (buf == NULL)
		rte_atomic64_inc(&ms->free.nb_fail);
}

static void
memstat_dump(FILE *f, struct memstat *ms)
{

	uint64_t alloc_sz, nb_alloc;
	long double muc, mut;

	nb_alloc = rte_atomic64_read(&ms->alloc.nb_call) -
		rte_atomic64_read(&ms->alloc.nb_fail);
	alloc_sz = rte_atomic64_read(&ms->alloc.sz) / nb_alloc;
	nb_alloc -= rte_atomic64_read(&ms->free.nb_call) -
		rte_atomic64_read(&ms->free.nb_fail);
	alloc_sz *= nb_alloc;
	mut = (alloc_sz == 0) ? 1 :
		(long double)ms->nb_alloc_obj * mtnk_prm.obj_size / alloc_sz;
	muc = (alloc_sz == 0) ? 1 :
		(long double)(ms->nb_alloc_obj + mtnk_prm.max_free) *
		mtnk_prm.obj_size / alloc_sz;

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
	fprintf(f, "\tnb_alloc_obj=%" PRIu64 ",\n", ms->nb_alloc_obj);
	fprintf(f, "\tnb_alloc_chunk=%" PRIu64 ",\n", nb_alloc);
	fprintf(f, "\talloc_sz=%" PRIu64 ",\n", alloc_sz);
	fprintf(f, "\tmem_util(total)=%.2Lf %%,\n", mut * 100);
	fprintf(f, "\tmem_util(cached)=%.2Lf %%,\n", muc * 100);
	fprintf(f, "};\n");

}

static void
memtank_stat_dump(FILE *f, uint32_t lc, const struct memtank_stat *ms)
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
	uint32_t ft, lc, n, num;
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

	/* calculate free threshold */
	ft = ma->worker.max_obj * global_cfg.wrk_free_thrsh / FREE_THRSH_MAX;

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
		num = (n >= ft) ? RTE_MIN(num, n) : 0;

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

		if (ma->master.flags & MASTER_FLAG_SHRINK) {

			n = tle_memtank_shrink(ma->mt);
			tm1 = rte_rdtsc_precise();
			ma->stats.shrink.nb_call++;
			ma->stats.shrink.nb_chunk += n;
			if (n != 0)
				ma->stats.shrink.nb_cycle += tm1 - tm0;
		}

		if (ma->master.flags & MASTER_FLAG_GROW) {

			tm1 = rte_rdtsc_precise();
			n = tle_memtank_grow(ma->mt);
			tm2 = rte_rdtsc_precise();
			ma->stats.grow.nb_call++;
			ma->stats.grow.nb_chunk += n;
			if (n != 0)
				ma->stats.grow.nb_cycle += tm2 - tm1;
		}

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
fill_worker_args(struct worker_args *wa, uint32_t alloc_flags,
	uint32_t free_flags)
{
	wa->max_obj = global_cfg.wrk_max_obj;
	wa->obj_size = mtnk_prm.obj_size;
	wa->alloc_flags = alloc_flags;
	wa->free_flags = free_flags;
}

static void
fill_master_args(struct master_args *ma, uint32_t flags)
{
	uint64_t tm;

	tm = global_cfg.run_time * rte_get_timer_hz();

	ma->run_cycles = tm;
	ma->delay_us = US_PER_S / MS_PER_S;
	ma->flags = flags;
}

/*
 * alloc/free by workers threads.
 * grow/shrink by master
 */
static int
test_memtank_mt1(void)
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
		fill_worker_args(&arg[lc].worker, 0, 0);
		rte_eal_remote_launch(test_memtank_worker, &arg[lc], lc);
	}

	/* launch on master */
	lc = rte_lcore_id();
	arg[lc].mt = mt;
	fill_master_args(&arg[lc].master,
		MASTER_FLAG_GROW | MASTER_FLAG_SHRINK);
	test_memtank_master(&arg[lc]);

	/* wait for slaves and collect stats. */
	rc = 0;
	RTE_LCORE_FOREACH_SLAVE(lc) {
		rc |= rte_eal_wait_lcore(lc);
		memtank_stat_dump(stdout, lc, &arg[lc].stats);
		ms.nb_alloc_obj += arg[lc].stats.alloc.nb_alloc -
			arg[lc].stats.free.nb_free;
	}

	lc = rte_lcore_id();
	memtank_stat_dump(stdout, lc, &arg[lc].stats);
	tle_memtank_dump(stdout, mt, 0);

	memstat_dump(stdout, &ms);

	tle_memtank_destroy(mt);
	return rc;
}

/*
 * alloc/free with grow/shrink by worker threads.
 * master does nothing
 */
static int
test_memtank_mt2(void)
{
	int32_t rc;
	uint32_t lc;
	struct tle_memtank *mt;
	struct tle_memtank_prm prm;
	struct memstat ms;
	struct memtank_arg arg[RTE_MAX_LCORE];

	const uint32_t alloc_flags = TLE_MTANK_ALLOC_CHUNK |
				TLE_MTANK_ALLOC_GROW;
	const uint32_t free_flags = TLE_MTANK_FREE_SHRINK;

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
		fill_worker_args(&arg[lc].worker, alloc_flags, free_flags);
		rte_eal_remote_launch(test_memtank_worker, &arg[lc], lc);
	}

	/* launch on master */
	lc = rte_lcore_id();
	arg[lc].mt = mt;
	fill_master_args(&arg[lc].master, 0);
	test_memtank_master(&arg[lc]);

	/* wait for slaves and collect stats. */
	rc = 0;
	RTE_LCORE_FOREACH_SLAVE(lc) {
		rc |= rte_eal_wait_lcore(lc);
		memtank_stat_dump(stdout, lc, &arg[lc].stats);
		ms.nb_alloc_obj += arg[lc].stats.alloc.nb_alloc -
			arg[lc].stats.free.nb_free;
	}

	lc = rte_lcore_id();
	memtank_stat_dump(stdout, lc, &arg[lc].stats);
	tle_memtank_dump(stdout, mt, 0);

	memstat_dump(stdout, &ms);

	tle_memtank_destroy(mt);
	return rc;
}

static int
parse_uint_val(const char *str, uint32_t *val, uint32_t min, uint32_t max)
{
	unsigned long v;
	char *end;

	errno = 0;
	v = strtoul(str, &end, 0);
	if (errno != 0 || end[0] != 0 || v < min || v > max)
		return -EINVAL;

	val[0] = v;
	return 0;
}

static int
parse_mem_str(const char *str)
{
	uint32_t i;

	static const struct {
		const char *name;
		int32_t val;
	} name2val[] = {
		{
			.name = "sys",
			.val = MEM_FUNC_SYS,
		},
		{
			.name = "rte",
			.val = MEM_FUNC_RTE,
		},
	};

	for (i = 0; i != RTE_DIM(name2val); i++) {
		if (strcmp(str, name2val[i].name) == 0)
			return name2val[i].val;
	}
	return -EINVAL;
}

static int
parse_opt(int argc, char * const argv[])
{
	int32_t opt, rc;
	uint32_t v;

	rc = 0;
	optind = 0;
	optarg = NULL;

	while ((opt = getopt(argc, argv, "f:m:s:t:w:")) != EOF) {
		switch (opt) {
		case 'f':
			rc = parse_uint_val(optarg, &v, FREE_THRSH_MIN,
				FREE_THRSH_MAX);
			if (rc == 0)
				global_cfg.wrk_free_thrsh = v;
			break;
		case 'm':
			rc = parse_mem_str(optarg);
			if (rc >= 0)
				global_cfg.mem_func = rc;
			break;
		case 's':
			rc = parse_uint_val(optarg, &v, OBJ_SZ_MIN,
				OBJ_SZ_MAX);
			if (rc == 0)
				mtnk_prm.obj_size = v;
			break;
		case 't':
			rc = parse_uint_val(optarg, &v, 0, UINT32_MAX);
			if (rc == 0)
				global_cfg.run_time = v;
			break;
		case 'w':
			rc = parse_uint_val(optarg, &v, 0, UINT32_MAX);
			if (rc == 0)
				global_cfg.wrk_max_obj = v;
			break;
		default:
			rc = -EINVAL;
		}
	}

	if (rc < 0)
		printf("%s: invalid value: \"%s\" for option: \'%c\'\n",
			__func__, optarg, opt);
	return  rc;
}

int
main(int argc, char * argv[])
{
	int32_t rc;
	uint32_t i, k;

	const struct {
		const char *name;
		int (*func)(void);
	} tests[] = {
		{
			.name = "MT1-WRK_ALLOC_FREE-MST_GROW_SHRINK",
			.func = test_memtank_mt1,
		},
		{
			.name = "MT1-WRK_ALLOC+GROW_FREE+SHRINK",
			.func = test_memtank_mt2,
		},
	};
		

	rc = rte_eal_init(argc, argv);
	if (rc < 0)
		rte_exit(EXIT_FAILURE,
			"%s: rte_eal_init failed with error code: %d\n",
			__func__, rc);

	rc = parse_opt(argc - rc, argv + rc);
	if (rc < 0)
		rte_exit(EXIT_FAILURE,
			"%s: parse_op failed with error code: %d\n",
			__func__, rc);

	for (i = 0, k = 0; i != RTE_DIM(tests); i++) {

		printf("TEST %s START\n", tests[i].name);

		rc = tests[i].func();
		k += (rc == 0);

		if (rc != 0)
			printf("TEST %s FAILED\n", tests[i].name);
		else
			printf("TEST %s OK\n", tests[i].name);
	}

	printf("Number of tests:\t%u\nSuccess:\t%u\nFailed:\t%u\n",
		i, k, i - k);
	return (k != i);
}

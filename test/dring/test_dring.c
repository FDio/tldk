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
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_ring.h>
#include <tle_dring.h>
#include <rte_random.h>

#define OBJ_NUM		UINT16_MAX
#define ITER_NUM	(4 * OBJ_NUM)

enum {
	NONE,
	SINGLE,
	MULTI,
};

struct dring_arg {
	struct tle_dring *dr;
	struct rte_ring *r;
	uint32_t iter;
	int32_t enq_type;
	int32_t deq_type;
	uint32_t enq;
	uint32_t deq;
};

/*
 * free memory allocated for drbs and for the ring itself.
 */
static void
fini_drb_ring(struct rte_ring *r)
{
	struct tle_drb *drb;

	/* free drbs. */
	while (rte_ring_dequeue(r, (void **)&drb) == 0)
		free(drb);

	/* free ring. */
	free(r);
}

/*
 * allocate drbs for specified number of objects, put them into the ring.
 */
static struct rte_ring *
init_drb_ring(uint32_t num)
{
	uint32_t i, k, n;
	size_t sz, tsz;
	struct rte_ring *r;
	struct tle_drb *drb;

	/* allocate and initialise rte_ring. */

	n = rte_align32pow2(num);
	sz =  sizeof(*r) + n * sizeof(r->ring[0]);

	r = calloc(1, sz);
	if (r == NULL) {
		printf("%s:%d(%u) failed to allocate %zu bytes;\n",
			__func__, __LINE__, num, sz);
		return NULL;
	}

	rte_ring_init(r, __func__, n, 0);

	/* allocate drbs and put them into the ring. */

	tsz = sz;
	for (i = 0; i != num; i += k) {
		k =  rte_rand() % (UINT8_MAX + 1) + 1;
		k = RTE_MIN(k, num - i);
		sz = tle_drb_calc_size(k);
		drb = calloc(1, sz);
		if (drb == NULL) {
			printf("%s:%d(%u) %u-th iteration: "
				"failed to allocate %zu bytes;\n",
				__func__, __LINE__, num, i, sz);
			fini_drb_ring(r);
			return NULL;
		}
		drb->size = k;
		rte_ring_enqueue(r, drb);
		tsz += sz;
	}

	printf("%s(%u) total %zu bytes allocated, number of drbs: %u;\n",
		__func__, num, tsz, rte_ring_count(r));
	return r;
}

/*
 * Each enqueued object will contain:
 * [2-3]B: it's own sequence number.
 * [0-1]B: next object sequence number, or UINT16_MAX.
 */
static void
test_fill_obj(uintptr_t obj[], uint32_t num)
{
	uint32_t i;

	for (i = 0; i != num - 1; i++)
		obj[i] = i << 16 | (i + 1);

	obj[i] = i << 16 | UINT16_MAX;
}

static uint32_t
test_check_obj(uintptr_t obj[], uint32_t num)
{
	uint32_t i, h, l, oh, ol;

	h = obj[0] >> 16;
	l = obj[0] & UINT16_MAX;

	if (h + 1 != l && l != UINT16_MAX)
		return 0;

	if (l == UINT16_MAX)
		l = 0;

	for (i = 1; i != num; i++) {

		oh = obj[i] >> 16;
		ol = obj[i] & UINT16_MAX;

		if (l != oh || (oh + 1 != ol && ol != UINT16_MAX))
			return i;

		l = ol;
		if (l == UINT16_MAX)
			l = 0;
	}

	return num;
}

static int
test_dring_dequeue(struct tle_dring *dr, struct rte_ring *r, uint32_t num,
	int32_t type)
{
	uint32_t i, k, lc, n, t;
	struct tle_drb *drb[num];
	uintptr_t obj[num];

	lc = rte_lcore_id();
	k = num;

	/* dequeue objects. */
	if (type == SINGLE)
		n = tle_dring_sc_dequeue(dr, (const void **)obj, num, drb, &k);
	else if (type == MULTI)
		n = tle_dring_mc_dequeue(dr, (const void **)obj, num, drb, &k);
	else
		return -EINVAL;

	if (n == 0)
		return 0;

	/* check the data returned. */
	t = test_check_obj(obj, n);
	if (t != n) {
		printf("%s:%d(%p, %u) at lcore %u: invalid dequeued object, "
			"n=%u, idx=%u, obj=%#x, prev obj=%#x;\n",
			__func__, __LINE__, dr, num, lc, n, t,
			(uint32_t)obj[t], (t == 0) ? 0 : (uint32_t)obj[t - 1]);
		return -EFAULT;
	}

	/* check and free drbs. */
	for (i = 0; i != k; i++) {
		/* udata value for drb in use shouldn't be zero. */
		if (drb[i]->udata == NULL) {
			printf("error @ %s:%d(%p, %u) at lcore %u: "
				"erroneous drb@%p={udata=%p, size=%u,};\n",
				__func__, __LINE__, dr, num, lc, drb[i],
				drb[i]->udata, drb[i]->size);
			return -EFAULT;
		}
		drb[i]->udata = NULL;
		rte_ring_enqueue(r, drb[i]);
	}

	return n;
}

static int
test_dring_enqueue(struct tle_dring *dr, struct rte_ring *r, uint32_t num,
	int32_t type)
{
	uint32_t i, j, k, lc, nb;
	struct tle_drb *drb[num];
	uintptr_t obj[num];

	lc = rte_lcore_id();

	/* prepare drbs to enqueue up to *num* objects. */
	for (i = 0, j = 0; i != num; i += k, j++) {

		if (rte_ring_dequeue(r, (void **)&drb[j]) != 0)
			break;

		/* udata value for unused drb should be zero. */
		if (drb[j]->udata != NULL) {
			printf("error @ %s:%d(%p, %u) at lcore %u: "
				"erroneous drb@%p={udata=%p, size=%u,};\n",
				__func__, __LINE__, dr, num, lc, drb[j],
				drb[j]->udata, drb[j]->size);
			return -EFAULT;
		}

		/* update udata value with current lcore id. */
		drb[j]->udata = (void *)(uintptr_t)(lc + 1);
		k = drb[j]->size;
		k = RTE_MIN(k, num - i);
	}

	/* no free drbs left. */
	if (i == 0)
		return 0;

	/* fill objects to enqueue. */
	test_fill_obj(obj, i);

	/* enqueue into the dring. */
	nb = j;
	if (type == SINGLE)
		k = tle_dring_sp_enqueue(dr, (const void **)obj, i, drb, &nb);
	else if (type == MULTI)
		k = tle_dring_mp_enqueue(dr, (const void **)obj, i, drb, &nb);
	else
		return -EINVAL;

	if (k != i) {
		printf("%s:%d(%p, %p, %u): failed to enqueue %u objects;\n",
			__func__, __LINE__, dr, r, num, i);
	}

	/* free unused drbs */
	for (i = j - nb; i != j; i++) {
		if ((uintptr_t)drb[i]->udata != lc + 1) {
			printf("error @ %s:%d(%p, %u) at lcore %u: "
				"erroneous drb@%p={udata=%p, size=%u,};\n",
				__func__, __LINE__, dr, num, lc, drb[i],
				drb[i]->udata, drb[i]->size);
			return -EFAULT;
		}
		drb[i]->udata = NULL;
		rte_ring_enqueue(r, drb[i]);
	}

	return k;
}

static int
test_dring_enq_deq(struct dring_arg *arg)
{
	int32_t rc;
	uint32_t i, lc, n;

	rc = 0;
	arg->enq = 0;
	arg->deq = 0;
	lc = rte_lcore_id();

	for (i = 0; i != arg->iter; i++) {

		/* try to enqueue random number of objects. */
		if (arg->enq_type != NONE) {
			n = rte_rand() % (UINT8_MAX + 1);
			rc = test_dring_enqueue(arg->dr, arg->r, n,
				arg->enq_type);
			if (rc < 0)
				break;
			arg->enq += rc;
		}

		/* try to dequeue random number of objects. */
		if (arg->deq_type != NONE) {
			n = rte_rand() % (UINT8_MAX + 1);
			rc = test_dring_dequeue(arg->dr, arg->r, n,
				arg->deq_type);
			if (rc < 0)
				break;
			arg->deq += rc;
		}
	}

	if (rc < 0)
		return rc;

	/* dequeue remaining objects. */
	while (arg->deq_type != NONE && arg->enq != arg->deq) {

		/* try to dequeue random number of objects. */
		n = rte_rand() % (UINT8_MAX + 1) + 1;
		rc = test_dring_dequeue(arg->dr, arg->r, n, arg->deq_type);
		if (rc <= 0)
			break;
		arg->deq += rc;
	}

	printf("%s:%d(lcore=%u, enq_type=%d, deq_type=%d): "
		"%u objects enqueued, %u objects dequeued\n",
		__func__, __LINE__, lc, arg->enq_type, arg->deq_type,
		arg->enq, arg->deq);
	return 0;
}

/*
 * enqueue/dequeue by single thread.
 */
static int
test_dring_st(void)
{
	int32_t rc;
	struct rte_ring *r;
	struct tle_dring dr;
	struct dring_arg arg;

	printf("%s started;\n", __func__);

	tle_dring_reset(&dr);
	r = init_drb_ring(OBJ_NUM);
	if (r == NULL)
		return -ENOMEM;

	tle_dring_dump(stdout, 1, &dr);

	memset(&arg, 0, sizeof(arg));
	arg.dr = &dr;
	arg.r = r;
	arg.iter = ITER_NUM;
	arg.enq_type = SINGLE;
	arg.deq_type = SINGLE;
	rc = test_dring_enq_deq(&arg);

	rc = (rc != 0) ? rc : (arg.enq != arg.deq);
	printf("%s finished with status: %s(%d);\n",
		__func__, strerror(-rc), rc);

	tle_dring_dump(stdout, rc != 0, &dr);
	fini_drb_ring(r);

	return rc;
}

static int
test_dring_worker(void *arg)
{
	struct dring_arg *p;

	p = (struct dring_arg *)arg;
	return test_dring_enq_deq(p);
}

/*
 * enqueue/dequeue by multiple threads.
 */
static int
test_dring_mt(int32_t master_enq_type, int32_t master_deq_type,
	int32_t slave_enq_type, int32_t slave_deq_type)
{
	int32_t rc;
	uint32_t lc;
	uint64_t deq, enq;
	struct rte_ring *r;
	struct tle_dring dr;
	struct dring_arg arg[RTE_MAX_LCORE];

	tle_dring_reset(&dr);
	r = init_drb_ring(OBJ_NUM);
	if (r == NULL)
		return -ENOMEM;

	memset(arg, 0, sizeof(arg));

	/* launch on all slaves */
	RTE_LCORE_FOREACH_SLAVE(lc) {
		arg[lc].dr = &dr;
		arg[lc].r = r;
		arg[lc].iter = ITER_NUM;
		arg[lc].enq_type = slave_enq_type;
		arg[lc].deq_type = slave_deq_type;
		rte_eal_remote_launch(test_dring_worker, &arg[lc], lc);
	}

	/* launch on master */
	lc = rte_lcore_id();
	arg[lc].dr = &dr;
	arg[lc].r = r;
	arg[lc].iter = ITER_NUM;
	arg[lc].enq_type = master_enq_type;
	arg[lc].deq_type = master_deq_type;
	rc = test_dring_worker(&arg[lc]);
	enq = arg[lc].enq;
	deq = arg[lc].deq;

	/* wait for slaves. */
	RTE_LCORE_FOREACH_SLAVE(lc) {
		rc |= rte_eal_wait_lcore(lc);
		enq += arg[lc].enq;
		deq += arg[lc].deq;
	}

	printf("%s:%d: total %" PRIu64 " objects enqueued, %"
		PRIu64 " objects dequeued\n",
		__func__, __LINE__, enq, deq);

	rc = (rc != 0) ? rc : (enq != deq);
	if (rc != 0)
		tle_dring_dump(stdout, 1, &dr);

	fini_drb_ring(r);
	return rc;
}

static int
test_dring_mp_mc(void)
{
	int32_t rc;

	printf("%s started;\n", __func__);
	rc = test_dring_mt(MULTI, MULTI, MULTI, MULTI);
	printf("%s finished with status: %s(%d);\n",
		__func__, strerror(-rc), rc);
	return rc;
}

static int
test_dring_mp_sc(void)
{
	int32_t rc;

	printf("%s started;\n", __func__);
	rc = test_dring_mt(MULTI, SINGLE, MULTI, NONE);
	printf("%s finished with status: %s(%d);\n",
		__func__, strerror(-rc), rc);
	return rc;
}

static int
test_dring_sp_mc(void)
{
	int32_t rc;

	printf("%s started;\n", __func__);
	rc = test_dring_mt(SINGLE, MULTI, NONE, MULTI);
	printf("%s finished with status: %s(%d);\n",
		__func__, strerror(-rc), rc);
	return rc;
}

static int
test_dring(void)
{
	int32_t rc;

	rc = test_dring_st();
	if (rc != 0)
		return rc;

	rc = test_dring_mp_mc();
	if (rc != 0)
		return rc;

	rc = test_dring_mp_sc();
	if (rc != 0)
		return rc;

	rc = test_dring_sp_mc();
	if (rc != 0)
		return rc;

	return 0;
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

	rc = test_dring();
	if (rc != 0)
		printf("TEST FAILED\n");
	else
		printf("TEST OK\n");

	return rc;
}

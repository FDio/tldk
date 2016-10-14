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

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_random.h>

#include <tle_timer.h>

struct test_elements {
	uint64_t expected_to_expire;
	uint32_t active;
	void *stop_handle;
	uint32_t id;
};

struct timer_test_main {
	struct tle_timer_wheel *tmr;
	uint32_t seed;
	uint32_t ntimers;
	uint32_t niter;
	uint32_t ticks_per_iter;
	struct test_elements *test_elts;
};

struct timer_test_main *global_test_main;

static void
run_wheel(struct tle_timer_wheel *tw, uint64_t interval)
{
	uint32_t i, j, k;
	uint64_t now = tw->last_run_time + tw->prm.tick_size + 1;
	uint32_t nb_tick;
	struct test_elements *te[MAX_TIMER_BURST];

	nb_tick = interval / tw->prm.tick_size;

	for (i = 0; i < nb_tick; i++)
	{
		tle_timer_expire(tw, now);
		now += (tw->prm.tick_size + 1);

		do {
			k = tle_timer_get_expired_bulk(tw, (void **)te,
				RTE_DIM(te));

			for (j = 0; j != k; j++)
			{
				te[j]->active = 0;
				te[j]->stop_handle = NULL;
			}
		} while (k);
	}
}

#define RDTSC_TO_SEC(t, h) 		((double)(t)/(h))

/** \brief 32-bit random number generator */
static inline uint32_t
random_uint32_t (uint32_t * seed)
{
	*seed = (1664525 * *seed) + 1013904223;
	return *seed;
}

static int
test_timer_rdtsc(void)
{
	struct timer_test_main tm;
	struct test_elements *te;
	uint64_t expiration_time;
	uint32_t i, j, k;
	uint64_t initial_wheel_offset;
	uint64_t hz, tick_size;
	struct tle_timer_wheel_args prm;
	uint64_t start_tsc, cur_tsc, diff_tsc;
	uint64_t max_expiration_time = 0;
	uint32_t adds = 0, deletes = 0;

	memset (&tm, 0, sizeof(tm));
	/* Default values */
	tm.ntimers = 1000000;
	tm.seed = 0xDEADDABE;
	tm.niter = 1000;
	tm.ticks_per_iter = 57;
	tm.test_elts = rte_zmalloc_socket(NULL,
		tm.ntimers * sizeof (tm.test_elts[0]), RTE_CACHE_LINE_SIZE,
		SOCKET_ID_ANY);
	global_test_main = &tm;

	hz = rte_get_timer_hz();
	tick_size = hz/10;
	printf("%s: hz=%lu, tick_size=%lu\n",
		__func__, hz, tick_size);

	prm.tick_size = tick_size;
	prm.max_timer = tm.ntimers;
	prm.socket_id = SOCKET_ID_ANY;
	tm.tmr = tle_timer_create (&prm);
	if (tm.tmr == NULL){
		printf("%s: tcp_timer_wheel_init failed\n", __func__);
		return -ENOMEM;
	}

	/* Prime offset */
	start_tsc = rte_rdtsc();

	initial_wheel_offset = tm.ticks_per_iter * tick_size;

	run_wheel(tm.tmr, initial_wheel_offset);

	/* Prime the pump */
	for (i = 0; i < tm.ntimers; i++)
	{
		te= &tm.test_elts[i];
		te->id = i;

		do {
			expiration_time =
				(random_uint32_t(&tm.seed) & ((1<<16) - 1)) *
				tick_size;
		} while (expiration_time == 0);

		if (expiration_time > max_expiration_time)
			max_expiration_time = expiration_time;

		te->expected_to_expire = expiration_time + initial_wheel_offset;
		te->stop_handle = tle_timer_start (tm.tmr, te, expiration_time);
		if (te->stop_handle == NULL)
			printf("%s: timer start error=%d\n",
				__func__, rte_errno);
		te->active = 1;
	}

	adds += i;

	for (i = 0; i < tm.niter; i++)
	{
		run_wheel (tm.tmr, tm.ticks_per_iter * tick_size);

		for (k = 0, j = 0; j < tm.ntimers; j++) {
			te = &tm.test_elts[j];

			if (te->active) {
				tle_timer_stop (tm.tmr, te->stop_handle);
				te->active = 0;
				te->stop_handle = NULL;
				k++;

				if (k > tm.ntimers/4)
					break;
			}
		}

		deletes += k;

		for (k = 0, j = 0; j < tm.ntimers; j++)
		{
			te = &tm.test_elts[j];

			if (!te->active) {
				do {
					expiration_time =
						(random_uint32_t(&tm.seed) &
						((1<<16) - 1)) * tick_size;
				} while (expiration_time == 0);

				if (expiration_time > max_expiration_time)
					max_expiration_time = expiration_time;

				te->expected_to_expire = expiration_time +
					(tm.tmr->current_tick * tick_size);
				te->stop_handle = tle_timer_start (tm.tmr, te,
					expiration_time);
				if (te->stop_handle == NULL)
					printf("%s: timer start error =%d\n",
						__func__, rte_errno);
				te->active = 1;
				k++;

				if (k > tm.ntimers/4)
					break;
			}
		}

		adds += k;
	}

	run_wheel(tm.tmr, max_expiration_time + 1);

	cur_tsc = rte_rdtsc();
	diff_tsc = cur_tsc - start_tsc;

	double ops_per_sec = ((double)adds + (double) deletes +
		(double)tm.tmr->current_tick) / RDTSC_TO_SEC(diff_tsc, hz);
	printf("ntimers=%u, niter=%u, %d adds, %d deletes, %d ticks\n",
		tm.ntimers, tm.niter, adds, deletes, tm.tmr->current_tick);
	printf("test ran %.2f seconds, %.2f ops/second, %.2f cycles/op\n",
		RDTSC_TO_SEC(diff_tsc, hz),
		ops_per_sec, (double)hz/ops_per_sec);

	rte_free(tm.test_elts);
	tle_timer_free(tm.tmr);

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

	rc = test_timer_rdtsc();
	if (rc != 0)
		printf("test_timer_rdtsc TEST FAILED\n");
	else
		printf("test_timer_rdtsc TEST OK\n");

	return rc;
}

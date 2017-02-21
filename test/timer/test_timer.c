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
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_random.h>
#include <rte_log.h>

#include <tle_timer.h>

#define	MAX_TIMER_BURST		0x20

#define RDTSC_TO_SEC(t, h) 		((double)(t)/(h))

struct test_elements {
	uint32_t expected_tick;
	uint32_t active;
	void *stop_handle;
	uint32_t id;
};

struct timer_test_main {
	struct tle_timer_wheel *tmr;
	uint64_t last_run_time;
	uint32_t current_tick;
	uint32_t seed;
	uint32_t ntimers;
	uint32_t niter;
	uint32_t ticks_per_iter;
	struct tle_timer_wheel_args prm;
	struct test_elements *test_elts;
};

struct timer_test_main *global_test_main;

/** \brief 32-bit random number generator */
static inline uint32_t
random_uint32_t(uint32_t *seed)
{
	*seed = (1664525 * *seed) + 1013904223;
	return *seed;
}

static void
run_wheel(struct timer_test_main *tm, uint64_t interval, uint32_t *expired)
{
	uint32_t i, j, k;
	uint64_t now = tm->last_run_time + tm->prm.tick_size;
	uint32_t nb_tick;
	struct test_elements *te[MAX_TIMER_BURST];

	nb_tick = interval / tm->prm.tick_size;

	for (i = 0; i < nb_tick; i++)
	{
		tle_timer_expire(tm->tmr, now);
		tm->last_run_time = now;

		k = tle_timer_get_expired_bulk(tm->tmr, (void **)te,
			RTE_DIM(te));
		while (k != 0) {
			for (j = 0; j != k; j++)
			{
				if (tm->current_tick != te[j]->expected_tick)
					RTE_LOG(ERR, USER1,
						"%s: [%u] expired at tick=%u, "
						"(not tick=%u)\n",
						__func__, te[j]->id,
						tm->current_tick,
						te[j]->expected_tick);

				te[j]->active = 0;
				te[j]->stop_handle = NULL;
				*expired += 1;
			}

			k = tle_timer_get_expired_bulk(tm->tmr, (void **)te,
				RTE_DIM(te));
		};
		now += (tm->prm.tick_size);
		tm->current_tick++;
	}
}

static int
test_timer_rdtsc(void)
{
	struct timer_test_main tm;
	struct test_elements *te;
	uint64_t expiration_time;
	uint32_t i, j, k;
	uint64_t initial_wheel_offset;
	struct tle_timer_wheel_args prm;
	uint64_t start_tsc, cur_tsc, diff_tsc;
	uint64_t max_expiration_time = 0;
	uint32_t adds = 0, deletes = 0, expires = 0;
	double ops_per_sec;
	uint64_t hz;

	memset(&tm, 0, sizeof(tm));
	/* Default values */
	tm.ntimers = 1000000;
	tm.seed = 0xDEADDABE;
	tm.niter = 1000;
	tm.ticks_per_iter = 57;
	tm.current_tick = 0;
	tm.test_elts = rte_zmalloc_socket(NULL,
		tm.ntimers * sizeof(tm.test_elts[0]), RTE_CACHE_LINE_SIZE,
		SOCKET_ID_ANY);
	global_test_main = &tm;

	hz = rte_get_tsc_hz(); /* timer in cpu cycles */
	prm.tick_size = hz / 10;
	prm.max_timer = tm.ntimers;
	prm.socket_id = SOCKET_ID_ANY;

	start_tsc = rte_rdtsc();

	tm.prm = prm;
	tm.tmr = tle_timer_create(&prm, start_tsc);
	tm.last_run_time = start_tsc;

	if (tm.tmr == NULL){
		printf("%s: tcp_timer_wheel_init failed\n", __func__);
		return -ENOMEM;
	}

	printf("hz=%lu, tick_size=%u, ntimers=%u, niter=%u, "
		"ticks_per_iter=%u\n", hz, prm.tick_size, tm.ntimers,
		tm.niter, tm.ticks_per_iter);

	/* Prime offset */
	initial_wheel_offset = tm.ticks_per_iter;

	run_wheel(&tm, initial_wheel_offset * prm.tick_size, &expires);

	/* Prime the pump */
	for (i = 0; i < tm.ntimers; i++)
	{
		te= &tm.test_elts[i];
		te->id = i;

		do {
			expiration_time =
				(random_uint32_t(&tm.seed) & ((1<<17) - 1));
		} while (expiration_time == 0);

		if (expiration_time > max_expiration_time)
			max_expiration_time = expiration_time;

		te->expected_tick = expiration_time + initial_wheel_offset;
		te->stop_handle = tle_timer_start(tm.tmr, te,
			expiration_time * prm.tick_size);
		if (te->stop_handle == NULL) {
			RTE_LOG(ERR, USER1, "%s: timer start error=%d\n",
				__func__, rte_errno);
			break;
		}
		te->active = 1;
	}

	adds += i;

	for (i = 0; i < tm.niter; i++)
	{
		run_wheel(&tm, initial_wheel_offset * prm.tick_size, &expires);

		for (k = 0, j = 0; j < tm.ntimers; j++) {
			te = &tm.test_elts[j];

			if (te->active) {
				tle_timer_stop(tm.tmr, te->stop_handle);
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
						((1<<17) - 1));
				} while (expiration_time == 0);

				if (expiration_time > max_expiration_time)
					max_expiration_time = expiration_time;

				te->expected_tick = expiration_time +
					tm.current_tick;
				te->stop_handle = tle_timer_start(tm.tmr, te,
					expiration_time * prm.tick_size);
				if (te->stop_handle == NULL) {
					RTE_LOG(ERR, USER1,
						"%s: timer start error =%d\n",
						__func__, rte_errno);
					break;
				}
				te->active = 1;
				k++;

				if (k > tm.ntimers/4)
					break;
			}
		}

		adds += k;
	}

	run_wheel(&tm, (max_expiration_time + 1) * prm.tick_size, &expires);

	cur_tsc = rte_rdtsc();
	diff_tsc = cur_tsc - start_tsc;

	ops_per_sec = ((double)adds + deletes +
		tm.current_tick) / RDTSC_TO_SEC(diff_tsc, hz);

	printf("%u adds, %u deletes, %u expires, %u ticks\n"
		"test ran %.2f seconds, %.2f ops/second, %.2f cycles/op\n",
		adds, deletes, expires, tm.current_tick,
		RDTSC_TO_SEC(diff_tsc, hz), ops_per_sec,
		(double)hz/ops_per_sec);

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

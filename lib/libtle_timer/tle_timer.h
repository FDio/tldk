/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *		 http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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

#ifndef __tcp_timer_h__
#define __tcp_timer_h__

#include <stdint.h>
#include <string.h>
#include <sys/queue.h>

#include <rte_config.h>
#include <rte_debug.h>
#include <rte_malloc.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @file
 *	@brief timer definitions
 *
 * Design parameters:
 *	granularity: configurable in terms of milliseconds.
 *	e.g. with 100ms tick
 *	required max period: 2.5 hours => 150 minutes => 90,000 ticks
 *	Rounding up to 256k ticks yields a two-level 512 slot-per-level
 *	wheel, resulting in a 7-hour max period.
 */

#define TW_SLOTS_PER_RING 512
#define TW_RING_SHIFT 9
#define TW_RING_MASK (TW_SLOTS_PER_RING -1)
#define TW_TIMER_ID_MASK 0x0FFFFFFF
#define	MAX_TIMER_BURST		0x20

enum {
	TW_RING_FAST,
	TW_RING_SLOW,
	TW_N_RINGS,
};

struct tle_timer_wheel_args {
	int32_t socket_id;         /**< socket ID to allocate memory for. */

	/** tick size in cpu cycles */
	uint32_t tick_size;

	/** maximum number of timers */
	uint32_t max_timer;
};

struct tle_timer_elmt {
	/** object for which timer is created */
	void *obj;

	/** ring handle to stop timer */
	uint16_t stop_ring;

	/** offset handle to stop timer */
	uint16_t stop_index;

	/** Slow ring only, saved when timer added to ring */
	uint16_t fast_index;

	LIST_ENTRY(tle_timer_elmt) link;
};

struct tle_timer_list {
	uint32_t num;
	LIST_HEAD(, tle_timer_elmt) head;
};

struct tle_timer_wheel {
	/** Next time the wheel should run */
	uint64_t next_run_time;

	/** Last time the wheel ran */
	uint64_t last_run_time;

	/** current tick */
	uint32_t current_tick;

	/** current wheel indices */
	uint32_t current_index[TW_N_RINGS];

	/** wheel arrays */
	struct tle_timer_list w[TW_N_RINGS][TW_SLOTS_PER_RING];

	/** free timers */
	struct tle_timer_list free;

	/** expired timers */
	struct tle_timer_list expired;

	/** timer wheel params */
	struct tle_timer_wheel_args prm;
};

/** initialize a timer wheel */
struct tle_timer_wheel *
tle_timer_create(struct tle_timer_wheel_args *prm);

/** free a timer wheel */
void
tle_timer_free(struct tle_timer_wheel *tw);

/** start a timer */
void *
tle_timer_start(struct tle_timer_wheel *tw, void *obj,
	uint64_t interval);

/** Stop a timer */
void
tle_timer_stop(struct tle_timer_wheel *tw, void *timer);

/** run the timer wheel. Call every tcp_tick timer (e.g. 100ms). */
void
tle_timer_expire(struct tle_timer_wheel *tw, uint64_t now);

/** retrieve the num expired timers. */
int
tle_timer_get_expired_bulk(struct tle_timer_wheel *tw, void *timers[],
	uint32_t num);

#ifdef __cplusplus
}
#endif

#endif /* __tcp_timer_h__ */

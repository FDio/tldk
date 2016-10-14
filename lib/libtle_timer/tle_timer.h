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

#ifndef __tle_timer_h__
#define __tle_timer_h__

#include <stdint.h>
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
 *	granularity: configurable in terms of units (i.e. cycles or ms).
 *	e.g. with 100ms tick
 *	required max period: 2.5 hours => 150 minutes => 90,000 ticks
 *	Rounding up to 256k ticks yields a two-level 512 slot-per-level
 *	wheel, resulting in a 7-hour max period.
 */

struct tle_timer_wheel_args {
	uint32_t tick_size; /** tick size in units */

	int32_t socket_id; /**< socket ID to allocate memory for. */

	uint32_t max_timer; /** maximum number of timers */
};

struct tle_timer_wheel;

/** initialize a timer wheel */
struct tle_timer_wheel *
tle_timer_create(struct tle_timer_wheel_args *prm, uint64_t now);

/** free a timer wheel */
void
tle_timer_free(struct tle_timer_wheel *tw);

/** start a timer */
void *
tle_timer_start(struct tle_timer_wheel *tw, void *obj, uint64_t interval);

/** stop a timer */
void
tle_timer_stop(struct tle_timer_wheel *tw, void *timer);

/** run the timer wheel. Call in every tick_size cycles
 * (e.g. equivalent of 100ms).
 */
void
tle_timer_expire(struct tle_timer_wheel *tw, uint64_t now);

/** bulk retrieve of expired timers */
int
tle_timer_get_expired_bulk(struct tle_timer_wheel *tw, void *timers[],
	uint32_t num);

#ifdef __cplusplus
}
#endif

#endif /* __tle_timer_h__ */

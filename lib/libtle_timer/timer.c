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

#include <string.h>
#include <sys/queue.h>
#include <rte_spinlock.h>
#include <rte_cycles.h>
#include <rte_errno.h>
#include <tle_timer.h>

#define TW_SLOTS_PER_RING	512
#define TW_RING_SHIFT		9
#define TW_RING_MASK		(TW_SLOTS_PER_RING - 1)
#define	MAX_TIMER_BURST		0x20

enum {
	TW_RING_FAST,
	TW_RING_SLOW,
	TW_N_RINGS,
};

struct tle_timer_list;

struct tle_timer_elmt {
	void *obj; /** object for which timer is created */

	struct tle_timer_list *list; /* current list object belongs to */

	/** Slow ring only, saved when timer added to ring */
	uint16_t fast_index;

	LIST_ENTRY(tle_timer_elmt) link;
};

struct tle_timer_list {
	uint32_t num;
	rte_spinlock_t lock;
	LIST_HEAD(, tle_timer_elmt) head;
};

struct tle_timer_wheel {
	uint64_t next_run_time; /** Next time the wheel should run */

	uint64_t last_run_time; /** Last time the wheel ran */

	uint32_t current_tick; /** current tick */

	uint32_t current_index[TW_N_RINGS]; /** current wheel indices */

	struct tle_timer_list free; /** free timers to be used */

	struct tle_timer_list expired; /** expired timers to be pulled */

	struct tle_timer_wheel_args prm; /** timer wheel configuration params */

	/** wheel arrays */
	struct tle_timer_list w[TW_N_RINGS][TW_SLOTS_PER_RING];
};

/** helper functions to manipulate the linked lists */
static inline uint32_t
get_timers(struct tle_timer_list *list, struct tle_timer_elmt *re[],
	uint32_t num)
{
	struct tle_timer_elmt *e;
	uint32_t i, n;

	n = RTE_MIN(list->num, num);
	for (i = 0; i != n; i++) {
		e = LIST_FIRST(&list->head);
		LIST_REMOVE(e, link);
		e->list = NULL;
		re[i] = e;
	}

	list->num -= n;
	return n;
}

static inline struct tle_timer_elmt *
get_timer(struct tle_timer_list *list)
{
	struct tle_timer_elmt *e;

	e = LIST_FIRST(&list->head);
	LIST_REMOVE(e, link);
	e->list = NULL;
	list->num--;
	return e;
}

static inline void
put_timers(struct tle_timer_list *list, struct tle_timer_elmt *te[],
	uint32_t num)
{
	uint32_t i;

	for (i = 0; i != num; i++) {
		te[i]->list = list;
		LIST_INSERT_HEAD(&list->head, te[i], link);
	}
	list->num += num;
}

static inline void
put_timer(struct tle_timer_list *list, struct tle_timer_elmt *e)
{
	e->list = list;
	LIST_INSERT_HEAD(&list->head, e, link);
	list->num++;
}

static inline struct tle_timer_elmt *
get_free_timer(struct tle_timer_wheel *tw)
{
	unsigned i, n;
	struct tle_timer_elmt *e;

	rte_spinlock_lock(&tw->free.lock);
	e = LIST_FIRST(&tw->free.head);
	if (e == NULL) {
		n = 128;
		n = RTE_MIN(n, tw->prm.max_timer - tw->free.num);
		for (i = 0; i < n; i++) {
			e = rte_zmalloc_socket(NULL, sizeof(*e),
					sizeof(e), tw->prm.socket_id);
			if (e != NULL)
				put_timer(&tw->free, e);
			else
				rte_panic("Failed to allocate timer");
		}
	}

	e = get_timer(&tw->free);
	rte_spinlock_unlock(&tw->free.lock);
	return e;
}

static inline void
rem_timer(struct tle_timer_list *list, struct tle_timer_elmt *e)
{
	LIST_REMOVE(e, link);
	e->list = NULL;
	list->num--;
}

/** create the tle timer wheel */
struct tle_timer_wheel *
tle_timer_create(struct tle_timer_wheel_args *prm, uint64_t now)
{
	uint32_t i, j;
	size_t sz;
	struct tle_timer_wheel *tw;

	if (prm == NULL) {
		rte_errno = -EINVAL;
		return NULL;
	}

	/* at least one timer has to be created */
	if (prm->max_timer == 0) {
		rte_errno = -EINVAL;
		return NULL;
	}

	/* do not allow tick size smaller than 1ms */
	if (prm->tick_size == 0) {
		rte_errno = -EINVAL;
		return NULL;
	}

	sz = sizeof(*tw);

	/* allocate memory */
	tw = rte_zmalloc_socket(NULL, sz, RTE_CACHE_LINE_SIZE,
		prm->socket_id);

	if (tw == NULL) {
		rte_errno = -ENOMEM;
		return NULL;
	}

	tw->last_run_time = now;
	tw->prm = *prm;

	/* initialize the lists */
	LIST_INIT(&tw->free.head);
	LIST_INIT(&tw->expired.head);

	for (i = 0; i < TW_N_RINGS; i++)
		for (j = 0; j < TW_SLOTS_PER_RING; j++)
			LIST_INIT(&tw->w[i][j].head);

	return tw;
}

/** free the tle timer wheel */
void
tle_timer_free(struct tle_timer_wheel *tw)
{
	rte_free(tw);
}

/** start a timer */
void *
tle_timer_start(struct tle_timer_wheel *tw, void *obj, uint64_t interval)
{
	uint16_t slow_ring_index, fast_ring_index;
	struct tle_timer_list *ts;
	struct tle_timer_elmt *e;
	uint32_t carry;
	uint32_t nb_tick;

	rte_errno = 0;
	if (!interval) {
		rte_errno = EINVAL;
		return NULL;
	}

	nb_tick = interval / tw->prm.tick_size;

	fast_ring_index = nb_tick & TW_RING_MASK;
	fast_ring_index += tw->current_index[TW_RING_FAST];
	carry = fast_ring_index >= TW_SLOTS_PER_RING ? 1 : 0;
	fast_ring_index %= TW_SLOTS_PER_RING;
	slow_ring_index = (nb_tick >> TW_RING_SHIFT) + carry;

	/* Timer duration exceeds ~7 hrs? Oops */
	if (slow_ring_index >= TW_SLOTS_PER_RING) {
		rte_errno = ERANGE;
		return NULL;
	}

	/* Timer expires more than 51.2 seconds from now? */
	if (slow_ring_index) {
		slow_ring_index += tw->current_index[TW_RING_SLOW];
		slow_ring_index %= TW_SLOTS_PER_RING;
		ts = &tw->w[TW_RING_SLOW][slow_ring_index];

		e = get_free_timer(tw);
		e->obj = obj;
		e->fast_index = fast_ring_index;
		rte_spinlock_lock(&ts->lock);
		put_timer(ts, e);
		rte_spinlock_unlock(&ts->lock);

		/* Return the user timer-cancellation handle */
		return (void *)e;
	}

	/* Timer expires less than 51.2 seconds from now */
	ts = &tw->w[TW_RING_FAST][fast_ring_index];

	e = get_free_timer(tw);
	e->obj = obj;
	rte_spinlock_lock(&ts->lock);
	put_timer(ts, e);
	rte_spinlock_unlock(&ts->lock);

	/* Give the user a handle to cancel the timer */
	return (void *)e;
}

/** stop a timer */
void tle_timer_stop(struct tle_timer_wheel *tw, void *timer)
{
	struct tle_timer_elmt *e;
	struct tle_timer_list *ts;

	/* Cancel the timer */
	e = (struct tle_timer_elmt *)timer;
	ts = e->list;
	while (ts != &tw->free) {
		if (ts == NULL) {
			rte_pause();
			ts = e->list;
			continue;
		}
		rte_spinlock_lock(&ts->lock);
		if (ts != e->list) {
			rte_spinlock_unlock(&ts->lock);
			ts = e->list;
			continue;
		}
		rem_timer(ts, e);
		rte_spinlock_unlock(&ts->lock);
		rte_spinlock_lock(&tw->free.lock);
		put_timer(&tw->free, e);
		rte_spinlock_unlock(&tw->free.lock);
		break;
	}
}

/** run the timer wheel. Call in every tick_size cycles
 * (e.g. equivalent of 100ms).
 */
void tle_timer_expire(struct tle_timer_wheel *tw, uint64_t now)
{
	uint32_t nb_tick, i, n;
	uint32_t fast_wheel_index, slow_wheel_index, demoted_index;
	struct tle_timer_list *ts, *ts2;
	struct tle_timer_elmt *re[MAX_TIMER_BURST], *e;

	/* Shouldn't happen */
	if (unlikely(now < tw->next_run_time))
		return;

	/* Number of tick_size cycles which have occurred */
	nb_tick = (now - tw->last_run_time) / tw->prm.tick_size;
	if (nb_tick == 0)
		return;

	/* Remember when we ran, compute next runtime */
	tw->next_run_time = (now + tw->prm.tick_size);
	tw->last_run_time = now;

	for (i = 0; i < nb_tick; i++) {
		fast_wheel_index = tw->current_index[TW_RING_FAST];

		/* If we've been around the fast ring once,
		 * process one slot in the slow ring before we handle
		 * the fast ring.
		 */
		if (unlikely(fast_wheel_index == TW_SLOTS_PER_RING)) {
			fast_wheel_index = tw->current_index[TW_RING_FAST] = 0;

			tw->current_index[TW_RING_SLOW]++;
			tw->current_index[TW_RING_SLOW] %= TW_SLOTS_PER_RING;
			slow_wheel_index = tw->current_index[TW_RING_SLOW];

			ts = &tw->w[TW_RING_SLOW][slow_wheel_index];

			/* Deal slow-ring elements into the fast ring. */
			rte_spinlock_lock(&ts->lock);
			while (ts->num != 0) {
				e = get_timer(ts);
				demoted_index = e->fast_index;
				ts2 = &tw->w[TW_RING_FAST][demoted_index];
				rte_spinlock_lock(&ts2->lock);
				put_timer(ts2, e);
				rte_spinlock_unlock(&ts2->lock);
			};
			LIST_INIT(&ts->head);
			rte_spinlock_unlock(&ts->lock);
		}

		/* Handle the fast ring */
		ts = &tw->w[TW_RING_FAST][fast_wheel_index];

		/* Clear the fast-ring slot and move timers in expired list*/
		rte_spinlock_lock(&ts->lock);
		n = get_timers(ts, re, RTE_DIM(re));
		rte_spinlock_lock(&tw->expired.lock);
		while (n != 0) {
			put_timers(&tw->expired, re, n);
			n = get_timers(ts, re, RTE_DIM(re));
		};
		rte_spinlock_unlock(&tw->expired.lock);
		LIST_INIT(&ts->head);
		rte_spinlock_unlock(&ts->lock);

		tw->current_index[TW_RING_FAST]++;
		tw->current_tick++;
	}
}

/** bulk retrieve of expired timers */
int
tle_timer_get_expired_bulk(struct tle_timer_wheel *tw, void *rt[], uint32_t num)
{
	uint32_t i, n;
	struct tle_timer_elmt *e[MAX_TIMER_BURST];

	rte_spinlock_lock(&tw->expired.lock);
	n = get_timers(&tw->expired, e, num);
	rte_spinlock_unlock(&tw->expired.lock);

	for (i = 0; i != n; i++)
		rt[i] = e[i]->obj;

	rte_spinlock_lock(&tw->free.lock);
	put_timers(&tw->free, e, n);
	rte_spinlock_unlock(&tw->free.lock);

	return n;
}

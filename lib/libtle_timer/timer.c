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

#include <rte_errno.h>
#include <tle_timer.h>

static uint32_t
get_timers(struct tle_timer_list *list,
	struct tle_timer_elmt *re[],
	uint32_t num)
{
	struct tle_timer_elmt *e;
	uint32_t i, n;

	n = RTE_MIN(list->num, num);
	for (i = 0, e = LIST_FIRST(&list->head);
			i != n;
			i++, e = LIST_NEXT(e, link)) {
		re[i] = e;
	}

	if (e == NULL)
		/* we retrieved all free entries */
		LIST_INIT(&list->head);
	else
		LIST_FIRST(&list->head) = e;

	list->num -= n;

	return n;
}

static struct tle_timer_elmt *
get_timer(struct tle_timer_list *list)
{
	struct tle_timer_elmt *e;

	e = NULL;
	if (list->num == 0)
		return e;

	get_timers(list, &e, 1);

	return e;
}

static inline void
put_timers(struct tle_timer_wheel *tw, struct tle_timer_list *list,
	struct tle_timer_elmt *te[], uint32_t num)
{
	uint32_t i, n;

	n = RTE_MIN(tw->prm.max_timer - list->num, num);
	if (n != num)
		RTE_LOG(ERR, USER1,
			"%s: list overflow by %u\n", __func__, num - n);

	for (i = 0; i != n; i++) {
		LIST_INSERT_HEAD(&list->head, te[i], link);
	}
	list->num += n;
}

static void
put_timer(struct tle_timer_wheel *tw, struct tle_timer_list *list,
	struct tle_timer_elmt *e)
{
	if (list->num == tw->prm.max_timer) {
		RTE_LOG(ERR, USER1, "%s: list is full\n", __func__);
		return;
	}

	put_timers(tw, list, &e, 1);
}

static inline void
rem_timer(struct tle_timer_list *list, struct tle_timer_elmt *e)
{
	LIST_REMOVE(e, link);
	list->num--;
}

/** create the tle timer wheel */
struct tle_timer_wheel *
tle_timer_create(struct tle_timer_wheel_args *prm)
{
	uint32_t i, j;
	size_t sz;
	struct tle_timer_wheel *tw;
	struct tle_timer_elmt *e;
	struct tle_timer_elmt *timers;

	sz = sizeof(*tw) + prm->max_timer * sizeof(struct tle_timer_elmt);

	/* allocate memory */
	tw = rte_zmalloc_socket(NULL, sz, RTE_CACHE_LINE_SIZE,
		prm->socket_id);

	if (tw == NULL) {
		rte_errno = -ENOMEM;
		return NULL;
	}

	tw->prm = *prm;
	timers = (struct tle_timer_elmt *)(tw + 1);

	/* initialize the stream pool */
	LIST_INIT(&tw->free.head);
	LIST_INIT(&tw->expired.head);

	for (i = 0; i < prm->max_timer; i++) {
		e = timers + i;
		put_timer(tw, &tw->free, e);
	}

	for (i = 0; i < TW_N_RINGS; i++)
	{
		for (j = 0; j < TW_SLOTS_PER_RING; j++)
		{
			LIST_INIT(&tw->w[i][j].head);
		}
	}

	return tw;
}

/** free the tle timer wheel */
void
tle_timer_free(struct tle_timer_wheel *tw)
{
	int i, j;
	struct tle_timer_list *ts;
	struct tle_timer_elmt *e;

	for (i = 0; i < TW_N_RINGS; i++)
	{
		for (j = 0; j < TW_SLOTS_PER_RING; j++)
		{
			ts = &tw->w[i][j];

			while(!LIST_EMPTY(&ts->head)) {
				e = LIST_FIRST(&ts->head);
				LIST_REMOVE(e, link);
			}
			LIST_INIT(&ts->head);
		}
	}

	rte_free(tw);
	memset (tw, 0, sizeof (*tw));
}

/** start a timer */
void *
tle_timer_start(struct tle_timer_wheel *tw, void *obj,
	uint64_t interval)
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
	if (slow_ring_index)
	{
		slow_ring_index += tw->current_index[TW_RING_SLOW];
		slow_ring_index %= TW_SLOTS_PER_RING;
		ts = &tw->w[TW_RING_SLOW][slow_ring_index];

		e = get_timer(&tw->free);
		e->stop_ring = TW_RING_SLOW;
		e->stop_index = slow_ring_index;
		e->obj = obj;
		e->fast_index = fast_ring_index;
		put_timer(tw, ts, e);

		/* Return the user timer-cancellation handle */
		return (void *)e;
	}

	/* Timer expires less than 51.2 seconds from now */
	ts = &tw->w[TW_RING_FAST][fast_ring_index];

	e = get_timer(&tw->free);
	e->stop_ring = TW_RING_FAST;
	e->stop_index = fast_ring_index;
	e->obj = obj;
	put_timer(tw, ts, e);

	/* Give the user a handle to cancel the timer */
	return (void *)e;
}

/** Stop a timer
 * We pass the timer_index and timer_id for consistency-checking only.
 */

void tle_timer_stop (struct tle_timer_wheel *tw, void *timer)
{
	struct tle_timer_elmt *e;
	struct tle_timer_list *ts;

	RTE_SET_USED(tw);

	/* Cancel the timer */
	e = (struct tle_timer_elmt *)timer;
	ts = &tw->w[e->stop_ring][e->stop_index];
	rem_timer(ts, e);
	memset(e, 0, sizeof(*e));
	put_timer(tw, &tw->free, e);
}

/** run the timer wheel. Call every tick_size (e.g. 100ms). */

void tle_timer_expire(struct tle_timer_wheel *tw, uint64_t now)
{
	uint32_t nb_tick, i, n;
	struct tle_timer_list *ts;
	struct tle_timer_list *ts2;
	struct tle_timer_elmt *e;
	struct tle_timer_elmt *re[MAX_TIMER_BURST];
	uint32_t fast_wheel_index, slow_wheel_index;
	uint32_t demoted_index;

	/* Shouldn't happen */
	if (unlikely(now < tw->next_run_time))
		return;

	/* Number of 100ms ticks which have occurred */
	nb_tick = (now - tw->last_run_time) / tw->prm.tick_size;
	if (nb_tick == 0)
		return;

	/* Remember when we ran, compute next runtime */
	tw->next_run_time = (now + tw->prm.tick_size);
	tw->last_run_time = now;

	for (i = 0; i < nb_tick; i++)
	{
		fast_wheel_index = tw->current_index[TW_RING_FAST];

		/*
		 * If we've been around the fast ring once,
		 * process one slot in the slow ring before we handle
		 * the fast ring.
		 */
		if (unlikely(fast_wheel_index == TW_SLOTS_PER_RING))
		{
			fast_wheel_index = tw->current_index[TW_RING_FAST] = 0;

			tw->current_index[TW_RING_SLOW]++;
			tw->current_index[TW_RING_SLOW] %= TW_SLOTS_PER_RING;
			slow_wheel_index = tw->current_index[TW_RING_SLOW];

			ts = &tw->w[TW_RING_SLOW][slow_wheel_index];

			/* Deal slow-ring elements into the fast ring. */
			while(ts->num != 0) {
				e = get_timer(ts);
				e->stop_ring = TW_RING_FAST;
				e->stop_index = e->fast_index;
				demoted_index = e->fast_index;
				ts2 = &tw->w[TW_RING_FAST][demoted_index];
				put_timer(tw, ts2, e);
			};
			LIST_INIT(&ts->head);
		}

		/* Handle the fast ring */
		ts = &tw->w[TW_RING_FAST][fast_wheel_index];

		/* Clear the fast-ring slot */
		do {
			n = get_timers(ts, re, RTE_DIM(re));
			put_timers(tw, &tw->expired, re, n);
		} while (n != 0);
		LIST_INIT(&ts->head);

		tw->current_index[TW_RING_FAST]++;
		tw->current_tick++;
		RTE_VERIFY(tw->current_tick);
	}
}

int
tle_timer_get_expired_bulk(struct tle_timer_wheel *tw, void *rt[],
	uint32_t num)
{
	uint32_t i, n;
	struct tle_timer_elmt *e;

	n = RTE_MIN(tw->expired.num, num);

	for (i = 0; i != n; i++){
		e = get_timer(&tw->expired);
		rt[i] = (void *)e->obj;
		memset(e, 0, sizeof(*e));
		put_timer(tw, &tw->free, e);
	}

	return n;
}

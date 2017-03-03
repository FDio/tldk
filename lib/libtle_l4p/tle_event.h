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

#ifndef _SEV_IMPL_H_
#define _SEV_IMPL_H_

#include <rte_common.h>
#include <rte_memory.h>
#include <rte_spinlock.h>
#include <rte_atomic.h>
#include <sys/queue.h>

#ifdef __cplusplus
extern "C" {
#endif

struct tle_evq;

/**
 * Possible states of the event.
 */
enum tle_ev_state {
	TLE_SEV_IDLE,
	TLE_SEV_DOWN,
	TLE_SEV_UP,
	TLE_SEV_NUM
};

struct tle_event {
	TAILQ_ENTRY(tle_event) ql;
	struct tle_evq *head;
	const void *data;
	enum tle_ev_state state;
} __rte_cache_aligned;

struct tle_evq {
	rte_spinlock_t lock;
	uint32_t nb_events;
	uint32_t nb_armed;
	uint32_t nb_free;
	TAILQ_HEAD(, tle_event) armed;
	TAILQ_HEAD(, tle_event) free;
	struct tle_event events[0];
};

/**
 * event queue creation parameters.
 */
struct tle_evq_param {
	int32_t socket_id;    /**< socket ID to allocate memory from. */
	uint32_t max_events;  /**< max number of events in queue. */
};

/**
 * create event queue.
 * @param prm
 *   Parameters used to create and initialise the queue.
 * @return
 *   Pointer to new event queue structure,
 *   or NULL on error, with error code set in rte_errno.
 *   Possible rte_errno errors include:
 *   - EINVAL - invalid parameter passed to function
 *   - ENOMEM - out of memory
 */
struct tle_evq *tle_evq_create(const struct tle_evq_param *prm);

/**
 * Destroy given event queue.
 *
 * @param evq
 *   event queue to destroy
 */
void tle_evq_destroy(struct tle_evq *evq);

/**
 * allocate a new event within given event queue.
 * @param evq
 *    event queue to allocate a new stream within.
 * @param data
 *   User data to be associated with that event.
 * @return
 *   Pointer to event structure that can be used in future tle_event API calls,
 *   or NULL on error, with error code set in rte_errno.
 *   Possible rte_errno errors include:
 *   - EINVAL - invalid parameter passed to function
 *   - ENOMEM - max limit of allocated events reached for that context
 */
struct tle_event *tle_event_alloc(struct tle_evq *evq, const void *data);

/**
 * free an allocated event.
 * @param ev
 *   Pointer to the event to free.
 */
void tle_event_free(struct tle_event *ev);

static inline enum tle_ev_state
tle_event_state(const struct tle_event *ev)
{
	return ev->state;
}

/**
 * move event from DOWN to UP state.
 * @param ev
 *   Pointer to the event.
 */
static inline void
tle_event_raise(struct tle_event *ev)
{
	struct tle_evq *q;

	if (ev->state != TLE_SEV_DOWN)
		return;

	q = ev->head;
	rte_compiler_barrier();

	rte_spinlock_lock(&q->lock);
	if (ev->state == TLE_SEV_DOWN) {
		ev->state = TLE_SEV_UP;
		TAILQ_INSERT_TAIL(&q->armed, ev, ql);
		q->nb_armed++;
	}
	rte_spinlock_unlock(&q->lock);
}

/**
 * move event from UP to DOWN state.
 * @param ev
 *   Pointer to the event.
 */
static inline void
tle_event_down(struct tle_event *ev)
{
	struct tle_evq *q;

	if (ev->state != TLE_SEV_UP)
		return;

	q = ev->head;
	rte_compiler_barrier();

	rte_spinlock_lock(&q->lock);
	if (ev->state == TLE_SEV_UP) {
		ev->state = TLE_SEV_DOWN;
		TAILQ_REMOVE(&q->armed, ev, ql);
		q->nb_armed--;
	}
	rte_spinlock_unlock(&q->lock);
}

/**
 * move from IDLE to DOWN/UP state.
 * @param ev
 *   Pointer to the event.
 * @param st
 *   new state for the event.
 */
static inline void
tle_event_active(struct tle_event *ev, enum tle_ev_state st)
{
	struct tle_evq *q;

	if (ev->state != TLE_SEV_IDLE)
		return;

	q = ev->head;
	rte_compiler_barrier();

	rte_spinlock_lock(&q->lock);
	if (st > ev->state) {
		if (st == TLE_SEV_UP) {
			TAILQ_INSERT_TAIL(&q->armed, ev, ql);
			q->nb_armed++;
		}
		ev->state = st;
	}
	rte_spinlock_unlock(&q->lock);
}

/**
 * move event IDLE state.
 * @param ev
 *   Pointer to the event.
 */
static inline void
tle_event_idle(struct tle_event *ev)
{
	struct tle_evq *q;

	if (ev->state == TLE_SEV_IDLE)
		return;

	q = ev->head;
	rte_compiler_barrier();

	rte_spinlock_lock(&q->lock);
	if (ev->state == TLE_SEV_UP) {
		TAILQ_REMOVE(&q->armed, ev, ql);
		q->nb_armed--;
	}
	ev->state = TLE_SEV_IDLE;
	rte_spinlock_unlock(&q->lock);
}

static inline void
tle_evq_idle(struct tle_evq *evq, struct tle_event *ev[], uint32_t num)
{
	uint32_t i, n;

	rte_spinlock_lock(&evq->lock);

	n = 0;
	for (i = 0; i != num; i++) {
		if (ev[i]->state == TLE_SEV_UP) {
			TAILQ_REMOVE(&evq->armed, ev[i], ql);
			n++;
		}
		ev[i]->state = TLE_SEV_IDLE;
	}

	evq->nb_armed -= n;
	rte_spinlock_unlock(&evq->lock);
}


/*
 * return up to *num* user data pointers associated with
 * the events that were in the UP state.
 * Each retrieved event is automatically moved into the DOWN state.
 * @param evq
 *   event queue to retrieve events from.
 * @param evd
 *   An array of user data pointers associated with the events retrieved.
 *   It must be large enough to store up to *num* pointers in it.
 * @param num
 *   Number of elements in the *evd* array.
 * @return
 *   number of of entries filled inside *evd* array.
 */
static inline int32_t
tle_evq_get(struct tle_evq *evq, const void *evd[], uint32_t num)
{
	uint32_t i, n;
	struct tle_event *ev;

	if (evq->nb_armed == 0)
		return 0;

	rte_compiler_barrier();

	rte_spinlock_lock(&evq->lock);
	n = RTE_MIN(num, evq->nb_armed);
	for (i = 0; i != n; i++) {
		ev = TAILQ_FIRST(&evq->armed);
		ev->state = TLE_SEV_DOWN;
		TAILQ_REMOVE(&evq->armed, ev, ql);
		evd[i] = ev->data;
	}
	evq->nb_armed -= n;
	rte_spinlock_unlock(&evq->lock);
	return n;
}


#ifdef __cplusplus
}
#endif

#endif /* _SEV_IMPL_H_ */

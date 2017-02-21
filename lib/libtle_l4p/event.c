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
#include <rte_malloc.h>
#include <rte_log.h>
#include <tle_event.h>

#include "osdep.h"

struct tle_evq *
tle_evq_create(const struct tle_evq_param *prm)
{
	struct tle_evq *evq;
	size_t sz;
	uint32_t i;

	if (prm == NULL) {
		rte_errno = EINVAL;
		return NULL;
	}

	sz = sizeof(*evq) + sizeof(evq->events[0]) * prm->max_events;
	evq =  rte_zmalloc_socket(NULL, sz, RTE_CACHE_LINE_SIZE,
		prm->socket_id);
	if (evq == NULL) {
		UDP_LOG(ERR, "allocation of %zu bytes for "
			"new tle_evq(%u) on socket %d failed\n",
			sz, prm->max_events, prm->socket_id);
		return NULL;
	}

	TAILQ_INIT(&evq->armed);
	TAILQ_INIT(&evq->free);

	for (i = 0; i != prm->max_events; i++) {
		evq->events[i].head = evq;
		TAILQ_INSERT_TAIL(&evq->free, evq->events + i, ql);
	}

	evq->nb_events = i;
	evq->nb_free = i;

	return evq;
}

void
tle_evq_destroy(struct tle_evq *evq)
{
	rte_free(evq);
}

struct tle_event *
tle_event_alloc(struct tle_evq *evq, const void *data)
{
	struct tle_event *h;

	if (evq == NULL) {
		rte_errno = EINVAL;
		return NULL;
	}

	rte_spinlock_lock(&evq->lock);
	h = TAILQ_FIRST(&evq->free);
	if (h != NULL) {
		TAILQ_REMOVE(&evq->free, h, ql);
		evq->nb_free--;
		h->data = data;
	} else
		rte_errno = ENOMEM;
	rte_spinlock_unlock(&evq->lock);
	return h;
}

void
tle_event_free(struct tle_event *ev)
{
	struct tle_evq *q;

	if (ev == NULL) {
		rte_errno = EINVAL;
		return;
	}

	q = ev->head;
	rte_spinlock_lock(&q->lock);
	ev->data = NULL;
	ev->state = TLE_SEV_IDLE;
	TAILQ_INSERT_HEAD(&q->free, ev, ql);
	q->nb_free++;
	rte_spinlock_unlock(&q->lock);
}

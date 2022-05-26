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

#include "test_tle_event.h"

TEST_F(tle_evq_test, tle_evq_create_null)
{
	evq = tle_evq_create(NULL);
	EXPECT_EQ(evq, (struct tle_evq *) NULL);
	EXPECT_EQ(rte_errno, EINVAL);
}

TEST_F(tle_evq_test, tle_evq_create_invalid_socket)
{
	evq_params.socket_id = 999;
	evq = tle_evq_create(&evq_params);
	ASSERT_EQ(evq, (struct tle_evq *) NULL);
}

TEST_F(tle_evq_test, tle_evq_create_destroy_positive)
{
	evq = tle_evq_create(&evq_params);
	ASSERT_NE(evq, (struct tle_evq *) NULL);
	EXPECT_EQ(rte_errno, 0);
	EXPECT_EQ(evq->nb_events, max_events);
	EXPECT_EQ(evq->nb_free, max_events);
	tle_evq_destroy(evq);
	EXPECT_EQ(rte_errno, 0);
}

TEST_F(tle_event_test, tle_event_alloc_null)
{
	event = tle_event_alloc(NULL, (void *) &fake_data);
	EXPECT_EQ(event, (struct tle_event *) NULL);
	EXPECT_EQ(rte_errno, EINVAL);
}

TEST_F(tle_event_test, tle_event_free_null)
{
	tle_event_free(NULL);
	EXPECT_EQ(rte_errno, EINVAL);
}

TEST_F(tle_event_test, tle_event_alloc_free_positive)
{
	event = tle_event_alloc(evq, (void *) &fake_data);
	ASSERT_NE(event, (struct tle_event *) NULL);
	EXPECT_EQ(rte_errno, 0);
	EXPECT_EQ(evq->nb_free, max_events - 1);
	tle_event_free(event);
	EXPECT_EQ(rte_errno, 0);
	EXPECT_EQ(evq->nb_free, max_events);
}

TEST_F(tle_event_test, tle_event_alloc_free_active_up)
{
	// basic setup
  event = tle_event_alloc(evq, (void *) &fake_data);
	ASSERT_NE(event, (struct tle_event *) NULL);
	EXPECT_EQ(rte_errno, 0);
	EXPECT_EQ(evq->nb_free, max_events - 1);

  // activate event
	tle_event_active(event, TLE_SEV_UP);
  ASSERT_EQ(event->state, TLE_SEV_UP);
  EXPECT_EQ(evq->nb_armed, 1);

  // free (ensure completely disarmed too)
	tle_event_free(event);
  EXPECT_EQ(event->state, TLE_SEV_IDLE);
	EXPECT_EQ(rte_errno, 0);
	EXPECT_EQ(evq->nb_free, max_events);
	EXPECT_EQ(evq->nb_armed, 0);
}

TEST_F(tle_event_test, tle_event_alloc_free_active_down)
{
	// basic setup
  event = tle_event_alloc(evq, (void *) &fake_data);
	ASSERT_NE(event, (struct tle_event *) NULL);
	EXPECT_EQ(rte_errno, 0);
	EXPECT_EQ(evq->nb_free, max_events - 1);

  // activate event
	tle_event_active(event, TLE_SEV_DOWN);
  ASSERT_EQ(event->state, TLE_SEV_DOWN);
  EXPECT_EQ(evq->nb_armed, 0);

  // free (ensure completely disarmed too)
	tle_event_free(event);
  EXPECT_EQ(event->state, TLE_SEV_IDLE);
	EXPECT_EQ(rte_errno, 0);
	EXPECT_EQ(evq->nb_free, max_events);
	EXPECT_EQ(evq->nb_armed, 0);
}

TEST_F(tle_event_test, tle_event_alloc_free_max_reached)
{
	uint32_t i;
	struct tle_event *last_event;

	for (i = 1; i <= max_events; i++) {
		event = tle_event_alloc(evq, (void *) &fake_data);
		ASSERT_NE(event, (struct tle_event *) NULL);
		EXPECT_EQ(rte_errno, 0);
		EXPECT_EQ(evq->nb_free, max_events - i);
	}

	last_event = tle_event_alloc(evq, (void *) &fake_data);
	ASSERT_EQ(last_event, (struct tle_event *) NULL);
	ASSERT_EQ(rte_errno, ENOMEM);

	for (i = 1; i <= max_events; i++) {
		tle_event_free(event);
	}
	EXPECT_EQ(evq->nb_free, max_events);
}

TEST_F(tle_event_state_test, tle_state_default)
{
	ASSERT_EQ(event->state, TLE_SEV_IDLE);
}

TEST_P(tle_event_state_active_test, tle_state_active)
{
	auto states = GetParam();

	tle_event_active(event, states.event_state);
	ASSERT_EQ(event->state, states.event_state);
	EXPECT_EQ(rte_errno, 0);
}

INSTANTIATE_TEST_CASE_P(Default, tle_event_state_active_test,
	testing::Values(
	event_state_active{TLE_SEV_IDLE},
	event_state_active{TLE_SEV_UP},
	event_state_active{TLE_SEV_DOWN}
));

TEST_P(tle_event_state_active_twice_test, tle_state_active_twice)
{
	auto states = GetParam();

	tle_event_active(event, states.first_state);
	ASSERT_EQ(event->state, states.first_state);
	EXPECT_EQ(rte_errno, 0);
	tle_event_active(event, states.second_state);
	ASSERT_EQ(event->state, states.result_state);
	EXPECT_EQ(rte_errno, 0);
}

INSTANTIATE_TEST_CASE_P(Default, tle_event_state_active_twice_test,
	testing::Values(
	event_state_active_twice{TLE_SEV_IDLE, TLE_SEV_IDLE, TLE_SEV_IDLE},
	event_state_active_twice{TLE_SEV_IDLE, TLE_SEV_DOWN, TLE_SEV_DOWN},
	event_state_active_twice{TLE_SEV_IDLE, TLE_SEV_UP, TLE_SEV_UP},
	event_state_active_twice{TLE_SEV_DOWN, TLE_SEV_IDLE, TLE_SEV_DOWN},
	event_state_active_twice{TLE_SEV_DOWN, TLE_SEV_UP, TLE_SEV_DOWN},
	event_state_active_twice{TLE_SEV_DOWN, TLE_SEV_DOWN, TLE_SEV_DOWN},
	event_state_active_twice{TLE_SEV_UP, TLE_SEV_IDLE, TLE_SEV_UP},
	event_state_active_twice{TLE_SEV_UP, TLE_SEV_DOWN, TLE_SEV_UP},
	event_state_active_twice{TLE_SEV_UP, TLE_SEV_UP, TLE_SEV_UP}
));

TEST_F(tle_event_state_test, tle_state_raise)
{
	tle_event_raise(event);
	ASSERT_EQ(event->state, TLE_SEV_IDLE);
	EXPECT_EQ(rte_errno, 0);
	tle_event_active(event, TLE_SEV_DOWN);
	ASSERT_EQ(event->state, TLE_SEV_DOWN);
	EXPECT_EQ(rte_errno, 0);
	tle_event_raise(event);
	ASSERT_EQ(event->state, TLE_SEV_UP);
	EXPECT_EQ(rte_errno, 0);
}

TEST_F(tle_event_state_test, tle_state_down)
{
	tle_event_down(event);
	ASSERT_EQ(event->state, TLE_SEV_IDLE);
	EXPECT_EQ(rte_errno, 0);
	tle_event_active(event, TLE_SEV_UP);
	ASSERT_EQ(event->state, TLE_SEV_UP);
	EXPECT_EQ(rte_errno, 0);
	tle_event_down(event);
	ASSERT_EQ(event->state, TLE_SEV_DOWN);
	EXPECT_EQ(rte_errno, 0);
}

TEST_P(tle_event_state_idle_test, tle_state_idle)
{
	auto states = GetParam();

	tle_event_active(event, states.event_state);
	ASSERT_EQ(event->state, states.event_state);
	EXPECT_EQ(rte_errno, 0);
	tle_event_idle(event);
	ASSERT_EQ(event->state, TLE_SEV_IDLE);
	EXPECT_EQ(rte_errno, 0);
}

INSTANTIATE_TEST_CASE_P(Default, tle_event_state_idle_test,
	testing::Values(
	event_state_active{TLE_SEV_IDLE},
	event_state_active{TLE_SEV_UP},
	event_state_active{TLE_SEV_DOWN}
));

TEST_F(tle_event_test, tle_event_get)
{
	uint32_t i;
	const void **evd;

	evd = (const void **) malloc(max_events * sizeof(void *));
	for (i = 1; i <= max_events; i++) {
		event = tle_event_alloc(evq, (void *) &fake_data);
		EXPECT_NE(event, (struct tle_event *) NULL);
		tle_event_active(event, TLE_SEV_UP);
		EXPECT_EQ(event->state, TLE_SEV_UP);
	}
	EXPECT_EQ(evq->nb_free, 0);
	EXPECT_EQ(tle_evq_get(evq, evd, max_events), max_events);
	free(evd);
}

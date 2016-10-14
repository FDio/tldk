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

#ifndef TEST_TLE_UDP_EVENT_H_
#define TEST_TLE_UDP_EVENT_H_

#include <gtest/gtest.h>
#include <rte_errno.h>
#include <tle_ctx.h>
#include <tle_event.h>

struct event_state_active {
	enum tle_ev_state event_state;
};

struct event_state_active_twice {
	enum tle_ev_state first_state;
	enum tle_ev_state second_state;
	enum tle_ev_state result_state;
};

class udp_evq : public ::testing::Test {
protected:

	/* Can parameterize here for
	 * different socket_id and max_events values
	 */
	int32_t socket_id;
	uint32_t max_events;
	struct tle_evq_param evq_params;
	struct tle_evq *evq;

	virtual void SetUp(void)
	{
		socket_id = SOCKET_ID_ANY;
		max_events = 10;
		rte_errno = 0;
		memset(&evq_params, 0, sizeof(struct tle_evq_param));
		evq_params.socket_id = socket_id;
		evq_params.max_events = max_events;
	}

	virtual void TearDown(void)
	{
	}
};

class udp_event : public ::udp_evq {
protected:

	int fake_data;
	struct tle_event *event;

	virtual void SetUp(void)
	{
		udp_evq::SetUp();
		evq = tle_evq_create(&evq_params);
		ASSERT_NE(evq, (struct tle_evq *) NULL);
		EXPECT_EQ(rte_errno, 0);
	}

	virtual void TearDown(void)
	{
		tle_evq_destroy(evq);
	}
};

class udp_event_state : public ::udp_event {
protected:

	virtual void SetUp(void)
	{
		udp_event::SetUp();
		event = tle_event_alloc(evq, (void *) &fake_data);
		ASSERT_NE(event, (struct tle_event *) NULL);
	}

	virtual void TearDown(void)
	{
		tle_event_free(event);
		udp_event::TearDown();
	}
};

struct udp_event_state_active : ::udp_event_state,
testing::WithParamInterface < event_state_active > {
	udp_event_state_active() {}
};

struct udp_event_state_active_twice : ::udp_event_state,
testing::WithParamInterface < event_state_active_twice > {
	udp_event_state_active_twice() {}
};

struct udp_event_state_idle : ::udp_event_state_active {
};

#endif /* TEST_TLE_UDP_EVENT_H_ */

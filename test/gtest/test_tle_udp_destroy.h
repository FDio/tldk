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

#ifndef TEST_TLE_UDP_DESTROY_H_
#define TEST_TLE_UDP_DESTROY_H_

#include <gtest/gtest.h>
#include <rte_errno.h>
#include <tle_udp_impl.h>

class udp_destroy : public ::testing::Test {

protected:
	struct tle_udp_ctx *ctx;
	struct tle_udp_ctx_param prm;

	virtual void SetUp(void)
	{
		rte_errno = 0;
		memset(&prm, 0, sizeof(prm));
		prm.socket_id = SOCKET_ID_ANY;
		prm.max_streams = 0x10;
		prm.max_stream_rbufs = 0x100;
		prm.max_stream_sbufs = 0x100;

		ctx = tle_udp_create(&prm);
		ASSERT_NE(ctx, (void *) NULL);
	}

	virtual void TearDown(void)
	{
	}
};

#endif /* TEST_TLE_UDP_DESTROY_H_ */

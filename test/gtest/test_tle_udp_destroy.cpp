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

#include "test_tle_udp_destroy.h"

TEST(udp_destroy_null, udp_destroy_null)
{
	tle_ctx_destroy(NULL);
	EXPECT_EQ(rte_errno, EINVAL);
}

TEST_F(udp_destroy, udp_destroy_positive)
{
	int rc;
	rte_errno = 0;
	tle_ctx_destroy(ctx);
	ASSERT_EQ(rte_errno, 0);
}

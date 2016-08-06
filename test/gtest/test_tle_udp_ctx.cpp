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

#include "test_tle_udp_ctx.h"

TEST(udp_ctx, udp_create_null)
{
	struct tle_udp_ctx *ctx;

	ctx = tle_udp_create(NULL);
	ASSERT_EQ(ctx, (struct tle_udp_ctx *) NULL);
	ASSERT_EQ(rte_errno, EINVAL);
}

TEST(udp_ctx, udp_create)
{
	struct tle_udp_ctx *ctx;
	struct tle_udp_ctx_param prm;

	memset(&prm, 0, sizeof(prm));
	prm.socket_id = SOCKET_ID_ANY;
	prm.max_streams = 0x10;
	prm.max_stream_rbufs = 0x100;
	prm.max_stream_sbufs = 0x100;

	ctx = tle_udp_create(&prm);
	ASSERT_NE(ctx, (void *)NULL);

	tle_udp_destroy(ctx);
}

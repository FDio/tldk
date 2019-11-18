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

#include "test_tle_ctx.h"

TEST(ctx_create, ctx_create_null)
{
	struct tle_ctx *ctx;

	ctx = tle_ctx_create(NULL);
	ASSERT_EQ(ctx, (struct tle_ctx *) NULL);
	ASSERT_EQ(rte_errno, EINVAL);
}

TEST(ctx_create, create_invalid_socket)
{
	struct tle_ctx *ctx;
	struct tle_ctx_param prm;

	memset(&prm, 0, sizeof(prm));
	prm.socket_id = SOCKET_ID_ANY;
	prm.max_streams = 0x10;
	prm.min_streams = 0x10;
	prm.max_stream_rbufs = 0x100;
	prm.max_stream_sbufs = 0x100;

	ctx = tle_ctx_create(NULL);
	ASSERT_EQ(ctx, (struct tle_ctx *) NULL);
	ASSERT_EQ(rte_errno, EINVAL);
}

TEST(ctx_create, ctx_create_proto_invalid)
{
	struct tle_ctx *ctx;
	struct tle_ctx_param prm;

	memset(&prm, 0, sizeof(prm));
	prm.socket_id = SOCKET_ID_ANY;
	prm.proto = TLE_PROTO_NUM;
	prm.max_streams = 0x10;
	prm.max_stream_rbufs = 0x100;
	prm.max_stream_sbufs = 0x100;

	ctx = tle_ctx_create(NULL);
	ASSERT_EQ(ctx, (struct tle_ctx *) NULL);
	ASSERT_EQ(rte_errno, EINVAL);
}

TEST(ctx_create, ctx_create_proto_not_spec)
{
	struct tle_ctx *ctx;
	struct tle_ctx_param prm;

	memset(&prm, 0, sizeof(prm));
	prm.socket_id = SOCKET_ID_ANY;
	prm.max_streams = 0x10;
	prm.max_stream_rbufs = 0x100;
	prm.max_stream_sbufs = 0x100;

	ctx = tle_ctx_create(&prm);
	ASSERT_NE(ctx, (void *)NULL);

	tle_ctx_destroy(ctx);
}

TEST(ctx_create, ctx_create_proto_udp)
{
	struct tle_ctx *ctx;
	struct tle_ctx_param prm;

	memset(&prm, 0, sizeof(prm));
	prm.socket_id = SOCKET_ID_ANY;
	prm.proto = TLE_PROTO_UDP;
	prm.max_streams = 0x10;
	prm.max_stream_rbufs = 0x100;
	prm.max_stream_sbufs = 0x100;

	ctx = tle_ctx_create(&prm);
	ASSERT_NE(ctx, (void *)NULL);

	tle_ctx_destroy(ctx);
}

TEST(ctx_create, ctx_create_proto_tcp)
{
	struct tle_ctx *ctx;
	struct tle_ctx_param prm;

	memset(&prm, 0, sizeof(prm));
	prm.socket_id = SOCKET_ID_ANY;
	prm.proto = TLE_PROTO_TCP;
	prm.max_streams = 0x10;
	prm.max_stream_rbufs = 0x100;
	prm.max_stream_sbufs = 0x100;

	ctx = tle_ctx_create(&prm);
	ASSERT_NE(ctx, (void *)NULL);

	tle_ctx_destroy(ctx);
}

TEST(ctx_create, ctx_create_invalidate)
{
	struct tle_ctx *ctx;
	struct tle_ctx_param prm;

	memset(&prm, 0, sizeof(prm));
	prm.socket_id = SOCKET_ID_ANY;
	prm.max_streams = 0x10;
	prm.max_stream_rbufs = 0x100;
	prm.max_stream_sbufs = 0x100;

	ctx = tle_ctx_create(&prm);
	ASSERT_NE(ctx, (void *)NULL);

	tle_ctx_invalidate(ctx);

	tle_ctx_destroy(ctx);
}

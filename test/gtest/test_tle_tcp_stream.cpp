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

#include "test_tle_tcp_stream.h"

/* --------- Basic tests for opening / closing  streams, no traffic --------- */

TEST_F(test_tle_tcp_stream, tcp_stream_test_open_nullctx)
{
	stream = tle_tcp_stream_open(nullptr,
			(const struct tle_tcp_stream_param *)&stream_prm);
	EXPECT_EQ(stream, nullptr);
	EXPECT_EQ(rte_errno, EINVAL);

	ret = tle_tcp_stream_close(stream);
	EXPECT_EQ(ret, -EINVAL);
}

TEST_F(test_tle_tcp_stream, tcp_stream_test_open_null_stream_prm)
{
	stream = tle_tcp_stream_open(ctx, nullptr);
	EXPECT_EQ(stream, nullptr);
	EXPECT_EQ(rte_errno, EINVAL);

	ret = tle_tcp_stream_close(stream);
	EXPECT_EQ(ret, -EINVAL);
}

TEST_F(test_tle_tcp_stream, tcp_stream_test_open_close_ipv4)
{
	stream = tle_tcp_stream_open(ctx,
			(const struct tle_tcp_stream_param *)&stream_prm);
	ASSERT_NE(stream, nullptr);

	ret = tle_tcp_stream_close(stream);
	ASSERT_EQ(ret, 0);
}

TEST_F(test_tle_tcp_stream, tcp_stream_test_open_close_ipv6)
{
	stream6 = tle_tcp_stream_open(ctx,
			(const struct tle_tcp_stream_param *)&stream_prm6);
	ASSERT_NE(stream, nullptr);

	ret = tle_tcp_stream_close(stream6);
	ASSERT_EQ(ret, 0);
}

TEST_F(test_tle_tcp_stream, tcp_stream_test_open_close_open_close)
{
	stream = tle_tcp_stream_open(ctx,
			(const struct tle_tcp_stream_param *)&stream_prm);
	ASSERT_NE(stream, nullptr);

	ret = tle_tcp_stream_close(stream);
	ASSERT_EQ(ret, 0);

	stream = tle_tcp_stream_open(ctx,
			(const struct tle_tcp_stream_param*)&stream_prm);
	ASSERT_NE(stream, nullptr);

	ret = tle_tcp_stream_close(stream);
	ASSERT_EQ(ret, 0);
}

TEST_F(test_tle_tcp_stream, tcp_stream_test_open_duplicate_ipv4)
{
	struct tle_stream *stream_dup;

	stream = tle_tcp_stream_open(ctx,
			(const struct tle_tcp_stream_param *)&stream_prm);
	ASSERT_NE(stream, nullptr);

	stream_dup = tle_tcp_stream_open(ctx,
			(const struct tle_tcp_stream_param*)&stream_prm);
	ASSERT_EQ(stream_dup, nullptr);
	ASSERT_EQ(rte_errno, EADDRINUSE);

	ret = tle_tcp_stream_close(stream);
	ASSERT_EQ(ret, 0);
}

TEST_F(test_tle_tcp_stream, tcp_stream_test_open_duplicate_ipv6)
{
	struct tle_stream *stream_dup;

	stream6 = tle_tcp_stream_open(ctx,
			(const struct tle_tcp_stream_param *)&stream_prm6);
	ASSERT_NE(stream, nullptr);

	stream_dup = tle_tcp_stream_open(ctx,
			(const struct tle_tcp_stream_param*)&stream_prm6);
	ASSERT_EQ(stream_dup, nullptr);
	ASSERT_EQ(rte_errno, EADDRINUSE);

	ret = tle_tcp_stream_close(stream6);
	ASSERT_EQ(ret, 0);
}

TEST_F(test_tle_tcp_stream, tcp_stream_test_close_null)
{
	ret = tle_tcp_stream_close(nullptr);
	EXPECT_EQ(ret, -EINVAL);
}

TEST_F(test_tle_tcp_stream, tcp_stream_test_closed_already)
{
	stream = tle_tcp_stream_open(ctx,
			(const struct tle_tcp_stream_param *)&stream_prm);
	ASSERT_NE(stream, nullptr);

	ret = tle_tcp_stream_close(stream);
	EXPECT_EQ(ret, 0);

	ret = tle_tcp_stream_close(stream);
	EXPECT_NE(ret, 0);
}

/* --------- Tests for get_addr call  --------- */

TEST_F(test_tle_tcp_stream_ops, tcp_stream_get_addr_null_stream)
{
	struct tle_tcp_stream_addr addr;

	ret = tle_tcp_stream_get_addr(nullptr, &addr);
	EXPECT_EQ(ret, -EINVAL);
}

TEST_F(test_tle_tcp_stream_ops, tcp_stream_get_addr_null_addr)
{
	ret = tle_tcp_stream_get_addr(stream, NULL);
	EXPECT_EQ(ret, -EINVAL);
}

TEST_F(test_tle_tcp_stream_ops, tcp_stream_get_addr_ipv4)
{
	struct tle_tcp_stream_addr addr;

	memset(&addr, 0, sizeof(addr));
	ret = tle_tcp_stream_get_addr(stream, &addr);
	ASSERT_EQ(ret, 0);

	ret = memcmp(&addr, &stream_prm.addr, sizeof(tle_tcp_stream_addr));
	ASSERT_EQ(ret, 0);
}

TEST_F(test_tle_tcp_stream_ops, tcp_stream_get_addr_ipv6)
{
	struct tle_tcp_stream_addr addr;

	memset(&addr, 0, sizeof(addr));
	ret = tle_tcp_stream_get_addr(stream6, &addr);
	ASSERT_EQ(ret, 0);

	ret = memcmp(&addr, &stream_prm6.addr, sizeof(tle_tcp_stream_addr));
	ASSERT_EQ(ret, 0);
}

/* --------- Basic tests for listen call, no incoming connections  --------- */

TEST_F(test_tle_tcp_stream_ops, tcp_stream_listen_null_stream)
{
	ret = tle_tcp_stream_listen(nullptr);
	EXPECT_EQ(ret, -EINVAL);
}

TEST_F(test_tle_tcp_stream_ops, tcp_stream_listen_ipv4)
{
	ret = tle_tcp_stream_listen(stream);
	ASSERT_EQ(ret, 0);

	ret = tle_tcp_stream_close(stream);
	ASSERT_EQ(ret, 0);
}

TEST_F(test_tle_tcp_stream_ops, tcp_stream_listen_ipv6)
{
	ret = tle_tcp_stream_listen(stream6);
	ASSERT_EQ(ret, 0);

	ret = tle_tcp_stream_close(stream6);
	ASSERT_EQ(ret, 0);
}

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

#include "test_tle_udp_stream.h"

TEST_F(test_tle_udp_stream, stream_test_open)
{
	stream = tle_udp_stream_open(ctx,
			(const struct tle_udp_stream_param *)&stream_prm);
	EXPECT_NE(stream, nullptr);
	ret = tle_udp_stream_close(stream);

	EXPECT_EQ(ret, 0);
}

TEST_F(test_tle_udp_stream, stream_test_open_nullctx)
{
	stream = tle_udp_stream_open(nullptr,
			(const struct tle_udp_stream_param *)&stream_prm);
	EXPECT_EQ(stream, nullptr);
	EXPECT_EQ(rte_errno, EINVAL);

	ret = tle_udp_stream_close(stream);
	EXPECT_EQ(ret, -EINVAL);
}

TEST_F(test_tle_udp_stream, stream_test_open_null_stream_prm)
{
	stream = tle_udp_stream_open(ctx, nullptr);
	EXPECT_EQ(stream, nullptr);
	EXPECT_EQ(rte_errno, EINVAL);

	ret = tle_udp_stream_close(stream);
	EXPECT_EQ(ret, -EINVAL);
}


TEST_F(test_tle_udp_stream, stream_test_open_close_open_close)
{
	stream = tle_udp_stream_open(ctx,
			(const struct tle_udp_stream_param *)&stream_prm);
	EXPECT_NE(stream, nullptr);

	ret = tle_udp_stream_close(stream);
	EXPECT_EQ(ret, 0);

	stream = tle_udp_stream_open(ctx,
			(const struct tle_udp_stream_param*)&stream_prm);
	EXPECT_NE(stream, nullptr);

	ret = tle_udp_stream_close(stream);
	EXPECT_EQ(ret, 0);
}

TEST_F(test_tle_udp_stream, stream_test_close)
{
	stream = tle_udp_stream_open(ctx,
			(const struct tle_udp_stream_param *)&stream_prm);
	EXPECT_NE(stream, nullptr);

	ret = tle_udp_stream_close(stream);
	EXPECT_EQ(ret, 0);
}

TEST_F(test_tle_udp_stream, stream_test_close_null)
{
	ret = tle_udp_stream_close(nullptr);
	EXPECT_EQ(ret, -EINVAL);
}


TEST_F(test_tle_udp_stream, stream_test_close_already)
{
	stream = tle_udp_stream_open(ctx,
			(const struct tle_udp_stream_param *)&stream_prm);
	EXPECT_NE(stream, nullptr);

	ret = tle_udp_stream_close(stream);
	EXPECT_EQ(ret, 0);

	ret = tle_udp_stream_close(stream);
	EXPECT_NE(ret, 0);
}

TEST_F(test_tle_udp_stream, stream_get_param)
{
	struct tle_udp_stream_param prm;

	stream = tle_udp_stream_open(ctx,
			(const struct tle_udp_stream_param *)&stream_prm);
	EXPECT_NE(stream, nullptr);

	ret = tle_udp_stream_get_param(stream,&prm);
	EXPECT_EQ(ret, 0);
}

TEST_F(test_tle_udp_stream, stream_get_param_streamnull)
{
	struct tle_udp_stream_param prm;

	stream = tle_udp_stream_open(ctx,
			(const struct tle_udp_stream_param *)&stream_prm);
	EXPECT_NE(stream, nullptr);

	ret = tle_udp_stream_get_param(nullptr, &prm);
	EXPECT_EQ(ret, -EINVAL);
}

TEST_F(test_tle_udp_stream, stream_get_param_prmnull)
{
	struct tle_udp_stream_param prm;

	stream = tle_udp_stream_open(ctx,
			(const struct tle_udp_stream_param *)&stream_prm);
	EXPECT_NE(stream, nullptr);

	ret = tle_udp_stream_get_param(stream, nullptr);
	EXPECT_EQ(ret, -EINVAL);
}




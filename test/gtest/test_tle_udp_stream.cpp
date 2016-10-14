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
#include <arpa/inet.h>

TEST_F(test_tle_udp_stream, stream_test_open)
{
	stream = tle_udp_stream_open(ctx,
			(const struct tle_udp_stream_param *)&stream_prm);
	EXPECT_NE(stream, nullptr);
	streams.push_back(stream);
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

	streams.push_back(stream);
}

TEST_F(test_tle_udp_stream, stream_test_open_duplicate)
{
	stream = tle_udp_stream_open(ctx,
			(const struct tle_udp_stream_param *)&stream_prm);
	EXPECT_NE(stream, nullptr);
	streams.push_back(stream);

	stream = tle_udp_stream_open(ctx,
			(const struct tle_udp_stream_param *)&stream_prm);
	EXPECT_EQ(stream, nullptr);
	EXPECT_EQ(rte_errno, EEXIST);
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
	EXPECT_EQ(ret, -EINVAL);
}

TEST_F(test_tle_udp_stream, stream_get_param)
{
	struct tle_udp_stream_param prm;

	stream = tle_udp_stream_open(ctx,
			(const struct tle_udp_stream_param *)&stream_prm);
	EXPECT_NE(stream, nullptr);
	streams.push_back(stream);

	ret = tle_udp_stream_get_param(stream,&prm);
	EXPECT_EQ(ret, 0);
}

TEST_F(test_tle_udp_stream, stream_get_param_streamnull)
{
	struct tle_udp_stream_param prm;

	stream = tle_udp_stream_open(ctx,
			(const struct tle_udp_stream_param *)&stream_prm);
	EXPECT_NE(stream, nullptr);
	streams.push_back(stream);

	ret = tle_udp_stream_get_param(nullptr, &prm);
	EXPECT_EQ(ret, -EINVAL);
}

TEST_F(test_tle_udp_stream, stream_get_param_prmnull)
{
	struct tle_udp_stream_param prm;

	stream = tle_udp_stream_open(ctx,
			(const struct tle_udp_stream_param *)&stream_prm);
	EXPECT_NE(stream, nullptr);
	streams.push_back(stream);

	ret = tle_udp_stream_get_param(stream, nullptr);
	EXPECT_EQ(ret, -EINVAL);
}

TEST_F(test_tle_udp_stream_max, stream_test_open_max)
{
	int i, j, cnt;
	struct in_addr src_s;
	struct in_addr dst_s;
	int dst_port = 32678;
	struct sockaddr_in *l_ipv4;
	struct sockaddr_in *r_ipv4;

	/* Set fields that will not change in sockaddr structures */
	inet_pton(AF_INET, base_l_ipv4, &src_s);
	l_ipv4 = (struct sockaddr_in *) &stream_prm.local_addr;
	l_ipv4->sin_family = AF_INET;
	l_ipv4->sin_port = htons(0);

	inet_pton(AF_INET, base_r_ipv4, &dst_s);
	r_ipv4 = (struct sockaddr_in *) &stream_prm.remote_addr;
	r_ipv4->sin_family = AF_INET;

	for(i = 0, cnt = 0; i < devs.size(); i++) {
		/* Get base IPv4 address and increment it if needed for
		 * stream source address;
		 * Incrementing only highest octet */

		l_ipv4->sin_addr.s_addr = src_s.s_addr + i;

		for(j = 0; j < nb_streams; j++, cnt++) {
			/* Get base IPv4 address and increment it if needed for
			 * stream destination  address */
			r_ipv4->sin_port = htons(dst_port + j);
			r_ipv4->sin_addr.s_addr = htonl(ntohl(dst_s.s_addr) + j);

			stream = tle_udp_stream_open(ctx,
					(const struct tle_udp_stream_param *)&stream_prm);

			if (cnt < MAX_STREAMS) {
				EXPECT_EQ(rte_errno, 0);
				ASSERT_NE(stream, nullptr);
				streams.push_back(stream);
			} else if (cnt >= MAX_STREAMS) {
				EXPECT_EQ(stream, nullptr);
				EXPECT_EQ(rte_errno, ENFILE);
			}
		}
	}
}

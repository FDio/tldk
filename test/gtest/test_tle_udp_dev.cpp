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

#include "test_tle_udp_dev.h"

TEST_F(udp_dev, udp_dev_add_null_ctx)
{
	dev = tle_udp_add_dev(NULL, &dev_prm);
	EXPECT_EQ(dev, (void *) NULL);
	EXPECT_EQ(rte_errno, EINVAL);
}

TEST_F(udp_dev, udp_dev_add_null_dev_prm)
{
	dev = tle_udp_add_dev(ctx, NULL);
	EXPECT_EQ(dev, (void *) NULL);
	EXPECT_EQ(rte_errno, EINVAL);
}

TEST_F(udp_dev, udp_dev_add_no_addr)
{
	memset(&(dev_prm).local_addr4, 0, sizeof(struct in_addr));
	memset(&(dev_prm).local_addr6, 0, sizeof(struct in6_addr));
	dev = tle_udp_add_dev(ctx, &dev_prm);
	EXPECT_EQ(dev, (void *) NULL);
	EXPECT_EQ(rte_errno, EINVAL);
}

TEST_F(udp_dev, udp_dev_add_anyaddr)
{
	inet_pton(AF_INET, "0.0.0.0", &(dev_prm).local_addr4);
	inet_pton(AF_INET6, "::0", &(dev_prm).local_addr6);
	dev = tle_udp_add_dev(ctx, &dev_prm);
	EXPECT_EQ(dev, (void *) NULL);
	EXPECT_EQ(rte_errno, EINVAL);
}

TEST_F(udp_dev, udp_dev_add_only_ipv4)
{
	memset(&(dev_prm).local_addr6, 0, sizeof(struct in6_addr));
	dev = tle_udp_add_dev(ctx, &dev_prm);
	ASSERT_NE(dev, (void *) NULL);
	EXPECT_EQ(rte_errno, 0);
}

TEST_F(udp_dev, udp_dev_add_only_ipv6)
{
	memset(&(dev_prm).local_addr4, 0, sizeof(struct in_addr));
	dev = tle_udp_add_dev(ctx, &dev_prm);
	ASSERT_NE(dev, (void *) NULL);
	EXPECT_EQ(rte_errno, 0);
}

TEST_F(udp_dev, udp_dev_add_nonexist_ipv4)
{
	memset(&(dev_prm).local_addr4, 0, sizeof(struct in_addr));
	inet_pton(AF_INET, "10.0.0.1", &(dev_prm).local_addr4);
	dev = tle_udp_add_dev(ctx, &dev_prm);
	ASSERT_NE(dev, (void *) NULL);
	EXPECT_EQ(rte_errno, 0);
}

TEST_F(udp_dev, udp_dev_add_positive)
{
	dev = tle_udp_add_dev(ctx, &dev_prm);
	ASSERT_NE(dev, (void *) NULL);
	EXPECT_EQ(rte_errno, 0);
	dev = tle_udp_add_dev(ctx, &dev_prm);
	ASSERT_NE(dev, (void *) NULL);
	EXPECT_EQ(rte_errno, 0);
}

TEST_F(udp_dev, udp_dev_del_positive)
{
	dev = tle_udp_add_dev(ctx, &dev_prm);
	ASSERT_NE(dev, (void *) NULL);
	EXPECT_EQ(rte_errno, 0);
	ASSERT_EQ(tle_udp_del_dev(dev), 0);
	EXPECT_EQ(rte_errno, 0);
}

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

#ifndef TEST_TLE_UDP_DEV_H_
#define TEST_TLE_UDP_DEV_H_

#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <rte_errno.h>
#include <tle_udp_impl.h>

#define RX_NO_OFFLOAD 0
#define TX_NO_OFFLOAD 0

class udp_dev : public ::testing::Test {

public:
	struct tle_udp_ctx *ctx;
	struct tle_udp_dev *dev;
	struct tle_udp_ctx_param prm;
	struct tle_udp_dev_param dev_prm;

	virtual void SetUp(void)
	{
		rte_errno = 0;
		memset(&prm, 0, sizeof(prm));
		prm.socket_id = SOCKET_ID_ANY;
		prm.max_streams = 0x1;
		prm.max_stream_rbufs = 0x1;
		prm.max_stream_sbufs = 0x1;

		memset(&dev_prm, 0, sizeof(dev_prm));

		/* Offload irrelevant in these tests, set to 0 */
		dev_prm.rx_offload = RX_NO_OFFLOAD;
		dev_prm.tx_offload = TX_NO_OFFLOAD;
		inet_pton(AF_INET, "192.168.2.1", &(dev_prm).local_addr4);
		inet_pton(AF_INET6, "fe80::21e:67ff:fec2:2568",
				&(dev_prm).local_addr6);

		ctx = tle_udp_create(&prm);
		ASSERT_NE(ctx, (void *) NULL);
	}

	virtual void TearDown(void)
	{
		tle_udp_destroy(ctx);
	}
};

#endif /* TEST_TLE_UDP_DEV_H_ */

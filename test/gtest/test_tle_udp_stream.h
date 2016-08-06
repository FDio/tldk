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

#ifndef TEST_TLE_UDP_STREAM_H_
#define TEST_TLE_UDP_STREAM_H_
#include <iostream>
#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <rte_errno.h>

#include <tle_udp_impl.h>
#include <tle_event.h>

struct tle_udp_ctx_param ctx_prm_tmpl = {
	.socket_id = SOCKET_ID_ANY,
	.max_streams = 0x10,
	.max_stream_rbufs = 0x100,
	.max_stream_sbufs = 0x100
};

struct tle_udp_dev_param dev_prm_tmpl = {
	.rx_offload = 0x100,
	.tx_offload = 0x100
};

class test_tle_udp_stream: public ::testing::Test {
public:
	void setup_dev_prm(struct tle_udp_dev_param *,
			char const *, char const *);
	struct tle_udp_ctx *setup_ctx(struct tle_udp_ctx_param *prm);
	struct tle_udp_dev *setup_dev(struct tle_udp_ctx *ctx,
			struct tle_udp_dev_param *dev_prm);
	struct tle_evq *setup_event();

	virtual void SetUp(void)
	{
		char const *ipv4_laddr = "192.168.0.1";
		char const *ipv4_raddr = "192.168.0.2";
		char const *ipv6 = "fe80::21e:67ff:fec2:2568";

		ctx = nullptr;
		dev = nullptr;
		stream = nullptr;
		/* Setup Context */
		ctx = setup_ctx(&ctx_prm_tmpl);
		/* Setup Dev */
		memset(&dev_prm, 0, sizeof(dev_prm));
		setup_dev_prm(&dev_prm, ipv4_laddr, ipv6);
		dev = setup_dev(ctx, &dev_prm);

		/* Stream Param & Event param */
		memset(&stream_prm, 0, sizeof(struct tle_udp_stream_param));
		inet_pton(AF_INET, ipv4_laddr, &stream_prm.local_addr);
		inet_pton(AF_INET, ipv4_raddr, &stream_prm.remote_addr);
		stream_prm.local_addr.ss_family = AF_INET;
		stream_prm.remote_addr.ss_family = AF_INET;
		stream_prm.recv_ev = tle_event_alloc(setup_event(), nullptr);
		stream_prm.send_ev = tle_event_alloc(setup_event(), nullptr);
	}

	virtual void TearDown(void)
	{
		ret = 0;
		tle_udp_stream_close(stream);
		tle_udp_del_dev(dev);
		tle_udp_destroy(ctx);
	}

	int ret;
	struct tle_udp_ctx *ctx;
	struct tle_udp_dev *dev;
	struct tle_udp_stream *stream;

	struct tle_udp_ctx_param ctx_prm;
	struct tle_udp_dev_param dev_prm;
	struct tle_udp_stream_param stream_prm;
};

struct tle_evq *test_tle_udp_stream::setup_event() {
	int32_t socket_id;
	uint32_t max_events;
	struct tle_evq_param evq_params;
	struct tle_evq *evq;

	socket_id = SOCKET_ID_ANY;
	max_events = 10;
	rte_errno = 0;
	memset(&evq_params, 0, sizeof(struct tle_evq_param));
	evq_params.socket_id = socket_id;
	evq_params.max_events = max_events;
	evq = tle_evq_create(&evq_params);
	return evq;
}

struct tle_udp_ctx
*test_tle_udp_stream::setup_ctx(struct tle_udp_ctx_param *prm) {
	struct tle_udp_ctx *ctx;

	ctx = tle_udp_create(prm);

	return ctx;
}

struct tle_udp_dev
*test_tle_udp_stream::setup_dev(struct tle_udp_ctx *ctx,
		struct tle_udp_dev_param *dev_prm) {

	struct tle_udp_dev *dev;

	dev = tle_udp_add_dev(ctx, dev_prm);

	return dev;
}

void test_tle_udp_stream::setup_dev_prm(struct tle_udp_dev_param *dev_prm,
		char const *ipv4, char const *ipv6) {

	inet_pton(AF_INET, ipv4, &dev_prm->local_addr4);
	inet_pton(AF_INET6, ipv6, &dev_prm->local_addr6);

}

#endif /* TEST_TLE_UDP_STREAM_H_ */

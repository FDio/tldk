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
#include <algorithm>
#include <string>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <rte_errno.h>

#include <tle_udp.h>
#include <tle_event.h>

#include "test_common.h"

#define MAX_STREAMS 0xFFFF
#define MAX_STREAM_RBUFS 0x100
#define MAX_STREAM_SBUFS 0x100
#define RX_OFFLOAD 0x100
#define TX_OFFLOAD 0x100

using namespace std;

struct tle_ctx_param ctx_prm_tmpl = {
	.socket_id = SOCKET_ID_ANY,
	.proto = TLE_PROTO_UDP,
	.max_streams = MAX_STREAMS,
	.max_stream_rbufs = MAX_STREAM_RBUFS,
	.max_stream_sbufs = MAX_STREAM_SBUFS
};

struct tle_dev_param dev_prm_tmpl = {
	.rx_offload = RX_OFFLOAD,
	.tx_offload = TX_OFFLOAD
};

class test_tle_udp_stream: public ::testing::Test {
public:
	void setup_dev_prm(struct tle_dev_param *,
			char const *, char const *);
	struct tle_ctx *setup_ctx(struct tle_ctx_param *prm);
	struct tle_dev *setup_dev(struct tle_ctx *ctx,
			struct tle_dev_param *dev_prm);
	struct tle_evq *setup_event();

	virtual void SetUp(void)
	{
		char const *ipv4_laddr = "192.0.0.1";
		char const *ipv4_raddr = "10.0.0.1";
		char const *ipv6 = "fe80::21e:67ff:fec2:2568";
		struct tle_ctx_param cprm;
		port = 10000;

		ctx = nullptr;
		dev = nullptr;
		stream = nullptr;
		/* Setup Context */
		cprm = ctx_prm_tmpl;
		cprm.max_streams = 0xA;
		cprm.lookup4 = dummy_lookup4;
		cprm.lookup6 = dummy_lookup6;
		ctx = setup_ctx(&cprm);
		ASSERT_NE(ctx, nullptr);

		/* Setup Dev */
		memset(&dev_prm, 0, sizeof(dev_prm));
		setup_dev_prm(&dev_prm, ipv4_laddr, ipv6);
		dev = setup_dev(ctx, &dev_prm);
		ASSERT_NE(dev, nullptr);

		/* Stream Param & Event param */
		memset(&stream_prm, 0, sizeof(struct tle_udp_stream_param));

		ip4_addr = (struct sockaddr_in *) &stream_prm.local_addr;
		ip4_addr->sin_family = AF_INET;
		ip4_addr->sin_port = htons(port);
		ip4_addr->sin_addr.s_addr = inet_addr(ipv4_laddr);

		ip4_addr = (struct sockaddr_in *) &stream_prm.remote_addr;
		ip4_addr->sin_family = AF_INET;
		ip4_addr->sin_port = htons(port);
		ip4_addr->sin_addr.s_addr = inet_addr(ipv4_raddr);

		stream_prm.recv_ev = tle_event_alloc(setup_event(), nullptr);
		stream_prm.send_ev = tle_event_alloc(setup_event(), nullptr);
	}

	virtual void TearDown(void)
	{
		ret = 0;
		for (auto s : streams)
			tle_udp_stream_close(s);

		tle_del_dev(dev);
		tle_ctx_destroy(ctx);
	}

	int ret;
	int port;
	struct tle_ctx *ctx;
	struct tle_dev *dev;
	struct tle_stream *stream;
	struct tle_ctx_param ctx_prm;
	struct tle_dev_param dev_prm;
	struct tle_udp_stream_param stream_prm;
	struct sockaddr_in *ip4_addr;

	vector<tle_stream *> streams;
};

struct tle_evq *
test_tle_udp_stream::setup_event()
{
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

struct tle_ctx
*test_tle_udp_stream::setup_ctx(struct tle_ctx_param *prm)
{
	struct tle_ctx *ctx;

	ctx = tle_ctx_create(prm);

	return ctx;
}

struct tle_dev
*test_tle_udp_stream::setup_dev(struct tle_ctx *ctx,
	struct tle_dev_param *dev_prm)
{
	struct tle_dev *dev;

	dev = tle_add_dev(ctx, dev_prm);

	return dev;
}

void
test_tle_udp_stream::setup_dev_prm(struct tle_dev_param *dev_prm,
	char const *ipv4, char const *ipv6)
{
	inet_pton(AF_INET, ipv4, &dev_prm->local_addr4);
	inet_pton(AF_INET6, ipv6, &dev_prm->local_addr6);

}

/* Fixture for max number of streams on single ctx + multiple devices */
class test_tle_udp_stream_max: public ::test_tle_udp_stream {
public:

	virtual void SetUp(void)
	{
		/* Create enough devices and streams to exceed
		 * MAX_STREAMS on ctx
		 */
		nb_devs = 10;
		nb_streams = 6554;

		in_addr_t src;
		string ssrc;

		memset(&ctx_prm, 0, sizeof(ctx_prm));
		ctx_prm = ctx_prm_tmpl;
		ctx_prm.lookup4 = dummy_lookup4;
		ctx_prm.lookup6 = dummy_lookup6;
		ctx = setup_ctx(&ctx_prm);
		ASSERT_NE(ctx, (void *)NULL);

		memset(&dev_prm, 0, sizeof(dev_prm));
		setup_dev_prm(&dev_prm, base_l_ipv4, base_l_ipv6);

		memset(&stream_prm, 0, sizeof(struct tle_udp_stream_param));
		stream_prm.recv_ev = tle_event_alloc(setup_event(), nullptr);
		stream_prm.send_ev = tle_event_alloc(setup_event(), nullptr);

		for (i = 0; i < nb_devs; i++) {
			ssrc = inet_ntoa(dev_prm.local_addr4);

			dev = setup_dev(ctx, &dev_prm);
			ASSERT_NE(dev, (void *)NULL);
			devs.push_back(dev);

			/* Modify base IP addresses for next loops */
			src = dev_prm.local_addr4.s_addr;
			src += 1;
			dev_prm.local_addr4.s_addr = src;
		}
	}

	virtual void TearDown(void)
	{
		for (auto s : streams)
			tle_udp_stream_close(s);

		for (auto d : devs)
			tle_del_dev(d);

		tle_ctx_destroy(ctx);
	}

	int i;
	int nb_devs;
	int nb_streams;
	char const *base_l_ipv4 = "10.0.0.1";
	char const *base_r_ipv4 = "190.0.0.1";
	char const *base_l_ipv6 = "2000::1";
	vector<tle_dev *> devs;
	vector<tle_stream *> streams;
};

#endif /* TEST_TLE_UDP_STREAM_H_ */

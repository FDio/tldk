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

#ifndef TEST_TLE_TCP_STREAM_H_
#define TEST_TLE_TCP_STREAM_H_

#include <iostream>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <sys/socket.h>
#include <netdb.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <rte_errno.h>

#include <tle_event.h>
#include <tle_ctx.h>
#include <tle_tcp.h>

#include "test_common.h"

#define MAX_STREAMS          0x100
#define MAX_STREAM_RBUFS     0x100
#define MAX_STREAM_SBUFS     0x100
#define RX_NO_OFFLOAD        0x0
#define TX_NO_OFFLOAD        0x0

static struct tle_ctx_param ctx_prm_tmpl = {
	.socket_id = SOCKET_ID_ANY,
	.proto = TLE_PROTO_TCP,
	.max_streams = MAX_STREAMS,
	.min_streams = MAX_STREAMS,
	.delta_streams = 0,
	.max_stream_rbufs = MAX_STREAM_RBUFS,
	.max_stream_sbufs = MAX_STREAM_SBUFS,
};

static struct tle_dev_param dev_prm_tmpl = {
	.rx_offload = RX_NO_OFFLOAD,
	.tx_offload = TX_NO_OFFLOAD
};

class tcp_stream_base: public ::testing::Test {

public:
	struct tle_ctx *setup_ctx(struct tle_ctx_param *prm);
	struct tle_dev *setup_dev(struct tle_ctx *ctx,
				struct tle_dev_param *dev_prm);
	void setup_dev_prm(struct tle_dev_param *dev_prm,
			char const *ipv4, char const *ipv6);
	int setup_stream_prm(struct tle_tcp_stream_param *stream_prm,
			char const *l_ip, char const *r_ip,
			int l_port, int r_port);
	struct tle_evq *setup_event();
};

struct tle_evq
*tcp_stream_base::setup_event()
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
*tcp_stream_base::setup_ctx(struct tle_ctx_param *prm)
{
	struct tle_ctx *ctx;

	prm->lookup4 = dummy_lookup4;
	prm->lookup6 = dummy_lookup6;

	ctx = tle_ctx_create(prm);

	return ctx;
}

struct tle_dev
*tcp_stream_base::setup_dev(struct tle_ctx *ctx, struct tle_dev_param *dev_prm)
{
	struct tle_dev *dev;

	dev = tle_add_dev(ctx, dev_prm);

	return dev;
}

void
tcp_stream_base::setup_dev_prm(struct tle_dev_param *dev_prm, char const *ipv4,
	char const *ipv6)
{
	inet_pton(AF_INET, ipv4, &dev_prm->local_addr4);
	inet_pton(AF_INET6, ipv6, &dev_prm->local_addr6);
}

int
tcp_stream_base::setup_stream_prm(struct tle_tcp_stream_param *stream_prm,
	char const *l_ip, char const *r_ip, int l_port, int r_port)
{
	int32_t ret;
	struct sockaddr_in *ip4_addr;
	struct sockaddr_in6 *ip6_addr;
	struct addrinfo hint, *res = NULL;
	struct tle_tcp_stream_cfg stream_cfg;

	memset(&hint, '\0', sizeof(hint));
	memset(&stream_cfg, 0, sizeof(stream_cfg));

	ret = getaddrinfo(l_ip, NULL, &hint, &res);
	if (ret != 0)
		return -EINVAL;

	if (res->ai_family == AF_INET) {
		ip4_addr = (struct sockaddr_in *) &stream_prm->addr.local;
		ip4_addr->sin_family = AF_INET;
		ip4_addr->sin_port = htons(l_port);
		ip4_addr->sin_addr.s_addr = inet_addr(l_ip);
	} else if (res->ai_family == AF_INET6) {
		ip6_addr = (struct sockaddr_in6 *) &stream_prm->addr.local;
		ip6_addr->sin6_family = AF_INET6;
		inet_pton(AF_INET6, l_ip, &ip6_addr->sin6_addr);
		ip6_addr->sin6_port = htons(l_port);
	} else {
		freeaddrinfo(res);
		return -EINVAL;
	}
	freeaddrinfo(res);

	memset(&hint, '\0', sizeof(hint));
	ret = getaddrinfo(r_ip, NULL, &hint, &res);
	if (ret != 0)
		return -EINVAL;

	if (res->ai_family == AF_INET) {
		ip4_addr = (struct sockaddr_in *) &stream_prm->addr.remote;
		ip4_addr->sin_family = AF_INET;
		ip4_addr->sin_port = htons(r_port);
		ip4_addr->sin_addr.s_addr = inet_addr(r_ip);
	} else if (res->ai_family == AF_INET6) {
		ip6_addr = (struct sockaddr_in6 *) &stream_prm->addr.remote;
		ip6_addr->sin6_family = AF_INET6;
		inet_pton(AF_INET6, r_ip, &ip6_addr->sin6_addr);
		ip6_addr->sin6_port = htons(r_port);
	} else {
		freeaddrinfo(res);
		return -EINVAL;
	}
	freeaddrinfo(res);

	stream_prm->cfg = stream_cfg;

	return 0;
}

class test_tle_tcp_stream: public ::tcp_stream_base {
protected:
	virtual void SetUp(void)
	{
		ipv4_laddr = "192.0.0.1";
		ipv4_raddr = "192.0.0.2";
		ipv6_laddr = "2001::1000";
		ipv6_raddr = "2001::2000";
		l_port = 10000;
		r_port = 10000;

		memset(&ctx_prm, 0, sizeof(ctx_prm));
		memset(&dev_prm, 0, sizeof(dev_prm));
		memset(&stream_prm, 0, sizeof(stream_prm));
		memset(&stream_prm6, 0, sizeof(stream_prm6));

		ctx_prm = ctx_prm_tmpl;
		dev_prm = dev_prm_tmpl;
		setup_dev_prm(&dev_prm, ipv4_laddr, ipv6_laddr);
		ret = setup_stream_prm(&stream_prm, ipv4_laddr, ipv4_raddr,
			l_port, r_port);
		ASSERT_EQ(ret, 0);
		setup_stream_prm(&stream_prm6, ipv6_laddr, ipv6_raddr, l_port,
			r_port);
		ASSERT_EQ(ret, 0);

		ctx = setup_ctx(&ctx_prm);
		ASSERT_NE(ctx, (void *) NULL);
		dev = setup_dev(ctx, &dev_prm);
		ASSERT_NE(dev, (void *) NULL);
	}

	virtual void TearDown(void)
	{
		ret = 0;
		tle_del_dev(dev);
		tle_ctx_destroy(ctx);
	}

	int ret;
	struct tle_ctx *ctx;
	struct tle_dev *dev;
	struct tle_stream *stream;
	struct tle_stream *stream6;

	struct tle_ctx_param ctx_prm;
	struct tle_dev_param dev_prm;
	struct tle_tcp_stream_param stream_prm;
	struct tle_tcp_stream_param stream_prm6;

	int l_port, r_port;
	char const *ipv4_laddr;
	char const *ipv4_raddr;
	char const *ipv6_laddr;
	char const *ipv6_raddr;
};

class test_tle_tcp_stream_ops: public ::test_tle_tcp_stream {
public:
	virtual void SetUp(void)
	{
		test_tle_tcp_stream::SetUp();
		stream = tle_tcp_stream_open(ctx,
			(const struct tle_tcp_stream_param *)&stream_prm);
		stream6 = tle_tcp_stream_open(ctx,
			(const struct tle_tcp_stream_param *)&stream_prm6);
	}

	virtual void TearDown(void)
	{
		tle_tcp_stream_close(stream6);
		tle_tcp_stream_close(stream);
		test_tle_tcp_stream::TearDown();
	}
};

#endif /* TEST_TLE_TCP_STREAM_H_ */

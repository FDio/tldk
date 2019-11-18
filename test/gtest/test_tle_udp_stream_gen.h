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

#ifndef TEST_TLE_UDP_STREAM_GEN_H_
#define TEST_TLE_UDP_STREAM_GEN_H_

#include <sys/types.h>

#include <stdio.h>
#include <map>
#include <string>
#include <algorithm>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <sys/socket.h>
#include <netdb.h>
#include <gtest/gtest.h>

#include <rte_version.h>

#include <tle_udp.h>
#include <tle_event.h>

#include "test_common.h"

#define RX_NO_OFFLOAD 0
#define TX_NO_OFFLOAD 0
#define CTX_MAX_RBUFS 0x100
#define CTX_MAX_SBUFS 0x100

#define RX_PCAP "rx_pcap.cap"
#define TX_PCAP "tx_pcap.cap"

/*
 * Check DPDK version:
 * Previous "eth_pcap" was changed to "net_pcap" after DPDK 16.07.
 * Use correct vdev name depending on version.
 */
#if (RTE_VERSION_NUM(16, 7, 0, 0) < \
	RTE_VERSION_NUM(RTE_VER_YEAR, RTE_VER_MONTH, 0, 0))
	#define VDEV_NAME "net_pcap0"
#else
	#define VDEV_NAME "eth_pcap0"
#endif

using namespace std;

extern struct rte_mempool *mbuf_pool;

/* Dummy lookup functions, TX operations are not performed in these tests */

static int
lookup4_function(void *opaque, const struct in_addr *addr, struct tle_dest *res)
{
	struct in_addr route;
	struct ether_hdr *eth;
	struct ipv4_hdr *ip4h;
	auto routes = static_cast<map<string, tle_dev *> *>(opaque);

	/* Check all routes added in map for a match with dest *addr */
	for (auto it = routes->begin(); it != routes->end(); ++it) {
		inet_pton(AF_INET, it->first.c_str(), &route);

		/* If it matches then fill *res and return with 0 code */
		if (memcmp(&route, addr, sizeof(struct in_addr)) == 0) {
			memset(res, 0, sizeof(*res));
			res->dev = it->second;
			res->mtu = 1500;
			res->l2_len = sizeof(*eth);
			res->l3_len = sizeof(*ip4h);
			res->head_mp = mbuf_pool;
			eth = (struct ether_hdr *)res->hdr;
			eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
			ip4h = (struct ipv4_hdr *)(eth + 1);
			ip4h->version_ihl = (4 << 4) |
				(sizeof(*ip4h) / IPV4_IHL_MULTIPLIER);
			ip4h->time_to_live = 64;
			ip4h->next_proto_id = IPPROTO_UDP;
			ip4h->fragment_offset = 0;

			return 0;
		}
	}

	return -ENOENT;
}

static int
lookup6_function(void *opaque, const struct in6_addr *addr,
	struct tle_dest *res)
{
	struct ether_hdr *eth;
	struct ipv6_hdr *ip6h;
	struct in6_addr route;
	auto routes = static_cast<map<string, tle_dev *> *>(opaque);

	/* Check all routes added in map for a match with dest *addr */
	for (auto it = routes->begin(); it != routes->end(); ++it) {
		inet_pton(AF_INET6, it->first.c_str(), &route);

		/* If it matches then fill *res and return with 0 code */
		if (memcmp(&route, addr, sizeof(struct in6_addr)) == 0) {
			memset(res, 0, sizeof(*res));
			res->dev = it->second;
			res->mtu = 1500;
			res->l2_len = sizeof(*eth);
			res->l3_len = sizeof(*ip6h);
			res->head_mp = mbuf_pool;
			eth = (struct ether_hdr *)res->hdr;
			eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv6);
			ip6h = (struct ipv6_hdr *)(eth + 1);
			ip6h->vtc_flow = 6 << 4;
			ip6h->proto = IPPROTO_UDP;
			ip6h->hop_limits = 64;

			return 0;
		}
	}
	return -ENOENT;
}

/*
 * Structures used to describe test instances:
 * test_str - main structure for describing test case instance; contains
 *            instance description, and vectors with information about
 *            devices, streams & streams to be generated for RX/TX path.
 * dev_s    - structure describing single device; contains device addresses,
 *            checksum offload information and expected number of received /
 *            transmitted packets.
 *            packets for that device in scenario.
 * stream_s - structure describing single stream to be created; contains
 *            information on local & remote IP's and port numbers, expected
 *            number of received and transmitted packets.
 * stream_g - structure describing a stream which to generate via scapy script;
 *            Contains information on IP addresses and port numbers and if
 *            L3/L4 checksums should be incorrectly calculated.
 *            In future: if packet should be fragmented.
 */

struct stream_g {
	int family;
	string src_ip;
	string dst_ip;
	int src_port;
	int dst_port;
	int nb_pkts;
	bool bad_chksum_l3;
	bool bad_chksum_l4;
	bool fragment;
};

struct stream_s {
	int family;
	int l_port;
	int r_port;
	string l_ip;
	string r_ip;
	int exp_pkts_rx;
	int exp_pkts_tx;
	int act_pkts_rx;
	int act_pkts_tx;
	tle_stream *ptr;
};

struct dev_s {
	string l_ipv4;
	string l_ipv6;
	uint64_t rx_offload;
	uint64_t tx_offload;
	int exp_pkts_bulk_rx;
	int exp_pkts_bulk_tx;
	int exp_pkts_enoent;
	int act_pkts_bulk_rx;
	int act_pkts_bulk_tx;
	int act_pkts_enoent;
	tle_dev *ptr;
};

struct test_str {
	string test_desc;
	vector<dev_s> devs;
	vector<stream_s> streams;
	vector<stream_g> gen_streams;
};

const char *vdevargs = "rx_pcap=" RX_PCAP ",tx_pcap=" TX_PCAP;

class test_tle_udp_gen_base : public testing::TestWithParam<test_str> {
public:

	tle_ctx *setup_ctx(void);
	tle_dev *setup_dev(tle_ctx *ctx, uint64_t rx_offload,
		uint64_t tx_offload, const char *local_ipv4,
		const char *local_ipv6);
	tle_evq *setup_evq(void);
	tle_event *setup_event(void);
	tle_stream *setup_stream(struct tle_ctx *ctx, int family,
		const char *l_ip, const char *r_ip, int l_port, int r_port);
	int setup_devices(dpdk_port_t *portid);
	int cleanup_devices(dpdk_port_t portid);
	int prepare_pcaps(string l_ip, string r_ip, int l_port, int r_port,
		int nb_pkts, int l3_chksum, int l4_chksum, string rx_pcap_dest);

	int cleanup_pcaps(const char *file);
	int close_streams(vector<struct stream_s> streams);
	int del_devs(vector<struct dev_s> devs);

	virtual void SetUp(void)
	{
		nb_ports = 1;
		tp = GetParam();

		/* Usual tldk stuff below -> ctx, dev, events etc. */
		ctx = setup_ctx();
		ASSERT_NE(ctx, nullptr);

		evq = setup_evq();
		ASSERT_NE(evq, nullptr);

		for (auto &d : tp.devs) {
			dev = setup_dev(ctx, d.rx_offload, d.tx_offload,
				d.l_ipv4.c_str(), d.l_ipv6.c_str());
			ASSERT_NE(dev, nullptr);

			/* Initialize counters for verifying results */
			d.act_pkts_bulk_rx = 0;
			d.act_pkts_bulk_tx = 0;
			d.act_pkts_enoent = 0;

			/* Save pointer to device */
			d.ptr = dev;
		}

		for (auto &s : tp.streams) {
			stream = setup_stream(ctx, s.family,
					s.l_ip.c_str(), s.r_ip.c_str(),
					s.l_port, s.r_port);
			ASSERT_NE(stream, nullptr);

			/* Initialize counters for verifying results */
			s.act_pkts_rx = 0;
			s.act_pkts_tx = 0;

			/* Save pointer to stream */
			s.ptr = stream;

			/* Find which dev has the same address as streams
			 * local address and save destination for later use
			 * in lookup functions
			 */
			if (s.family == AF_INET) {
				for (auto &d : tp.devs) {
					if (s.l_ip.compare(d.l_ipv4) == 0)
						routes4.insert(pair<string,
							tle_dev *>(s.r_ip,
								d.ptr));
				}
			} else if (s.family == AF_INET6) {
				for (auto &d : tp.devs) {
					if (s.l_ip.compare(d.l_ipv6) == 0)
						routes6.insert(pair<string,
							tle_dev *>(s.r_ip,
								d.ptr));
				}
			}
		}

		/* setup pcap/eth devices */
		setup_devices(&portid);
	}

	virtual void TearDown(void)
	{
		/*
		 * Remember to shutdown & detach rte devices
		 * and clean / delete .pcap files so not to
		 * interfere with next test
		 */
		close_streams(tp.streams);
		del_devs(tp.devs);
		tle_ctx_destroy(ctx);
		cleanup_devices(portid);
		cleanup_pcaps(RX_PCAP);
		cleanup_pcaps(TX_PCAP);
	}

	dpdk_port_t nb_ports;
	dpdk_port_t portid;
	uint32_t socket_id;
	uint32_t max_events;
	struct tle_ctx *ctx;
	struct tle_dev *dev;
	struct tle_evq *evq;
	struct tle_stream *stream;
	map<string, tle_dev *> routes4;
	map<string, tle_dev *> routes6;
	test_str tp;
	const void *cb;
};

int
test_tle_udp_gen_base::setup_devices(dpdk_port_t *portid)
{
	/* attach + configure + start pmd device */
	if (rte_eal_hotplug_add("vdev", VDEV_NAME, vdevargs) < 0 ||
			rte_eth_dev_get_port_by_name(VDEV_NAME, portid) != 0)
		return -1;
	cb = rte_eth_add_rx_callback(*portid, 0,
		typen_rx_callback, nullptr);
	if (port_init(*portid, mbuf_pool) != 0)
		return -1;

	return 0;
}

int
test_tle_udp_gen_base::cleanup_devices(dpdk_port_t portid)
{
	/* release mbufs + detach device */
	char name[RTE_ETH_NAME_MAX_LEN];

	rte_eth_dev_stop(portid);
	rte_eth_dev_close(portid);
	rte_eal_hotplug_remove("vdev", VDEV_NAME);

	return 0;
}

int
test_tle_udp_gen_base::prepare_pcaps(string l_ip, string r_ip, int l_port,
	int r_port, int nb_pkts, int l3_chksum, int l4_chksum,
	string rx_pcap_dest)
{
	string py_cmd;

	/* generate pcap rx & tx files * for tests using scapy */
	py_cmd = "python " + string(binpath) + "/test_scapy_gen.py ";
	py_cmd = py_cmd + " " + l_ip + " " + r_ip + " " +
			to_string(l_port) + " " + to_string(r_port) + " " +
			to_string(nb_pkts);

	if (l3_chksum > 0)
		py_cmd = py_cmd + " -bc3 " + to_string(l3_chksum);
	if (l4_chksum > 0)
		py_cmd = py_cmd + " -bc4 " + to_string(l4_chksum);
	py_cmd = py_cmd + " " + rx_pcap_dest;
	system(py_cmd.c_str());
	return 0;
}

int
test_tle_udp_gen_base::cleanup_pcaps(const char *file)
{
	if (remove(file) != 0)
		perror("Error deleting pcap file");

	return 0;
}

tle_ctx *
test_tle_udp_gen_base::setup_ctx(void)
{

	struct tle_ctx *ctx;
	struct tle_ctx_param ctx_prm;

	memset(&ctx_prm, 0, sizeof(ctx_prm));
	ctx_prm.socket_id = SOCKET_ID_ANY;
	ctx_prm.max_streams = 0x10;
	ctx_prm.min_streams = 0x8;
	ctx_prm.delta_streams = 0x8;
	ctx_prm.max_stream_rbufs = CTX_MAX_RBUFS;
	ctx_prm.max_stream_sbufs = CTX_MAX_SBUFS;
	ctx_prm.lookup4 = lookup4_function;
	ctx_prm.lookup6 = lookup6_function;
	ctx_prm.lookup4_data = &routes4;
	ctx_prm.lookup6_data = &routes6;

	ctx = tle_ctx_create(&ctx_prm);

	return ctx;
}

struct tle_dev *
test_tle_udp_gen_base::setup_dev(struct tle_ctx *ctx, uint64_t rx_offload,
	uint64_t tx_offload, const char *l_ipv4, const char *l_ipv6)
{
	struct tle_dev *dev;
	struct tle_dev_param dev_prm;

	memset(&dev_prm, 0, sizeof(dev_prm));
	dev_prm.rx_offload = RX_NO_OFFLOAD;
	dev_prm.tx_offload = TX_NO_OFFLOAD;
	if (l_ipv4 != NULL)
		inet_pton(AF_INET, l_ipv4, &(dev_prm).local_addr4);
	if (l_ipv6 != NULL)
		inet_pton(AF_INET6, l_ipv6, &(dev_prm).local_addr6);

	dev = tle_add_dev(ctx, &dev_prm);

	return dev;
}

struct tle_evq *
test_tle_udp_gen_base::setup_evq()
{
	uint32_t socket_id;
	uint32_t max_events;
	struct tle_evq_param evq_params;
	struct tle_evq *evq;

	socket_id = SOCKET_ID_ANY;
	max_events = 10;
	memset(&evq_params, 0, sizeof(struct tle_evq_param));

	evq_params.socket_id = socket_id;
	evq_params.max_events = max_events;
	evq = tle_evq_create(&evq_params);
	return evq;
}

struct tle_stream *
test_tle_udp_gen_base::setup_stream(struct tle_ctx *ctx, int family,
	const char *l_ip, const char *r_ip, int l_port, int r_port)
{
	struct tle_stream *stream;
	struct tle_udp_stream_param stream_prm;
	struct sockaddr_in *ip4_addr;
	struct sockaddr_in6 *ip6_addr;
	int32_t ret;

	memset(&stream_prm, 0, sizeof(stream_prm));

	if (family == AF_INET) {
		ip4_addr = (struct sockaddr_in *) &stream_prm.local_addr;
		ip4_addr->sin_family = AF_INET;
		ip4_addr->sin_port = htons(l_port);
		ip4_addr->sin_addr.s_addr = inet_addr(l_ip);

		ip4_addr = (struct sockaddr_in *) &stream_prm.remote_addr;
		ip4_addr->sin_family = AF_INET;
		ip4_addr->sin_port = htons(r_port);
		ip4_addr->sin_addr.s_addr = inet_addr(r_ip);
	} else if (family == AF_INET6) {
		ip6_addr = (struct sockaddr_in6 *) &stream_prm.local_addr;
		ip6_addr->sin6_family = AF_INET6;
		inet_pton(AF_INET6, l_ip, &ip6_addr->sin6_addr);
		ip6_addr->sin6_port = htons(l_port);

		ip6_addr = (struct sockaddr_in6 *) &stream_prm.remote_addr;
		ip6_addr->sin6_family = AF_INET6;
		inet_pton(AF_INET6, r_ip, &ip6_addr->sin6_addr);
		ip6_addr->sin6_port = htons(r_port);
	} else {
		printf("Invalid address family, stream not created\n");
		return NULL;
	}

	/* Not supporting callbacks and events at the moment */
	/* TODO: Add tests which use cb's and events. */
	stream_prm.recv_ev = tle_event_alloc(evq, nullptr);
	stream_prm.send_ev = tle_event_alloc(evq, nullptr);

	stream = tle_udp_stream_open(ctx,
			(const struct tle_udp_stream_param *) &stream_prm);

	return stream;
}

int
test_tle_udp_gen_base::close_streams(vector<struct stream_s> streams)
{
	int rc;

	for (auto &s : streams) {
		rc = tle_udp_stream_close(s.ptr);
		if (rc != 0)
			return -1;
	}

	return 0;
}

int
test_tle_udp_gen_base::del_devs(vector<struct dev_s> devs)
{
	int rc;

	for (auto &d : devs) {
		rc = tle_del_dev(d.ptr);
		if (rc != 0)
			return -1;
	}

	return 0;
}

class tle_rx_test : public test_tle_udp_gen_base {
public:
	virtual void SetUp(void)
	{
		/* Generate RX pcap file, for RX tests, then
		 * follow setup steps as in base class */
		tp = GetParam();

		for(auto &s : tp.gen_streams) {
			prepare_pcaps(s.src_ip.c_str(), s.dst_ip.c_str(),
				s.src_port, s.dst_port, s.nb_pkts,
				s.bad_chksum_l3, s.bad_chksum_l4, RX_PCAP);
		}
		test_tle_udp_gen_base::SetUp();
	}
};

class tle_rx_enobufs: public tle_rx_test { };

class tle_tx_test: public test_tle_udp_gen_base {
public:
	virtual void SetUp(void)
	{
		/* Generate 1-packet PCAP RX file so that virtual device can be
		 * initialized (needs a pcap file present during init), then
		 * follow setup steps as in base class
		 */
		prepare_pcaps("10.0.0.1", "10.0.0.1", 100, 100, 1, 0, 0,
			RX_PCAP);
		test_tle_udp_gen_base::SetUp();
	}
};

#endif /* TEST_TLE_UDP_STREAM_GEN_H_ */

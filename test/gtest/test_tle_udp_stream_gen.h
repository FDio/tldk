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
#include <string>
#include <algorithm>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <sys/socket.h>
#include <netdb.h>
#include <gtest/gtest.h>

#include <rte_version.h>

#include <tle_udp_impl.h>
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
#if (RTE_VER_YEAR >= 16 && RTE_VER_MONTH > 7)
	#define VDEV_NAME "net_pcap0"
#else
	#define VDEV_NAME "eth_pcap0"
#endif

using namespace std;

extern struct rte_mempool *mbuf_pool;

/* Dummy lookup functions, TX operations are not performed in these tests */

static int
dummy_lookup4(void *opaque, const struct in_addr *addr,
	struct tle_udp_dest *res)
{
	struct tle_udp_dest *dst;
	dst = (tle_udp_dest*)opaque;

	rte_memcpy(res, dst, dst->l2_len + dst->l3_len +
			offsetof(struct tle_udp_dest, hdr));

	return 0;
}

static int
dummy_lookup6(void *opaque, const struct in6_addr *addr,
	struct tle_udp_dest *res)
{
	struct tle_udp_dest *dst;
	dst = (tle_udp_dest*)opaque;

	rte_memcpy(res, dst, dst->l2_len + dst->l3_len +
			offsetof(struct tle_udp_dest, hdr));

	return 0;
}

/*
 * Structures used to describe test instances:
 * test_str - main structure for describing test case instance; contains
 *            instance description, and vectors with information about
 *            devices & scapy generated streams.
 * dev_s    - structure describing single device; contains device addresses,
 *            checksum offload information and expected number of received
 *            packets for that device in scenario. Streams vector contains
 *            information about each stream associated with device.
 * stream_s - structure describing single stream in device; contains
 *            information on local & remote IP's and port numbers, expected
 *            number of received packets.
 * stream_g - structure describing a stream which to generate via scapy script;
 *            Contains information on IP addresses and port numbers and if
 *            L3/L4 checksums should be incorrectly calculated.
 *            In future: if packet should be fragmented.
 * test_r   - structure contains pointer to all created devices and streams;
 *            Also keeps information how many packets were successfully
 *            received on each device and stream for verification at the end
 *            of each test instance.
 */

struct stream_s {
	int l_port;
	int r_port;
	string l_ip;
	string r_ip;
	int exp_pkts_rx;
};

struct stream_g {
	string src_ip;
	string dst_ip;
	int src_port;
	int dst_port;
	int nb_pkts;
	bool bad_chksum_l3;
	bool bad_chksum_l4;
	bool fragment;
};

struct dev_s {
	string l_ipv4;
	string l_ipv6;
	int rx_offload;
	int tx_offload;
	int exp_pkts_bulk_rx;
	int exp_enoent;
	vector<stream_s> streams;
};

struct test_str {
	string test_desc;
	vector<dev_s> devs;
	vector<stream_g> streams;
};

struct test_r {
	int rx_dev;
	int tx_dev;
	struct tle_udp_dev *dev_ptr;
	vector<int> rx_str;
	vector<int> tx_str;
	vector <tle_udp_stream*> str_ptr;
};

const char *vdevargs[] = {VDEV_NAME",rx_pcap=" RX_PCAP",tx_pcap=" TX_PCAP};

class test_tle_udp_stream_gen: public testing::TestWithParam<test_str> {
public:

	tle_udp_ctx *setup_ctx(void);
	tle_udp_dev *setup_dev(tle_udp_ctx *ctx, uint32_t rx_offload,
		uint32_t tx_offload, const char *local_ipv4, const char *local_ipv6);
	tle_evq *setup_evq(void);
	tle_event *setup_event(void);
	tle_udp_stream *setup_stream(struct tle_udp_ctx *ctx,
		const char *l_ip, const char *r_ip, int l_port, int r_port);
	int setup_devices(uint8_t *portid);
	int cleanup_devices(uint8_t portid);
	int prepare_pcaps(string l_ip, string r_ip,
			int l_port, int r_port, int nb_pkts,
			int l3_chksum, int l4_chksum, string rx_pcap_dest);

	int cleanup_pcaps(const char *file);
	int close_streams_devs(vector<struct test_r> ptrs);

	virtual void SetUp(void)
	{
		uint32_t i, j;	/* Counters for loops*/
		nb_ports = 1;
		tp = GetParam();

		/* Usual tldk stuff below -> ctx, dev, events etc. */
		ctx = setup_ctx();
		ASSERT_NE(ctx, nullptr);

		evq = setup_evq();
		ASSERT_NE(evq, nullptr);

		for(auto d : tp.devs) {
			/* Temporary helper vectors below */
			vector<int> str_rx_temp;
			vector<int> str_tx_temp;
			vector<struct tle_udp_stream*> str_ptr_temp;

			dev = setup_dev(ctx, d.rx_offload, d.tx_offload,
						d.l_ipv4.c_str(), d.l_ipv6.c_str());
			ASSERT_NE(dev, nullptr);

			for(auto s : d.streams) {
				stream = setup_stream(ctx, s.l_ip.c_str(), s.r_ip.c_str(),
					s.l_port, s.r_port);

				ASSERT_NE(stream, nullptr);

				/*
				 * Initialize stream expected results with zeroes
				 * and save stream pointers for later use
				 */
				str_rx_temp.push_back(0);
				str_tx_temp.push_back(0);
				str_ptr_temp.push_back(stream);
			}

			/*
			 * Initialize dev expected results with 0
			 * and save pointer for later use
			 */
			results.push_back({0, 0, dev, str_rx_temp, str_tx_temp,str_ptr_temp});
		}

		for(auto s : tp.streams) {
			prepare_pcaps(s.src_ip.c_str(), s.dst_ip.c_str(),
						  s.src_port, s.dst_port,
						  s.nb_pkts, s.bad_chksum_l3, s.bad_chksum_l4, RX_PCAP);
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
		close_streams_devs(results);
		tle_udp_destroy(ctx);
		cleanup_devices(portid);
		cleanup_pcaps(RX_PCAP);
		cleanup_pcaps(TX_PCAP);
	}

	uint8_t nb_ports;
	uint8_t portid;
	uint32_t socket_id;
	uint32_t max_events;
	struct tle_udp_ctx *ctx;
	struct tle_udp_dev *dev;
	struct tle_evq *evq;
	struct tle_udp_stream *stream;
	vector<test_r> results;
	test_str tp;
	void *cb;
};

int test_tle_udp_stream_gen::setup_devices(uint8_t *portid) {

	/* attach + configure + start pmd device */

	if (rte_eth_dev_attach(vdevargs[0], portid) != 0)
		return -1;
	cb = rte_eth_add_rx_callback(*portid, 0,
		typen_rx_callback, nullptr);
	if (port_init(*portid, mbuf_pool) != 0)
		return -1;

	return 0;
}

int test_tle_udp_stream_gen::cleanup_devices(uint8_t portid) {

	/* release mbufs + detach device */
	char name[RTE_ETH_NAME_MAX_LEN];

	rte_eth_dev_stop(portid);
	rte_eth_dev_close(portid);
	rte_eth_dev_detach(portid, name);

	return 0;
}

int test_tle_udp_stream_gen::prepare_pcaps(string l_ip, string r_ip,
		int l_port, int r_port, int nb_pkts, int l3_chksum, int l4_chksum,
		string rx_pcap_dest) {
	/* generate pcap rx & tx files * for tests using scapy */

	string py_cmd = "python ./test/gtest/test_scapy_gen.py ";
	py_cmd = py_cmd + " " + l_ip + " " + r_ip + " " +\
			to_string(l_port) + " " + to_string(r_port) + " " +\
			to_string(nb_pkts);

	if (l3_chksum > 0)
		py_cmd = py_cmd + " -bc3 " + to_string(l3_chksum);
	if (l4_chksum > 0)
		py_cmd = py_cmd + " -bc4 " + to_string(l4_chksum);
	py_cmd = py_cmd + " " + rx_pcap_dest;
	system(py_cmd.c_str());

	return 0;
}

int test_tle_udp_stream_gen::cleanup_pcaps(const char *file) {
	if(remove(file) != 0)
	    perror( "Error deleting pcap file" );
	return 0;
}

struct tle_udp_ctx*
test_tle_udp_stream_gen::setup_ctx(void) {

	struct tle_udp_ctx *ctx;
	struct tle_udp_ctx_param ctx_prm;

	memset(&ctx_prm, 0, sizeof(ctx_prm));
	ctx_prm.socket_id = SOCKET_ID_ANY;
	ctx_prm.max_streams = 0x10;
	ctx_prm.max_stream_rbufs = CTX_MAX_RBUFS;
	ctx_prm.max_stream_sbufs = CTX_MAX_SBUFS;
	ctx_prm.lookup4 = dummy_lookup4;
	ctx_prm.lookup6 = dummy_lookup6;

	ctx = tle_udp_create(&ctx_prm);

	return ctx;
}

struct tle_udp_dev *test_tle_udp_stream_gen::setup_dev(struct tle_udp_ctx *ctx,
		uint32_t rx_offload, uint32_t tx_offload,
		const char *l_ipv4, const char *l_ipv6) {

	struct tle_udp_dev *dev;
	struct tle_udp_dev_param dev_prm;

	memset(&dev_prm, 0, sizeof(dev_prm));
	dev_prm.rx_offload = RX_NO_OFFLOAD;
	dev_prm.tx_offload = TX_NO_OFFLOAD;
	if (l_ipv4 != NULL)
		inet_pton(AF_INET, l_ipv4, &(dev_prm).local_addr4);
	if (l_ipv6 != NULL)
		inet_pton(AF_INET6, l_ipv6, &(dev_prm).local_addr6);

	dev = tle_udp_add_dev(ctx, &dev_prm);

	return dev;
}

struct tle_evq *test_tle_udp_stream_gen::setup_evq() {

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

struct tle_udp_stream *test_tle_udp_stream_gen::setup_stream(
		struct tle_udp_ctx *ctx, const char *l_ip, const char *r_ip,
		int l_port, int r_port) {

	struct tle_udp_stream *stream;
	struct tle_udp_stream_param stream_prm;
	struct sockaddr_in *ip4_addr;
	struct sockaddr_in6 *ip6_addr;
	struct addrinfo hint, *res = NULL;
	int32_t ret;

	memset(&hint, '\0', sizeof(hint));
	memset(&stream_prm, 0, sizeof(stream_prm));

	ret = getaddrinfo(l_ip, NULL, &hint, &res);
	if (ret) {
		printf("Invalid address; %s, %d\n", gai_strerror(ret), ret);
		return NULL;
	}
	if (res->ai_family == AF_INET) {
		ip4_addr = (struct sockaddr_in *) &stream_prm.local_addr;
		ip4_addr->sin_family = AF_INET;
		ip4_addr->sin_port = htons(l_port);
		ip4_addr->sin_addr.s_addr = inet_addr(l_ip);
	} else if (res->ai_family == AF_INET6) {
		ip6_addr = (struct sockaddr_in6 *) &stream_prm.local_addr;
		ip6_addr->sin6_family = AF_INET6;
		inet_pton(AF_INET6, l_ip, &ip6_addr->sin6_addr);
		ip6_addr->sin6_port = htons(l_port);
	} else {
		printf("%s is an is unknown address format %d\n", l_ip,
			res->ai_family);
		return NULL;
	}
	freeaddrinfo(res);

	ret = getaddrinfo(r_ip, NULL, &hint, &res);
	if (ret) {
		printf("Invalid address; %s, %d\n", gai_strerror(ret), ret);
		return NULL;
	}
	if (res->ai_family == AF_INET) {
		ip4_addr = (struct sockaddr_in *) &stream_prm.remote_addr;
		ip4_addr->sin_family = AF_INET;
		ip4_addr->sin_port = htons(r_port);
		ip4_addr->sin_addr.s_addr = inet_addr(r_ip);
	} else if (res->ai_family == AF_INET6) {
		ip6_addr = (struct sockaddr_in6 *) &stream_prm.remote_addr;
		ip6_addr->sin6_family = AF_INET6;
		inet_pton(AF_INET6, r_ip, &ip6_addr->sin6_addr);
		ip6_addr->sin6_port = htons(r_port);
	} else {
		printf("%s is an is unknown address format %d\n", r_ip,
				res->ai_family);
		return NULL;
	}
	freeaddrinfo(res);

	/* Not supporting callbacks and events at the moment */
	/* TODO:
	 * Add tests which use cb's and events.
	 */
	stream_prm.recv_ev = tle_event_alloc(evq, nullptr);
	stream_prm.send_ev = tle_event_alloc(evq, nullptr);

	stream = tle_udp_stream_open(ctx,
			(const struct tle_udp_stream_param *) &stream_prm);

	return stream;
}

int test_tle_udp_stream_gen::close_streams_devs(vector<struct test_r> ptrs) {

	int i, j, rc;

	for(i = 0; i < ptrs.size(); i++) {
		for(j = 0; j < ptrs[i].str_ptr.size(); j++) {
			rc = tle_udp_stream_close(ptrs[i].str_ptr[j]);
			if(rc != 0)
				return -1;
		}
		rc = tle_udp_del_dev(ptrs[i].dev_ptr);
		if(rc != 0)
			return -1;
	}
	return 0;
}

class tle_rx_enobufs: public test_tle_udp_stream_gen { };

#endif /* TEST_TLE_UDP_STREAM_GEN_H_ */

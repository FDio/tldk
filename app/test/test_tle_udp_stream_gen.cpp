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

#include "test_tle_udp_stream_gen.h"

TEST_P(tle_rx_enobufs, enobufs_test)
{
	int j, pkt_cnt = 0, enobufs_cnt = 0;
	uint16_t nb_rx, nb_rx_bulk;
	struct rte_mbuf *m[BURST_SIZE];
	struct rte_mbuf *rp[BURST_SIZE];
	int rc[BURST_SIZE];

	/* Receive packets until we reach end on pcap file*/
	do {
		memset(rc, 0, sizeof(int) * BURST_SIZE);
		nb_rx = rte_eth_rx_burst(portid, 0, m, BURST_SIZE);
		pkt_cnt += nb_rx;
		for(auto &d: tp.devs){
			nb_rx_bulk = tle_udp_rx_bulk(d.ptr, m, rp, rc, nb_rx);
			for(j = 0; j < BURST_SIZE; j++) {
				if(rc[j] == ENOBUFS) {
					enobufs_cnt++;
				}
			}
			d.act_pkts_bulk_rx += nb_rx_bulk;
		}
	} while (nb_rx > 0);

	/*
	 * Verify results - number of rx packets per dev and stream
	 * and packets dropped due to ENOBUFS
	 */

	for(auto &d: tp.devs) {
		EXPECT_EQ(d.act_pkts_bulk_rx, d.exp_pkts_bulk_rx);
		EXPECT_EQ(enobufs_cnt, pkt_cnt - d.act_pkts_bulk_rx);
	}
}
/*
 * TODO: Obviously this way of defining test scenarios is terrible.
 * Need to move to JSON files in future and parse from external file.
 * Currently first commented out entry is an example of what values should be
 * inserted into certain fields
 * */
INSTANTIATE_TEST_CASE_P(enobufs_test, tle_rx_enobufs, testing::Values(
/* test_str example */
/* {
	"Description",
	Devices configs below
	{
		{"Dev local IPv4", "Dev local IPv6",
			RX_OFFLOAD, TX_OFFLOAD,
			Exp. nb. of rx pkts on device,
			Exp. nb. of tx pkts on device,
			Exp. nb. of total ENOENT pkts on device,
		},
	},
	Streams config on device below
	{
		{local port, remote port, "local ip", "remote ip",
		exp. nb. of rx. pkts, exp. nb. of tx. pkts},
	},
	Pkts to generate with scapy to pcap file
	{
		{"Src IP", "Dst IP",
		Src port, Dst port,
		nb of pkts,
		l3 chksum, l4 chksum, fragment?},
	}
}, */
test_str
{
	"IPv4 - 1 dev 1 stream, only correct pkts",
	{
		{"10.0.0.1", "2001::1000", RX_NO_OFFLOAD, TX_NO_OFFLOAD,
				CTX_MAX_RBUFS - 1, 0, 0}
	},
	{
		{AF_INET, 10001, 10002, "10.0.0.1", "10.0.0.2", 0, 0},
	},
	{
		{AF_INET, "10.0.0.2", "10.0.0.1", 10002, 10001, 1000, 0, 0, 0},
	}
},
test_str
{
	"IPv4 - 1 dev 1 stream, only correct pkts",
	{
		{"10.0.0.1", "2001::1000", RX_NO_OFFLOAD, TX_NO_OFFLOAD,
				CTX_MAX_RBUFS - 1, 0, 0, 0}
	},
	{
		{AF_INET6, 10001, 10002, "2001::1000", "2001::2000", 0, 0},
	},
	{
		{AF_INET6, "2001::2000", "2001::1000", 10002, 10001, 1000, 0, 0, 0},
	}
}
));

TEST_P(tle_rx_test, test)
{
	int j;
	uint16_t nb_rx, nb_rx_bulk, nb_str_rx;
	struct rte_mbuf *m[BURST_SIZE];
	struct rte_mbuf *n[BURST_SIZE];
	struct rte_mbuf *rp[BURST_SIZE];
	int rc[BURST_SIZE];

	/* Receive packets until we reach end on pcap file*/
	do {
		nb_rx = rte_eth_rx_burst(portid, 0, m, BURST_SIZE);
		for(auto &d: tp.devs) {
			memset(rc, 0, sizeof(int) * BURST_SIZE);
			nb_rx_bulk = tle_udp_rx_bulk(d.ptr, m, rp, rc, nb_rx);
			d.act_pkts_bulk_rx += nb_rx_bulk;
			for(j = 0; j < BURST_SIZE; j++) {
				if(rc[j] == ENOENT)
					d.act_pkts_enoent += 1;
			}
		}

		for(auto &s: tp.streams) {
			nb_str_rx = tle_udp_stream_recv(s.ptr, n, BURST_SIZE);
			s.act_pkts_rx += nb_str_rx;
		}
	} while (nb_rx > 0);


	/*
	 * Verify results - number of rx packets per dev and stream.
	 */
	for(auto &d: tp.devs) {
		EXPECT_EQ(d.act_pkts_bulk_rx, d.exp_pkts_bulk_rx);
		EXPECT_EQ(d.act_pkts_enoent, d.exp_pkts_enoent);
	}

	for(auto &s: tp.streams) {
		EXPECT_EQ(s.act_pkts_rx, s.exp_pkts_rx);
	}
}
INSTANTIATE_TEST_CASE_P(rx_recv, tle_rx_test, testing::Values(
test_str
{
	"IPv4 - 1 dev 1 stream, only correct pkts",
	{
		{"10.0.0.1", "2001::1000", RX_NO_OFFLOAD, TX_NO_OFFLOAD, 10, 0, 0},
	},
	{
		{AF_INET, 10001, 10002, "10.0.0.1", "10.0.0.2", 10, 0},
	},
	{
		{AF_INET, "10.0.0.2", "10.0.0.1", 10002, 10001, 10, 0, 0, 0},
	}
},

test_str
{
	"IPv4 - 1 dev 1 stream, only incorrect pkts",
	{
		{"10.0.0.1", "2001::1000", RX_NO_OFFLOAD, TX_NO_OFFLOAD, 0, 0, 40},
	},
	{
		{AF_INET, 10001, 10002, "10.0.0.1", "10.0.0.2", 0, 0},
	},
	{
		{AF_INET, "20.0.0.2", "10.0.0.1", 10002, 10001, 10, 0, 0, 0},
		{AF_INET, "10.0.0.2", "20.0.0.1", 10002, 10001, 10, 0, 0, 0},
		{AF_INET, "10.0.0.2", "10.0.0.1", 20002, 10001, 10, 0, 0, 0},
		{AF_INET, "10.0.0.2", "10.0.0.1", 10002, 20001, 10, 0, 0, 0},
	}
},

test_str
{
	"IPv4 - 1 dev with 1 stream, only correct pkts but incorrect chksum",
	{
		{"10.0.0.1", "2001::1000", RX_NO_OFFLOAD, TX_NO_OFFLOAD, 30, 0, 0}
	},
	{
		{AF_INET, 10001, 10002, "10.0.0.1", "10.0.0.2", 0, 0},
	},
	{
		{AF_INET, "10.0.0.2", "10.0.0.1", 10002, 10001, 10, 1, 0, 0},
		{AF_INET, "10.0.0.2", "10.0.0.1", 10002, 10001, 10, 0, 1, 0},
		{AF_INET, "10.0.0.2", "10.0.0.1", 10002, 10001, 10, 1, 1, 0},
	}
},

test_str
{
	"IPv6 - 1 dev with 1 stream, only correct pkts",
	{
		{"10.0.0.1", "2001::1000", RX_NO_OFFLOAD, TX_NO_OFFLOAD, 10, 0, 0}
	},
	{
		{AF_INET6, 10001, 10002, "2001::1000", "2001::2000", 10, 0},
	},
	{
		{AF_INET6, "2001::2000", "2001::1000", 10002, 10001, 10, 0, 0, 0},
	}
},

test_str
{
	"IPv6 - 1 dev with 1 stream, only incorrect pkts",
	{
		{"10.0.0.1", "2001::1000", RX_NO_OFFLOAD, TX_NO_OFFLOAD, 0, 0, 40},
	},
	{
		{AF_INET6, 10001, 10002, "2001::1000", "2001::2000", 0, 0},
	},
	{
		{AF_INET6, "3001::2000", "2001::1000", 10002, 10001, 10, 0, 0, 0},
		{AF_INET6, "2001::3000", "2001::1000", 10002, 10001, 10, 0, 0, 0},
		{AF_INET6, "2001::2000", "2001::1000", 30002, 10001, 10, 0, 0, 0},
		{AF_INET6, "2001::2000", "2001::1000", 10002, 30001, 10, 0, 0, 0},
	}
},

test_str
{
	"IPv6 - 1 dev with 1 stream, only correct pkts but incorrect chksum",
	/*
	 * Note: one of streams will be received as IPv6 does not have
	 * checksum field by default.
	 */
	{
		{"10.0.0.1", "2001::1000", RX_NO_OFFLOAD, TX_NO_OFFLOAD, 30, 0, 0}
	},
	{
		{AF_INET6, 10001, 10002, "2001::1000", "2001::2000", 10, 0},
	},
	{
		{AF_INET6, "2001::2000", "2001::1000", 10002, 10001, 10, 1, 0, 0},
		{AF_INET6, "2001::2000", "2001::1000", 10002, 10001, 10, 0, 1, 0},
		{AF_INET6, "2001::2000", "2001::1000", 10002, 10001, 10, 1, 1, 0},
	}
},

test_str
{
	/* Multiple streams, multiple correct pkt streams, mixed IPv4 & IPv6;
	 * 3 dev, 3 stream per dev, only correct pkts */
	"Mixed IPv4+IPv6; Multiple devs with multiple correct streams",
	{
		{"10.0.0.1", "2001::1000",RX_NO_OFFLOAD, TX_NO_OFFLOAD, 300, 0, 600},
		{"20.0.0.1", "2002::1000", RX_NO_OFFLOAD, TX_NO_OFFLOAD, 300, 0, 600},
		{"30.0.0.1", "2003::1000", RX_NO_OFFLOAD, TX_NO_OFFLOAD, 300, 0, 600},
	},
	{
		{AF_INET, 10001, 10011, "10.0.0.1", "10.0.0.2", 100, 0},
		{AF_INET, 10002, 10012, "10.0.0.1", "10.0.0.3", 100, 0},
		{AF_INET6, 10003, 10013, "2001::1000", "2001::4000", 100, 0},
		{AF_INET, 20001, 20011, "20.0.0.1", "20.0.0.2", 100, 0},
		{AF_INET6, 20002, 20012, "2002::1000", "2002::3000", 100, 0},
		{AF_INET6, 20003, 20013, "2002::1000", "2002::4000", 100, 0},
		{AF_INET, 20001, 20011, "30.0.0.1", "30.0.0.2", 100, 0},
		{AF_INET6, 20002, 20012, "2003::1000", "2003::3000", 100, 0},
		{AF_INET6, 20003, 20013, "2003::1000", "2003::4000", 100, 0}
	},
	{
		{AF_INET, "10.0.0.2", "10.0.0.1", 10011, 10001, 100, 0, 0, 0},
		{AF_INET, "10.0.0.3", "10.0.0.1", 10012, 10002, 100, 0, 0, 0},
		{AF_INET, "20.0.0.2", "20.0.0.1", 20011, 20001, 100, 0, 0, 0},
		{AF_INET, "30.0.0.2", "30.0.0.1", 20011, 20001, 100, 0, 0, 0},
		{AF_INET6, "2001::4000", "2001::1000", 10013, 10003, 100, 0, 0, 0},
		{AF_INET6, "2002::3000", "2002::1000", 20012, 20002, 100, 0, 0, 0},
		{AF_INET6, "2002::4000", "2002::1000", 20013, 20003, 100, 0, 0, 0},
		{AF_INET6, "2003::3000", "2003::1000", 20012, 20002, 100, 0, 0, 0},
		{AF_INET6, "2003::4000", "2003::1000", 20013, 20003, 100, 0, 0, 0},
	}
}
));

TEST_P(tle_tx_test, tx_send)
{
	int i, j, s, pkts_to_send;
	uint16_t nb_tx, nb_tx_bulk, nb_str_tx;
	struct rte_mbuf *m[BURST_SIZE];
	struct rte_mbuf *n[BURST_SIZE];
	int rc[BURST_SIZE];
	struct sockaddr_storage dest;
	uint8_t *plaintext;
	unsigned plaintext_len;
	unsigned plaintext_pad_len;
	char text[]="DEADBEEF";

	for(auto &sg: tp.gen_streams) {

		/* Find from which stream we will be sending - save the pointer and
		 * index number for later TX counter validation */
		for(s = 0; s < tp.streams.size(); s++) {
			auto tmp = tp.streams[s];
			if(sg.dst_ip.compare(tmp.l_ip) == 0 && sg.dst_port == tmp.l_port) {
				stream = tmp.ptr;
				break;
			}
		}

		/* Prepare sockaddr for sending */
		memset(&dest, 0, sizeof(dest));
		if (sg.family == AF_INET) {
			((sockaddr_in *) &dest)->sin_family = AF_INET;
			((sockaddr_in *) &dest)->sin_port = htons(sg.src_port);
			inet_pton(AF_INET, sg.src_ip.c_str(),
					&((sockaddr_in *) &dest)->sin_addr);
		} else if (sg.family == AF_INET6) {
			((sockaddr_in6 *) &dest)->sin6_family = AF_INET6;
			((sockaddr_in6 *) &dest)->sin6_port = htons(sg.src_port);
			inet_pton(AF_INET6, sg.src_ip.c_str(),
					&((sockaddr_in6 *) &dest)->sin6_addr);
		}

		nb_str_tx = 0;
		/* Send all packets to stream*/
		for(i = 0; i < sg.nb_pkts; i += nb_str_tx) {
			pkts_to_send = (sg.nb_pkts - i < BURST_SIZE) ?
					(sg.nb_pkts - i) : BURST_SIZE;

			/* Allocate Mbufs */
			for(j = 0; j < pkts_to_send; j++) {
				m[j] = rte_pktmbuf_alloc(mbuf_pool);
				ASSERT_NE(m[j], nullptr);

				memset(rte_pktmbuf_mtod(m[j], uint8_t *), 0,
					       rte_pktmbuf_tailroom(m[j]));
				plaintext = (uint8_t *)rte_pktmbuf_append(m[j],
							sizeof(text));
				memcpy(rte_pktmbuf_mtod(m[j], uint8_t *), &text, sizeof(text));
			}

			nb_str_tx = tle_udp_stream_send(stream, m, pkts_to_send,
					reinterpret_cast<struct sockaddr*>(&dest));
			ASSERT_GE(nb_str_tx, 0);
			if(nb_str_tx == 0) {
				for(j = 0; j < pkts_to_send; j++) {
					rte_pktmbuf_free(m[j]);
				}
				nb_str_tx = pkts_to_send;
				continue;
			}
			tp.streams[s].act_pkts_tx += nb_str_tx;
		}
	}

	/* Send out packets from devices */
	for(auto &d: tp.devs) {
		nb_tx_bulk = 0;
		do {
			nb_tx_bulk = tle_udp_tx_bulk(d.ptr, n, BURST_SIZE);
			ASSERT_GE(nb_str_tx, 0);
			d.act_pkts_bulk_tx += nb_tx_bulk;
			nb_tx = rte_eth_tx_burst(portid, 0, n, nb_tx_bulk);
			ASSERT_GE(nb_str_tx, 0);
		} while (nb_tx_bulk > 0);
	}

	/*
	 * Verify results - number of rx packets per dev and stream.
	 */
	for(auto &d: tp.devs) {
		EXPECT_EQ(d.act_pkts_bulk_tx, d.exp_pkts_bulk_tx);
		EXPECT_EQ(d.act_pkts_enoent, d.exp_pkts_enoent);
	}

	for(auto &s: tp.streams) {
		EXPECT_EQ(s.act_pkts_tx, s.exp_pkts_tx);
	}
}

INSTANTIATE_TEST_CASE_P(test, tle_tx_test, testing::Values(
test_str
{
	"IPv4 - 1 dev 1 stream, only correct pkts",
	{
		{"10.0.0.1", "2001::1000", RX_NO_OFFLOAD, TX_NO_OFFLOAD, 0, 100, 0},
	},
	{
		{AF_INET, 10001, 10002, "10.0.0.1", "10.0.0.2", 0, 100},
	},
	{
		{AF_INET, "10.0.0.2", "10.0.0.1", 10002, 10001, 100, 0, 0, 0},
	}
},
test_str
{
	"IPv6 - 1 dev 1 stream, only correct pkts",
	{
		{"10.0.0.1", "2001::1000", RX_NO_OFFLOAD, TX_NO_OFFLOAD, 0, 100, 0},
	},
	{
		{AF_INET6, 10001, 10002, "2001::1000", "2001::2000", 0, 100},
	},
	{
		{AF_INET6, "2001::2000", "2001::1000", 10002, 10001, 100, 0, 0, 0},
	}
},
test_str
{
	/* Multiple streams, mixed IPv4 & IPv6; */
	"Mixed IPv4+IPv6; Multiple devs with multiple correct streams",
	{
		{"10.0.0.1", "2001::1000",RX_NO_OFFLOAD, TX_NO_OFFLOAD, 0, 300, 0},
		{"20.0.0.1", "2002::1000", RX_NO_OFFLOAD, TX_NO_OFFLOAD, 0, 300, 0},
		{"30.0.0.1", "2003::1000", RX_NO_OFFLOAD, TX_NO_OFFLOAD, 0, 300, 0},
	},
	{
		{AF_INET, 10001, 10011, "10.0.0.1", "10.0.0.2", 0, 100},
		{AF_INET, 10002, 10012, "10.0.0.1", "10.0.0.3", 0, 100},
		{AF_INET6, 10003, 10013, "2001::1000", "2001::4000", 0, 100},
		{AF_INET, 20001, 20011, "20.0.0.1", "20.0.0.2", 0, 100},
		{AF_INET6, 20002, 20012, "2002::1000", "2002::3000", 0, 100},
		{AF_INET6, 20003, 20013, "2002::1000", "2002::4000", 0, 100},
		{AF_INET, 20001, 20011, "30.0.0.1", "30.0.0.2", 0, 100},
		{AF_INET6, 20002, 20012, "2003::1000", "2003::3000", 0, 100},
		{AF_INET6, 20003, 20013, "2003::1000", "2003::4000", 0, 100}
	},
	{
		{AF_INET, "10.0.0.2", "10.0.0.1", 10011, 10001, 100, 0, 0, 0},
		{AF_INET, "10.0.0.3", "10.0.0.1", 10012, 10002, 100, 0, 0, 0},
		{AF_INET, "20.0.0.2", "20.0.0.1", 20011, 20001, 100, 0, 0, 0},
		{AF_INET, "30.0.0.2", "30.0.0.1", 20011, 20001, 100, 0, 0, 0},
		{AF_INET6, "2001::4000", "2001::1000", 10013, 10003, 100, 0, 0, 0},
		{AF_INET6, "2002::3000", "2002::1000", 20012, 20002, 100, 0, 0, 0},
		{AF_INET6, "2002::4000", "2002::1000", 20013, 20003, 100, 0, 0, 0},
		{AF_INET6, "2003::3000", "2003::1000", 20012, 20002, 100, 0, 0, 0},
		{AF_INET6, "2003::4000", "2003::1000", 20013, 20003, 100, 0, 0, 0},
	}
}
));

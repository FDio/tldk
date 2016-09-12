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
	int i, j, pkt_cnt = 0, enobufs_cnt = 0;
	uint16_t nb_rx, nb_rx_bulk;
	struct rte_mbuf *m[BURST_SIZE];
	struct rte_mbuf *n[BURST_SIZE];
	struct rte_mbuf *rp[BURST_SIZE];
	int rc[BURST_SIZE];

	/* Receive packets until we reach end on pcap file*/
	do {
		nb_rx = rte_eth_rx_burst(portid, 0, m, BURST_SIZE);
		pkt_cnt += nb_rx;

		for(i = 0; i < results.size(); i++) {
			memset(rc, 0, sizeof(int) * BURST_SIZE);
			nb_rx_bulk = tle_udp_rx_bulk(results[i].dev_ptr, m, rp, rc, nb_rx);
			for(j = 0; j < BURST_SIZE; j++) {
				if(rc[j] == ENOBUFS)
					enobufs_cnt++;
			}
			results[i].rx_dev+=nb_rx_bulk;
		}
	} while (nb_rx > 0);

	/*
	 * Verify results - number of rx packets per dev and stream.
	 * TODO: Verify number of dropped pkts and reason of drop?
	 */
	for(i = 0; i < results.size(); i++) {
		EXPECT_EQ(tp.devs[i].exp_pkts_bulk_rx, results[i].rx_dev);
		EXPECT_EQ(enobufs_cnt, pkt_cnt - results[i].rx_dev);
	}
}
INSTANTIATE_TEST_CASE_P(enobufs_test, tle_rx_enobufs, testing::Values(
	test_str
	{
		"IPv4 - 1 dev 1 stream, only correct pkts",
		{
			{"10.0.0.1", "2001::1000",
				RX_NO_OFFLOAD, TX_NO_OFFLOAD, CTX_MAX_RBUFS - 1, 0,
				{
					{10001, 10002, "10.0.0.1", "10.0.0.2", 0},
				}
			}
		},
		{
				{"10.0.0.2", "10.0.0.1", 10002, 10001, 1000, 0, 0, 0},
		}
	},
	test_str
	{
		"IPv4 - 1 dev 1 stream, only correct pkts",
		{
			{"10.0.0.1", "2001::1000",
				RX_NO_OFFLOAD, TX_NO_OFFLOAD, CTX_MAX_RBUFS - 1, 0,
				{
					{10001, 10002, "2001::1000", "2001::2000", 0},
				}
			}
		},
		{
				{"2001::2000", "2001::1000", 10002, 10001, 1000, 0, 0, 0},
		}
	}
));

TEST_P(test_tle_udp_stream_gen, test)
{
	int i, j;
	uint16_t nb_rx, nb_rx_bulk, nb_str_rx, enoent_cnt=0;

	struct rte_mbuf *m[BURST_SIZE];
	struct rte_mbuf *n[BURST_SIZE];
	struct rte_mbuf *rp[BURST_SIZE];
	int rc[BURST_SIZE];
	vector<int> enoent(results.size(), 0);

	/* Receive packets until we reach end on pcap file*/
	do {
		nb_rx = rte_eth_rx_burst(portid, 0, m, BURST_SIZE);

		for(i = 0; i < results.size(); i++) {
			memset(rc, 0, sizeof(int) * BURST_SIZE);
			nb_rx_bulk = tle_udp_rx_bulk(results[i].dev_ptr, m, rp, rc, nb_rx);
			for(j = 0; j < BURST_SIZE; j++) {
				if(rc[j] == ENOENT)
					enoent[i]++;
			}
			results[i].rx_dev+=nb_rx_bulk;

			for(j = 0; j < results[i].str_ptr.size(); j++) {
				nb_str_rx = tle_udp_stream_recv(results[i].str_ptr[j], n, BURST_SIZE);
				results[i].rx_str[j]+=nb_str_rx;
			}
		}
	} while (nb_rx > 0);

	/*
	 * Verify results - number of rx packets per dev and stream.
	 * TODO: Verify number of dropped pkts and reason of drop?
	 */
	for(i = 0; i < results.size(); i++) {
		EXPECT_EQ(tp.devs[i].exp_pkts_bulk_rx, results[i].rx_dev);
		EXPECT_EQ(tp.devs[i].exp_enoent, enoent[i]);
		for(j = 0; j < results[i].str_ptr.size(); j++) {
			EXPECT_EQ(tp.devs[i].streams[j].exp_pkts_rx, results[i].rx_str[j]);
		}
	}
}
/*
 * TODO: Obviously this way of defining test scenarios is terrible.
 * Need to move to JSON files in future and parse from external file.
 * Currently first commented out entry is an example of what values should be
 * inserted into certain fields
 * */
INSTANTIATE_TEST_CASE_P(rx_recv, test_tle_udp_stream_gen, testing::Values(
/* test_str example */
/* {
	"Description",
	{
		Device config below
		{"Dev local IPv4", "Dev local IPv6",
			RX_OFFLOAD, TX_OFFLOAD, Exp. nb. of rx pkts on device,
			Exp. nb. of total ENOENT pkts on device,
			{
				Streams config on device below
				{local port, remote port, "local ip", "remote ip",
				exp. nb. of pkts},
			}
		}
	},
	Pkts to generate with scapy to pcap file
	{
		{"Src IP", "Dst IP", Src port, Dst port, nb of pkts,
		l3 chksum, l4 chksum, fragment?},
	}
}, */
	test_str
	{
		"IPv4 - 1 dev 1 stream, only correct pkts",
		{
			{"10.0.0.1", "2001::1000",
				RX_NO_OFFLOAD, TX_NO_OFFLOAD, 10, 0,
				{
					{10001, 10002, "10.0.0.1", "10.0.0.2", 10},
				}
			}
		},
		{
				{"10.0.0.2", "10.0.0.1", 10002, 10001, 10, 0, 0, 0},
		}
	},

	test_str
	{
		"IPv4 - 1 dev 1 stream, only incorrect pkts",
		{
			{"10.0.0.1", "2001::1000",
				RX_NO_OFFLOAD, TX_NO_OFFLOAD, 0, 40,
				{
					{10001, 10002, "10.0.0.1", "10.0.0.2", 0},
				}
			}
		},
		{
				{"20.0.0.2", "10.0.0.1", 10002, 10001, 10, 0, 0, 0},
				{"10.0.0.2", "20.0.0.1", 10002, 10001, 10, 0, 0, 0},
				{"10.0.0.2", "10.0.0.1", 20002, 10001, 10, 0, 0, 0},
				{"10.0.0.2", "10.0.0.1", 10002, 20001, 10, 0, 0, 0},
		}
	},

	test_str
	{
		"IPv4 - 1 dev with 1 stream, only correct pkts but incorrect chksum",
		{
			{"10.0.0.1", "fe80::2500",
				RX_NO_OFFLOAD, TX_NO_OFFLOAD, 30, 0,
				{
					{10001, 10002, "10.0.0.1", "10.0.0.2", 0},
				}
			}
		},
		{
				{"10.0.0.2", "10.0.0.1", 10002, 10001, 10, 1, 0, 0},
				{"10.0.0.2", "10.0.0.1", 10002, 10001, 10, 0, 1, 0},
				{"10.0.0.2", "10.0.0.1", 10002, 10001, 10, 1, 1, 0},
		}
	},

	test_str
	{
		"IPv6 - 1 dev with 1 stream, only correct pkts",
		{
			{"10.0.0.1", "2001::1000",
				RX_NO_OFFLOAD, TX_NO_OFFLOAD, 10, 0,
				{
					{10001, 10002, "2001::1000", "2001::2000", 10},
				}
			}
		},
		{
				{"2001::2000", "2001::1000", 10002, 10001, 10, 0, 0, 0},
		}
	},

	test_str
	{
		"IPv6 - 1 dev with 1 stream, only incorrect pkts",
		{
			{"10.0.0.1", "2001::1000",
				RX_NO_OFFLOAD, TX_NO_OFFLOAD, 0, 40,
				{
					{10001, 10002, "2001::1000", "2001::2000", 0},
				}
			}
		},
		{
				{"3001::2000", "2001::1000", 10002, 10001, 10, 0, 0, 0},
				{"2001::3000", "2001::1000", 10002, 10001, 10, 0, 0, 0},
				{"2001::2000", "2001::1000", 30002, 10001, 10, 0, 0, 0},
				{"2001::2000", "2001::1000", 10002, 30001, 10, 0, 0, 0},
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
			{"10.0.0.1", "2001::1000",
				RX_NO_OFFLOAD, TX_NO_OFFLOAD, 30, 0,
				{
					{10001, 10002, "2001::1000", "2001::2000", 10},
				}
			}
		},
		{
				{"2001::2000", "2001::1000", 10002, 10001, 10, 1, 0, 0},
				{"2001::2000", "2001::1000", 10002, 10001, 10, 0, 1, 0},
				{"2001::2000", "2001::1000", 10002, 10001, 10, 1, 1, 0},
		}
	},

	test_str
	{
		/* Multiple streams, multiple correct pkt streams, mixed IPv4 & IPv6;
		 * 3 dev, 3 stream per dev, only correct pkts */
		"Mixed IPv4+IPv6; Multiple devs with multiple correct streams",
		{
			{"10.0.0.1", "2001::1000",
				RX_NO_OFFLOAD, TX_NO_OFFLOAD, 300, 600,
				{
						{10001, 10011, "10.0.0.1", "10.0.0.2", 100},
						{10002, 10012, "10.0.0.1", "10.0.0.3", 100},
						{10003, 10013, "2001::1000", "2001::4000", 100}
				}
			},
			{"20.0.0.1", "2002::1000",
				RX_NO_OFFLOAD, TX_NO_OFFLOAD, 300, 600,
				{
						{20001, 20011, "20.0.0.1", "20.0.0.2", 100},
						{20002, 20012, "2002::1000", "2002::3000", 100},
						{20003, 20013, "2002::1000", "2002::4000", 100}
				}
			},
			{"30.0.0.1", "2003::1000",
				RX_NO_OFFLOAD, TX_NO_OFFLOAD, 300, 600,
				{
						{20001, 20011, "30.0.0.1", "30.0.0.2", 100},
						{20002, 20012, "2003::1000", "2003::3000", 100},
						{20003, 20013, "2003::1000", "2003::4000", 100}
				}
			},
		},
		{
				{"10.0.0.2", "10.0.0.1", 10011, 10001, 100, 0, 0, 0},
				{"10.0.0.3", "10.0.0.1", 10012, 10002, 100, 0, 0, 0},
				{"20.0.0.2", "20.0.0.1", 20011, 20001, 100, 0, 0, 0},
				{"30.0.0.2", "30.0.0.1", 20011, 20001, 100, 0, 0, 0},
				{"2001::4000", "2001::1000", 10013, 10003, 100, 0, 0, 0},
				{"2002::3000", "2002::1000", 20012, 20002, 100, 0, 0, 0},
				{"2002::4000", "2002::1000", 20013, 20003, 100, 0, 0, 0},
				{"2003::3000", "2003::1000", 20012, 20002, 100, 0, 0, 0},
				{"2003::4000", "2003::1000", 20013, 20003, 100, 0, 0, 0},
		}
	}
));

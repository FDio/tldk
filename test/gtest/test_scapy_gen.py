# Copyright (c) 2016 Intel Corporation.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
from socket import inet_pton
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.layers.inet import UDP
from random import shuffle

src_mac = "00:00:00:00:de:ad"
dst_mac = "00:00:de:ad:be:ef"
eth_hdr_len = len(Ether())
ip_hdr_len = len(IP())
ipv6_hdr_len = len(IPv6())
udp_hdr_len = len(UDP())
udpv4_hdr_len = eth_hdr_len + ip_hdr_len + udp_hdr_len
udpv6_hdr_len = eth_hdr_len + ipv6_hdr_len + udp_hdr_len


def write_pkts(pkts, pcap_path):
    try:
        pktdump = PcapWriter(pcap_path, append=False, sync=True)
        pktdump.write(pkts)
    except IOError:
        pass


def read_pkts(pcap_path):
    try:
        pkts_ref = PcapReader(pcap_path)
        pkts = pkts_ref.read_all()
        return list(pkts)
    except IOError:
        pkts = []
        return pkts


def main():
    parser = argparse.ArgumentParser(description="Generate packets for"
                                                 "TLDK rx/tx tests")
    parser.add_argument("l_ip")
    parser.add_argument("r_ip")
    parser.add_argument("l_port", type=int)
    parser.add_argument("r_port", type=int)
    parser.add_argument("nb_pkts", type=int)
    parser.add_argument("file")
    parser.add_argument("-bc3", "--bad_chksum_l3", default=None, type=int)
    parser.add_argument("-bc4", "--bad_chksum_l4", default=None, type=int)
    parser.add_argument("-f", "--fragment")
    parser.add_argument("-r", "--rand-pkt-size")

    args = parser.parse_args()

    ip_ver = ""
    try:
        inet_pton(socket.AF_INET, args.l_ip)
        ip_ver = "ipv4"
    except socket.error:
        ip_ver = "ipv6"

    pkts = read_pkts(args.file)

    if "ipv4" in ip_ver:
        for i in range(0, args.nb_pkts):
            pkt = Ether(dst=dst_mac, src=src_mac) /\
                  IP(src=args.l_ip, dst=args.r_ip, frag=0, chksum=args.bad_chksum_l3) /\
                  UDP(sport=args.l_port, dport=args.r_port, chksum=args.bad_chksum_l4) /\
                  Raw(RandString(size=(100 - udpv4_hdr_len)))
            pkts.append(pkt)
    else:
        for i in range(0, args.nb_pkts):
            pkt = Ether(dst=dst_mac, src=src_mac) /\
                        IPv6(src=args.l_ip, dst=args.r_ip) /\
                        UDP(sport=args.l_port, dport=args.r_port, chksum=args.bad_chksum_l4) / \
                        Raw(RandString(size=(100 - udpv6_hdr_len)))
            pkts.append(pkt)

    shuffle(pkts)
    write_pkts(pkts, args.file)

main()

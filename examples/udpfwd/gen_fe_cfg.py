#!/usr/bin/env python
#
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
#
#
# generate FE config script
#

import sys, optparse, math

def print_usage ():
	print "Usage: " + sys.argv[0] + " [-f fe_lcore_list] [-b be_lcore_list]"
	print "          [-p start_port] [-n number_of_streams]"
	print "          [-m mode] [-q local_address] [-r remote_address]"
	print "          [-s fwd_local_address] [-t fwd_remote_address]"
	print "          [-l txlen] [-4/-6] [-H]"
	print
	print "Options"
	print "   -f, --fe_lcore_list: list of lcores used for FE. Multiple " \
			"lcores are comma-separated, within double quote"
	print "   -b, --be_lcore_list: list of lcores used for BE. Multiple " \
			"lcores are comma-separated, within double quote"
	print "   -p, --start_port: starting UDP port number"
	print "   -n, --number_of_streams: number of streams to be generated"
	print "   -m, --mode: mode of the application. [echo, rx, tx, fwd]"
	print "   -q, --local_address: local address of the stream"
	print "   -r, --remote_address: remote address of the stream"
	print "   -s, --fwd_local_address: forwarding local address of the stream"
	print "   -t, --fwd_remote_address: forwarding remote address of the " \
			"stream"
	print "   -l, --txlen: transmission length for rx/tx mode"
	print "   -H: if port number to printed in hex format"
	print "   -4/-6: if default ip addresses to be printed in ipv4/ipv6 format"

def align_power_of_2(x):
	return 2**(x-1).bit_length()

def print_stream(mode, la, ra, fwd_la, fwd_ra, lcore, belcore, lport,
		fwrport, txlen):
	if support_hex != 0:
		lport_str = str(format(lport, '#x'))
		fwrport_str = str(format(fwrport, '#x'))
	else:
		lport_str = str(lport)
		fwrport_str = str(fwrport)

	stream = "lcore=" + str(lcore) + ",belcore=" + str(belcore) + ",op=" + mode
	stream += ",laddr=" + la + ",lport=" + lport_str
	stream += ",raddr=" + ra + ",rport=0"

	if mode == 'fwd':
		stream += ",fwladdr=" + fwd_la + ",fwlport=0,fwraddr=" + fwd_ra
		stream += ",fwrport=" + fwrport_str

	if mode == 'rx' or mode == 'tx':
		stream += ",txlen=" + str(txlen)

	print stream

parser = optparse.OptionParser()
parser.add_option("-b", "--be_lcore_list", dest = "be_lcore_list",
	help = "BE lcore lists.")
parser.add_option("-f", "--fe_lcore_list", dest = "fe_lcore_list",
	help = "FE lcore lists.")
parser.add_option("-p", "--start_port", dest = "start_port",
	help = "start port.")
parser.add_option("-n", "--number_of_streams", dest = "number_of_streams",
	help = "number of streams.")
parser.add_option("-m", "--mode", dest = "mode",
	help = "mode (op, rx, tx, fwd).")
parser.add_option("-q", "--local_address", dest = "local_address",
	help = "local_address.")
parser.add_option("-r", "--remote_address", dest = "remote_address",
	help = "remote_address.")
parser.add_option("-s", "--fwd_local_address", dest = "fwd_local_address",
	help = "fwd_local_address.")
parser.add_option("-t", "--fwd_remote_address", dest = "fwd_remote_address",
	help = "fwd_remote_address.")
parser.add_option("-l", "--txlen", dest = "txlen", help = "txlen.")
parser.add_option("-4", action = "store_false", dest = "ipv6",
	help = "IPv4/IPv6")
parser.add_option("-6", action = "store_true", dest = "ipv6",
	help = "IPv4/IPv6")
parser.add_option("-H", action = "store_true", dest = "support_hex",
	help = "print ports in hexa format")

(options, args) = parser.parse_args()

if len(sys.argv) == 1:
	print
	print_usage()
	print
	sys.exit()

supported_modes = ['echo', 'rx', 'tx', 'fwd']
support_hex = 0
txlen = 72

if options.ipv6 == True:
	la = '::'
	ra = '::'
	fwd_la = '::'
	fwd_ra = '::'
else:
	la = '0.0.0.0'
	ra = '0.0.0.0'
	fwd_la = '0.0.0.0'
	fwd_ra = '0.0.0.0'

if options.support_hex == True:
	support_hex = 1

if options.txlen != None:
	txlen = options.txlen

if options.fe_lcore_list != None:
	felcore_list = list(map(int, options.fe_lcore_list.split(",")))
	felcore_list.sort()
else:
	felcore_list = []

if options.be_lcore_list != None:
	belcore_list = list(map(int, options.be_lcore_list.split(",")))
	belcore_list.sort()
else:
	print "default BE lcore list = [ 1 ]"
	belcore_list = [1]

if options.mode != None:
	mode = options.mode
	if mode not in supported_modes:
		print "Supported modes: " + str(supported_modes)
		print "Provided mode \"" + mode + "\" is not supported. Terminating..."
		sys.exit()
else:
	print "default mode = echo"
	mode = "echo"

if options.start_port != None:
	start_port = int(options.start_port)
else:
	print "default start_port = 32768"
	start_port = 32768

if options.number_of_streams != None:
	number_of_streams = int(options.number_of_streams)
else:
	print "default number_of_streams = 1"
	number_of_streams = 1

fwd_start_port = 53248

if options.local_address != None:
	la = options.local_address

if options.remote_address != None:
	ra = options.remote_address

if options.fwd_local_address != None:
	fwd_la = options.fwd_local_address

if options.fwd_remote_address != None:
	fwd_ra = options.fwd_remote_address

belcore_count = len(belcore_list)
align_belcore_count = align_power_of_2(belcore_count)
nb_bits = int(math.log(align_belcore_count, 2))

felcore_count = len(felcore_list)
if felcore_count != 0:
	if number_of_streams % felcore_count == 0:
		nb_stream_per_flc = number_of_streams / felcore_count
	else:
		nb_stream_per_flc = (number_of_streams / felcore_count) + 1

for i in range(start_port, start_port + number_of_streams):
	k = i - start_port
	align_belcore_count = align_power_of_2(belcore_count)
	blc_indx = (i % align_belcore_count) % belcore_count
	belcore = belcore_list[blc_indx]
	if felcore_count != 0:
		flc_indx = k / nb_stream_per_flc
		felcore = felcore_list[flc_indx]
	else:
		felcore = belcore

	print_stream(mode, la, ra, fwd_la, fwd_ra, felcore, belcore, i,
		fwd_start_port + k, txlen)

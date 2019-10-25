#! /bin/bash

# readme section---------------------------------------------------------------

# usage: /bin/bash run_test.sh [-46lrh]
#
# Run all tests using nctxrx.sh. Report stored and printed
# after tests were done. For details about options run
# script with -h (help)
#
# User needs to specify following environment variables:
#  ETH_DEV	- ethernet device to be used on SUT by DPDK
#  REMOTE_HOST	- ip/hostname of DUT
#  REMOTE_IFACE	- interface name for the test-port on DUT
#  L4FWD_PATH	- path to l4fwd app binary
# Optional envirenment variables:
#  L4FWD_FECORE	- core on which l4fwd frontend should run
#  L4FWD_BECORE	- core on which l4fwd backend should run

# options which can be changed by user-----------------------------------------

# general settings
TCP_PORT=6000
LOCAL_IPV4=192.168.1.60
LOCAL_IPV6=fd12:3456:789a:0001:0000:0000:0000:0060

# reorder settings
reorder_min=0
reorder_max=15
reorder_step=3

# loss settings
loss_min=0
loss_max=30
loss_step=10

# file for results storage
DIR=`dirname $0`
result=${DIR}/result.out
echo -e "Test\t\tProtocol\tFile\t\tStatus\tTime" > ${result}

# how many times test file should be send during tests
nb=3

# variables used by script-----------------------------------------------------

# option parsing variables
run_loss=1
run_reorder=1
use_ip4=0
use_ip6=0

# track number of tests which have failed
error_count=0

# functions and calls----------------------------------------------------------

usage()
{
	echo -e "USAGE:\t$0 -[lrf46]"
	echo -e "\t\t-l Perform loss tests only"
	echo -e "\t\t-r Perform reorder tests only"
	echo -e "\t\t-4 Use IPv4/TCP"
	echo -e "\t\t-6 Use IPv6/TCP"
	echo -e "\t\t-h Display this help"
	echo -e "INFO:\tIf [l/r] not specified, all tests will be invoked"
	echo -e "\tOptions [4/6] may be used together."
}

while getopts ":ilr46h" opt
do
	case $opt in
		l)
			run_reorder=0
			run_loss=1
			;;
		r)
			run_reorder=1
			run_loss=0
			;;
		4)
			use_ip4=1
			;;
		6)
			use_ip6=1
			;;
		h)
			usage
			exit 0
			;;
		?)
			echo "Invalid option"
			usage
			exit 127
			;;
	esac
done

# add intermediary data into result file
gather_data()
{
	test_case=$1
	test_value=$2
	protocol=$3

	length=$(expr length "${test_case} ${test_value}")
	if [[ ${length} -lt 8 ]]
	then
		tab="\t\t"
	else
		tab="\t"
	fi

	# add protocol used in test case which was invoked
	sed -i "s_.*_${protocol}\t\t&_" ${result}.tmp
	# add description of test case which was invoked (in first line)
	sed -i "1 s_.*_${test_case} ${test_value}${tab}&_" ${result}.tmp
	# add blank space to be aligned with first row
	sed -i "1 ! s_.*_\t\t&_" ${result}.tmp
	# add empty line befor each major test case
	sed -i "1 s_.*_\n&_" ${result}.tmp
	cat ${result}.tmp >> ${result}
	rm -f ${result}.tmp
}

# check if IP protocol was specified
if [[ ${use_ip4} -eq 0 && ${use_ip6} -eq 0 ]]
then
	echo "Error: No IP protocol specified"
	usage
	exit 127
fi

# run all tests
while [[ ${use_ip4} -ne 0 || ${use_ip6} -ne 0 ]]
do
	#set protocol to be used in this round of tests
	if [[ ${use_ip4} -eq 1 ]]
	then
		proto="ipv4"
	elif [[ ${use_ip6} -eq 1 ]]
	then
		proto="ipv6"
	fi

	# check if reorder tests should be run
	if [[ ${run_reorder} -eq 1 ]]
	then
		# run test for all specified reorder values
		for reorder in $(seq ${reorder_min} \
				${reorder_step} \
				${reorder_max})
		do
			/bin/bash ${DIR}/nctxrx.sh \
				-i ${proto} \
				-a ${LOCAL_IPV4} \
				-p ${TCP_PORT} \
				-n ${nb} \
				-r ${reorder} \
				-o ${result}.tmp \
				-v

			# check test status
			st=$?
			if [[ ${st} -eq 0 ]]
			then
				echo -e "\nTests for reorder: ${reorder}\t[OK]"
			else
				echo -e "\nTests for reorder: $reorder}\t[FAIL]"
				error_count=$(expr ${error_count} + 1)
			fi

			# gather results
			gather_data "Reorder" ${reorder} ${proto}

		done
	fi

	# check if loss tests should be run
	if [[ ${run_loss} -eq 1 ]]
	then
		# run test for all specified reorder values
		for loss in $(seq ${loss_min} ${loss_step} ${loss_max})
		do
			/bin/bash ${DIR}/nctxrx.sh \
				-i ${proto} \
				-a ${LOCAL_IPV4} \
				-p ${TCP_PORT} \
				-n ${nb} \
				-l ${loss} \
				-o ${result}.tmp \
				-v

			# check test status
			st=$?
			if [[ ${st} -eq 0 ]]
			then
				echo -e "\nTests for loss: ${loss}\t[OK]"
			else
				echo -e "\nTests for loss: ${loss}\t[FAIL]"
				error_count=$(expr ${error_count} + 1)

			fi

			# gather results
			gather_data "Loss" ${loss} ${proto}
		done
	fi

	# mark that tests were done for one of the protocols
	if [[ ${use_ip4} -eq 1 ]]
	then
		use_ip4=0
	elif [[ ${use_ip6} -eq 1 ]]
	then
		use_ip6=0
	fi
done

if [[ ${error_count} -eq 0 ]]
then
	echo -e "\nAll tests have ended successfully"
else
	echo -e "\n${error_count} tests have failed"
fi

# print report after all tests were done
echo -e "Report\n"
cat ${result}

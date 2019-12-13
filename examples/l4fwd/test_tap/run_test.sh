#! /bin/bash

# readme section---------------------------------------------------------------

# usage: /bin/bash run_test.sh [-46alrh]
#
# Run all tests using nctxrx.sh. Report stored and printed
# after tests were done. For details about options run
# script with -h (help)
#
# User needs to specify following environment variables:
#  L4FWD_PATH	- path to l4fwd app binary
# Optional envirenment variables:
#  L4FWD_FECORE	- core on which l4fwd frontend should run
#  L4FWD_BECORE	- core on which l4fwd backend should run

# options which can be changed by user-----------------------------------------

# reorder settings
reorder_min=4
reorder_max=9
reorder_step=5

# loss settings
loss_min=0
loss_max=20
loss_step=20

# file for results storage
DIR=$(dirname $0)
result=${DIR}/result.out
echo -e "Test\t\tProtocol\tFile\t\t\tStatus\tTime" > ${result}

# how many times test file should be send during tests
nb=3

# variables used by script-----------------------------------------------------

# option parsing variables
run_loss=0
run_reorder=0
use_ip4=0
use_ip6=0

# track number of tests which have failed
error_count=0

SECONDS=0

# functions and calls----------------------------------------------------------

usage()
{
	echo -e "Usage:"
	echo -e "\t$0 [-alr46h]"
	echo -e "Options:"
	echo -e "\t-a Run all tests"
	echo -e "\t-l Perform loss tests"
	echo -e "\t-r Perform reorder tests"
	echo -e "\t-4 Use IPv4/TCP"
	echo -e "\t-6 Use IPv6/TCP"
	echo -e "\t-h Display this help"
	echo -e "Info:"
	echo -e "\tOptions [4/6] may be used together."
}

while getopts ":alr46h" opt
do
	case $opt in
		a)
			run_loss=1
			run_reorder=1
			;;
		l)
			run_loss=1
			;;
		r)
			run_reorder=1
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

# check if tests to perform are specified
if [[ ${run_loss} -eq 0 && ${run_reorder} -eq 0 ]]
then
	echo -e "Error: No tests specified\n"
	usage
	exit 127
fi

# check if IP protocol was specified
if [[ ${use_ip4} -eq 0 && ${use_ip6} -eq 0 ]]
then
	echo -e "Error: No IP protocol specified\n"
	usage
	exit 127
fi

# get number of tests to perform
if [[ ${run_reorder} -eq 1 ]]
then
	nb_of_reorder=$(( $(( ${reorder_max} - ${reorder_min} )) \
		/ ${reorder_step} + 1 ))
else
	nb_of_reorder=0
fi

if [[ ${run_loss} -eq 1 ]]
then
	nb_of_loss=$(( $(( ${loss_max} - ${loss_min} )) / ${loss_step} + 1 ))
else
	nb_of_loss=0
fi

if [[ ${use_ip4} -eq 1 && ${use_ip6} -eq 1 ]]
then
	multiply=2
else
	multiply=1
fi

nb_of_tests=$(( $(( ${nb_of_loss} + ${nb_of_reorder} )) * ${multiply} ))
tests_performed=0

echo "Number of tests to run: ${nb_of_tests}"

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
				-p ${proto} \
				-n ${nb} \
				-r ${reorder} \
				-o ${result}.tmp \
				-v

			# check test status
			st=$?
			if [[ ${st} -eq 0 ]]
			then
				echo -e "\nTest for reorder: ${reorder}\t[OK]"
			else
				echo -e "\nTest for reorder: ${reorder}\t[FAIL]"
				error_count=$(expr ${error_count} + 1)
			fi

			# gather results
			gather_data "Reorder" ${reorder} ${proto}
			tests_performed=$(( ${tests_performed} + 1 ))
			echo -e "\n[PROGRESS] ${tests_performed} out of \
${nb_of_tests} done\n"
		done
	fi

	# check if loss tests should be run
	if [[ ${run_loss} -eq 1 ]]
	then
		# run test for all specified reorder values
		for loss in $(seq ${loss_min} ${loss_step} ${loss_max})
		do
			/bin/bash ${DIR}/nctxrx.sh \
				-p ${proto} \
				-n ${nb} \
				-l ${loss} \
				-o ${result}.tmp \
				-v

			# check test status
			st=$?
			if [[ ${st} -eq 0 ]]
			then
				echo -e "\nTest for loss: ${loss}\t[OK]"
			else
				echo -e "\nTest for loss: ${loss}\t[FAIL]"
				error_count=$(expr ${error_count} + 1)
			fi

			# gather results
			gather_data "Loss" ${loss} ${proto}
			tests_performed=$(( ${tests_performed} + 1 ))
			echo -e "\n[PROGRESS] ${tests_performed} out of \
${nb_of_tests} done\n"
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
	echo -e "\nAll tests have ended successfully" >> ${result}
else
	echo -e "\n${error_count} tests have failed" >> ${result}
fi

if [[ $SECONDS -gt 60 ]]
then
	let "minutes=SECONDS/60"
	let "seconds=SECONDS%60"
	echo "All tests completed in $minutes minute(s) and $seconds second(s)"\
		>> ${result}
else
	echo "All tests completed in $SECONDS second(s)" >> ${result}
fi

# print report after all tests were done
echo -e "Report:\n"
cat ${result}

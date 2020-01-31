#! /bin/bash

# readme section---------------------------------------------------------------

# usage: /bin/bash nctxrx.sh [-ifnpalrdovh]
#
# Run specific test setup based on options. For details about options run
# script with -h (help)
#
# User needs to specify following environment variables:
#  L4FWD_PATH	- path to l4fwd app binary
#  ETH_DEV	- for real NIC usage - ethernet device to be used on SUT by DPDK
#		- for tap interface - tap
#
# User needs to set following enviroment variables in case of real NIC usage:
#  REMOTE_HOST	- ip/hostname of DUT
#  REMOTE_IFACE	- interface name for the test-port on DUT
#  LOCAL_MAC	- MAC address used by DPDK
#
# Optional envirenment variables:
#  L4FWD_FECORE	- core on which l4fwd frontend should run
#  L4FWD_BECORE	- core on which l4fwd backend should run
#
# The purpose of the script is to automate validation tests for l4fwd app where
# packets are out of order/lost. Script is operating on local linux machine only
# or on local and remote machine (depending on enviroment variables).
#
# For local machine only, l4fwd application is being run by the script, which
# sets up the tap interface. Created interface is serving a connection for l4fwd
# and netcat within the same OS.
#
# For local/remote linux machine mode, script uses real NIC specified in
# enviroment variable. Connection with remote machine is made via ssh. L4fwd app
# is being run on local machine, while interface and netcat are being set on
# remote side (operated by linux).
#
# Netcat is used to send test data via TCP to l4fwd, which is set to echo mode
# (sends back the same data). Depending on test specified, TCP segments are
# artificially changed inside sending buffer, so they are lost in some
# percentage or sent out of order. Report is printed after all tests were
# performed.
#
# Example of traffic visualisation
# Netcat(TAP/NIC) --(TCP out of order)--> (TAP/NIC)L4FWD(TAP/NIC) --
#	--(TCP with correct order)--> (TAP/NIC)Netcat(validation)

# options which can be changed by the user if needed---------------------------

# timeout in [s] for calling nc (in case traffic stuck)
timeout=600

# delay for netem (20 [ms] is default value when reorder option used)
delay=0

# default loss of packets [%] value
loss=0

# default probability [%] of not loosing burst of packets
loss_burst=80

# variables used by script-----------------------------------------------------

# temp files to remove at the end
rmxf=""
rmresults=""

# specify if <tc qdisc ... netem ...> instruction should be invoked
set_netem=0

# flag to check if default files should to be used (default 1)
# default files are generated with urandom
default_file=1

# IP protocol version
ipv4=0
ipv6=0

# default result file
local_result_file=$(dirname $0)/results.out

# should verbose mode be used
verbose=0

# netcat option for using IPv6, initially empty
nc_ipv6=""

# functions--------------------------------------------------------------------

usage_internal()
{
	echo -e "Usage:"
	echo -e "\t$0 [-vh] [-p protocol] [-f test_file] [-n number] \
[-l loss] [-r gap] [-d delay] [-o result_file]"
	echo -e "Options:"
	echo -e "\t-p <protocol>\t\tSet IP protocol to use."
	echo -e "\t\t\t\tAcceptable values: ipv4/ipv6."
	echo -e "\n\t-f <test_file>\t\tChoose a file to be sent during tests \
(full path to file on remote machine)."
	echo -e "\t\t\t\tNot specified will perform tests on default files."
	echo -e "\n\t-n <number>\t\tChoose how many times send the test file."
	echo -e "\t\t\t\tFiles will be send simultaneously by opening \
new netcat connection."
	echo -e "\n\t-l <loss>\t\tSet average loss of packets in %."
	echo -e "\t\t\t\tEg. loss=10 means 10% of packets will be lost."
	echo -e "\n\t-r <gap>\t\tSet gap for packets to be reordered."
	echo -e "\t\t\t\tEg. gap=5 means every 5'th packet will be reordered."
	echo -e "\t\t\t\tIf delay is not set as well, default value of 10ms \
will be used."
	echo -e "\n\t-d <delay>\t\tSet delay for packet sending in ms."
	echo -e "\n\t-o <result_file>\tUser specified file to which results \
should be stored."
	echo -e "\t\t\t\tDefault file is ${local_result_file}"
	echo -e "\n\t-v\t\t\tVerbose mode - prints additional output."
	echo -e "\n\t-h\t\t\tDisplay this help."
}

# parse options and arguments
while getopts ":f:n:p:l:r:d:o:vh" opt
do
	case $opt in
		p)
			ipv=$OPTARG
			if [[ ${ipv} == "ipv4" ]]
			then
				ipv4=1
			elif [[ ${ipv} == "ipv6" ]]
			then
				ipv6=1
				nc_ipv6="-6"
			else
				echo "No IP protocol specified"
				usage_internal
				exit 127
			fi
			;;
		f)
			file=$OPTARG
			default_file=0
			;;
		n)
			num=$OPTARG
			;;
		l)
			set_netem=1
			loss=$OPTARG
			;;
		r)
			set_netem=1
			reorder=$OPTARG
			;;
		d)
			set_netem=1
			delay=$OPTARG
			;;
		o)
			local_result_file=$OPTARG
			;;
		v)
			verbose=1
			;;
		h)
			usage_internal
			exit 0
			;;
		?)
			echo "Invalid option"
			usage_internal
			exit 127
			;;
	esac
done

# load configuration
. $(dirname $0)/config.sh

# send file with results to local machine when in real NIC mode
send_results()
{
	if_verbose echo -e "Sending result file to local"
	scp ${scp_suppress} ${REMOTE_HOST}:${REMOTE_RESDIR}/results.out \
		${local_result_file}
	ssh ${REMOTE_HOST} rm -f ${REMOTE_RESDIR}/results.out
}

# test setup
run_test()
{
	of=$1
	# visual break of the output
	if_verbose echo -e "\nRunning netcat"

	pids=""
	i=0
	while [ $i -lt $num ]
	do
		# save command for nc in 'cmd'
		# time -> meassure time of execution for netcat
		# -q 0 -> wait 0 seconds after EOF and quit
		# timeout to deal with hanging connection when sth went wrong
		# feed netcat with {of} file to send
		# receiving end is redirected to out/...out file
		# 'exec' for redirecting nc err output to not mess result
		cmd="exec 4>&2
\$({ time timeout ${timeout} nc ${nc_ipv6} -q 0 ${nc_addr} ${TCP_PORT} \
	< ${REMOTE_DIR}/${of} \
	> ${REMOTE_OUTDIR}/${of}.out.${i} 2>&4; } \
	2>${REMOTE_RESDIR}/${of}.result.${i} )
exec 4>&-"

		# create temporary file for nc command to execute
		xf=$(use_ssh mktemp -p ${REMOTE_DIR})

		# store command from {cmd} into temporaty file
		if [[ ${USE_TAP} -eq 0 ]]
		then
			echo "${cmd}" | ssh ${REMOTE_HOST} "cat > ${xf}"
		else
			echo "${cmd}" | cat > ${xf}
		fi

		# execute nc command in the background
		use_ssh /bin/bash ${xf} &

		pids="${pids} $!"

		# adds tempfiles to list to remove later
		rmxf="${rmxf} ${xf}"
		rmresults="${rmresults} ${REMOTE_RESDIR}/${of}.result.${i}"

		i=$(expr $i + 1)
	done

	# sleep for 1 sec
	sleep 1

	# wait until previous commands finish (nc commands)
	wait ${pids}

	# remove temporary files
	use_ssh rm -f ${rmxf}

	# visual break
	if_verbose echo -e "\nNetstat:"

	# prints network information for given {TCP_PORT} number
	# -n -> show numeric addresses
	# -a -> show all (both listening and non-listening sockets)
	if_verbose use_ssh netstat -na | grep ${TCP_PORT}

	# visual break
	if_verbose echo -e "\nJobs:"

	# display status of jobs in the current session (this bash script)
	if_verbose use_ssh jobs -l

	# visual break
	if_verbose echo -e "\nNetcat processes:"

	# display current processes for netcat
	# -e -> show all processes
	# -f -> do full format listing (more info)
	# grep -v -> get rid of the following word match from grep output
	if_verbose use_ssh ps -ef | grep "nc " | grep -v grep

	# visual break
	if_verbose echo -e "\nRunning validation"

	flag_error=0
	i=0
	while [[ ${i} -lt ${num} ]]
	do
		# prints checksum of sent and received file
		if_verbose use_ssh cksum ${REMOTE_DIR}/${of} \
			${REMOTE_OUTDIR}/${of}.out.${i}

		# compares sent and received files if they match
		# compare {of} and {out/of.out.i} line by line
		use_ssh diff ${REMOTE_DIR}/${of} ${REMOTE_OUTDIR}/${of}.out.${i}

		# capture the result of diff command above
		rc=$?

		# update results file
		update_results ${of} ${rc} ${i}

		# check if result of diff is 0
		# equals 0 -> files are the same
		# not 0 -> files differ in some way -> report Error and exit
		#		with no execution of the rest of the script
		if [ ${rc} -ne 0 ]
		then
			echo -e "TEST FAILED - ${of}"
			echo "ERROR: files ${of} ${of}.out.${i} differ"

			# mark that there was an error
			flag_error=${rc}
		fi

		# remove received file from out/ directory
		use_ssh rm -f ${REMOTE_OUTDIR}/${of}.out.${i}

		i=$(expr $i + 1)
	done

	# remove temporary results
	use_ssh rm -f ${rmresults}

	if [[ flag_error -ne 0 ]]
	then
		return ${flag_error}
	fi

	if_verbose echo ""
	echo -e "TEST SUCCESSFUL - ${of}"
	if_verbose echo ""

	return 0
}

# clean up after error or end of tests
cleanup()
{
	if [[ ${USE_TAP} -eq 0 ]]
	then
		send_results
	fi
	restore_netem
	l4fwd_stop
	remove_directories
}

# script start-----------------------------------------------------------------

# start l4fwd app
l4fwd_start

#configure configure tap interfaces
configure_interfaces

# check if default files should be used
if [[ ${default_file} -eq 0 ]]
then
	if_verbose echo -e "Sending test file to remote"
	if [[ ${USE_TAP} -eq 0 ]]
	then
		scp ${scp_suppress} ${file} ${REMOTE_HOST}:${REMOTE_DIR}
	fi
	run_test ${file}

	# check test outcome
	ret=$?
	if [[ ${ret} -ne 0 ]]
	then
		cleanup
		exit ${ret}
	fi
	use_ssh rm -f ${REMOTE_DIR}/${file}
else
	# use default files with size 8MB
	for size in 8
	do
		# generate file
		if_verbose echo -e "\nGenerating ${size}MB file for test"
		x=$(use_ssh mktemp $(basename $0).${size}MB.XXX \
			-p ${REMOTE_DIR})

		use_ssh dd if=/dev/urandom of=${x} bs=1M \
				count=${size} ${dd_suppress}

		# run test over generated file
		run_test $(basename ${x})

		# check test outcome
		ret=$?
		if [[ ${ret} -ne 0 ]]
		then
			cleanup
			exit ${ret}
		fi

		# remove generated file only if test successful
		use_ssh rm -f ${x}
	done
fi

cleanup
exit 0

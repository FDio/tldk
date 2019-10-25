#! /bin/bash

# readme section---------------------------------------------------------------

# usage: /bin/bash nctxrx.sh [-ifnpalrdovh]
#
# Run specific test setup based on options. For details about options run
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
#
# The purpose of the script is to automate validation tests for l4fwd app
# where packets are out of order/lost. It expects l4fwd application being
# run on local linux system (SUT). Script is oparating on remote linux
# machine (DUT) with use of ssh. SUT and DUT are connected via NIC. On SUT
# network traffic is managed by DPDK and on DUT by linux. On DUT netcat is
# used to send test data via TCP to TLDK on SUT, which is set to echo mode
# (sends back the same data). Depending on test specified, TCP segments are
# artificially changed in sending buffer of DUT, so they are lost in some
# percentage or sent out of order. If specified, report is sent from DUT
# to SUT after all tests were performed.
#
# Example traffic visualisation:
# DUT --(TCP out of order)--> SUT --(TCP with correct order)--> DUT(validation)

# options which can be changed by the user if needed---------------------------

# timeout in [s] for calling nc (in case traffic stuck)
timeout=600

# delay for netem (10 [ms] is default value when reorder option used)
delay=10

# default loss of packets [%] value
loss=0

# variables used by script-----------------------------------------------------

# temp files to remove at the end
rmxf=""
rmresults=""

# specify if <tc qdisc ... netem ...> instruction should be invoked
set_netem=0

# flag to check if default files should to be used (default 1)
# default files are generated with urandom (couple of sizes)
default_file=1

# IP protocol version
ipv4=0
ipv6=0

# should results be redirected
redirect_results=0

# should verbose mode be used
verbose=0

# functions--------------------------------------------------------------------

usage_internal()
{
	echo "Usage:"
		echo -e "\t$0 -[ifnpalrdovh]"
	echo -e "\t\t-i <ipv4/ipv6> \tChoose IP protocol to use"
	echo -e "\t\t-f <file> \tChoose file to be sent during tests.\n\
		\t\t\t\t(Full path to file on remote machine)
\t\t\t\tNot specified will perform tests on default files"
	echo -e "\t\t-n <num> \tChoose how many times send the file.\n\
\t\t\t\tEach file will be send by opening new netcat connection"
	echo -e "\t\t-p <num> \tSet port number of receiving side"
	echo -e "\t\t-a <addr> \tSet IP address of the receiving side"
	echo -e "\t\t-l <val> \tSet average loss of packets in %"
	echo -e "\t\t-r <val> \tSet every <val>'th packet to be reordered.\n\
\t\t\t\tIf delay is not set as well, default value of 10ms will be used."
	echo -e "\t\t-d <val> \tSet delay for packet sending in ms"
	echo -e "\t\t-o <file>\tFile to which results should be stored"
	echo -e "\t\t-v Verbose mode - prints additional output"
	echo -e "\t\t-h \t\tDisplay this help"
}

# parse options and arguments
while getopts ":i:f:n:p:a:l:r:d:o:vh" opt
do
	case $opt in
		i)
			ipv=$OPTARG
			if [[ ${ipv} -eq "ipv4" ]]
			then
				ipv4=1
			elif [[ ${ipv} -eq "ipv6" ]]
			then
				ipv6=1
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
		p)
			port=$OPTARG
			;;
		a)
			addr=$OPTARG
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
			redirect_results=1
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
DIR=$(dirname $0)
. ${DIR}/config.sh

# send file with results to local machine
send_results()
{
	if [[ ${redirect_results} -eq 1 ]]
	then
		if_verbose echo -e "Sending result file to local"
		scp ${scp_suppress} ${REMOTE_HOST}:${REMOTE_RESDIR}/results.out \
			${local_result_file}
	fi
	ssh ${REMOTE_HOST} rm -f ${REMOTE_RESDIR}/results.out
}

# test setup
run_test()
{
	of=$1
	# visual break of the output
	if_verbose echo -e "\nRunning netcat"

	i=0
	while [ $i -lt $num ]
	do
		# save command for nc in 'cmd'
		# time -> meassure time of execution for netcat
		# -q 0 -> wait 0 seconds after EOF and quit
		# timeout to deal with hanging connection when sth went wrong
		# feed netcat with {of} file to send
		# receiving end is redirected to out/...out files
		# 'exec' for redirecting nc err output to not mess result
		cmd="exec 4>&2
\$({ time timeout ${timeout} nc -q 0 ${addr} ${port} < ${REMOTE_DIR}/${of} \
	> ${REMOTE_OUTDIR}/${of}.out.${i} 2>&4; } \
	2>${REMOTE_RESDIR}/${of}.result.${i} )
exec 4>&-"

		# create temporary file for nc command to execute
		xf=$(ssh ${REMOTE_HOST} mktemp -p ${REMOTE_DIR})

		# store command from {cmd} into temporaty file
		echo "${cmd}" | ssh ${REMOTE_HOST} "cat > ${xf}"

		# execute nc command in the background
		ssh ${REMOTE_HOST} /bin/bash ${xf} &

		# adds tempfiles to list to remove later
		rmxf="${rmxf} ${xf}"
		rmresults="${rmresults} ${REMOTE_RESDIR}/${of}.result.${i}"

		i=$(expr $i + 1)
	done

	# sleep for 1 sec
	sleep 1

	# wait until previous commands finish (nc commands)
	wait

	# remove temporary files
	ssh ${REMOTE_HOST} rm -f ${rmxf}

	# visual break
	if_verbose echo -e "\nNetstat:"

	# prints network information for given {port} number
	# -n -> show numeric addresses
	# -a -> show all (both listening and non-listening sockets)
	if_verbose ssh ${REMOTE_HOST} netstat -na | grep ${port}

	# visual break
	if_verbose echo -e "\nJobs:"

	# display status of jobs in the current session (this bash script)
	if_verbose ssh ${REMOTE_HOST} jobs -l

	# visual break
	if_verbose echo -e "\nNetcat processes:"

	# display current processes for netcat
	# -e -> show all processes
	# -f -> do full format listing (more info)
	# grep -v -> get rid of the following word match from grep output
	if_verbose ssh ${REMOTE_HOST} ps -ef | grep "nc " | grep -v grep

	# visual break
	if_verbose echo -e "\nRunning validation"

	# prints checksum of given {of} file -> file to transfer
	# just for visual check that it is the same
	if_verbose ssh ${REMOTE_HOST} cksum ${REMOTE_DIR}/${of}

	i=0
	while [[ ${i} -lt ${num} ]]
	do
		# prints checksum of received file
		if_verbose ssh ${REMOTE_HOST} cksum ${REMOTE_OUTDIR}/${of}.out.${i}

		# comapres sent and received files if they match
		# compare {of} and {out/of.out.i} line by line
		ssh ${REMOTE_HOST} diff ${REMOTE_DIR}/${of} \
			${REMOTE_OUTDIR}/${of}.out.${i}

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

			# remove temporary results
			ssh ${REMOTE_HOST} rm -f ${rmresults}
			return ${rc}
		fi

		# remove received file from out/ directory
		ssh ${REMOTE_HOST} rm -f ${REMOTE_OUTDIR}/${of}.out.${i}

		i=$(expr $i + 1)
	done

	# remove temporary results
	ssh ${REMOTE_HOST} rm -f ${rmresults}

	if_verbose echo ""
	echo -e "TEST SUCCESSFUL - ${of}"
	if_verbose echo ""
	return 0
}

# clean up after error or end of tests
cleanup()
{
	send_results
	restore_netem
	l4fwd_stop
	remove_directories
}

# script start-----------------------------------------------------------------

#configure remote machine
configure_remote

# start l4fwd app
l4fwd_start

# check if default files should be used
if [[ ${default_file} -eq 0 ]]
then
	if_verbose echo -e "Sending test file to remote"
	scp ${scp_suppress} ${file} ${REMOTE_HOST}:${REMOTE_DIR}
	run_test ${file}

	# check test outcome
	ret=$?
	if [[ ${ret} -ne 0 ]]
	then
		cleanup
		exit ${ret}
	fi
	ssh ${REMOTE_HOST} rm -f ${REMOTE_DIR}/${file}
else
	# use default files with sizes 1, 4, 8, 16, 32 MB
	for size in 1 4 8 16 32
	do
		# generate file
		if_verbose echo -e "Generating ${size}MB file for test"
		x=$(ssh ${REMOTE_HOST} mktemp $(basename $0).${size}MB.XXX \
			-p ${REMOTE_DIR})

			ssh ${REMOTE_HOST} dd if=/dev/urandom of=${x} bs=1M \
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
		ssh ${REMOTE_HOST} rm -f ${x}
	done
fi

cleanup
exit 0

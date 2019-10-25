#! /bin/bash

# hardcoded variables which can be changed by the user if needed---------------

# DPDK port to be used
DPDK_PORT=0

# TCP port to be used
TCP_PORT=6000

# local interface addresses to set
LOCAL_IPV4=192.168.1.60
LOCAL_IPV6=fd12:3456:789a:0001:0000:0000:0000:0060

# remote interface addresses to set
REMOTE_IPV4=192.168.1.64
REMOTE_IPV6=fd12:3456:789a:0001:0000:0000:0000:0064

# mask length for addresses of each IP version
MASK_IPV4=24
MASK_IPV6=64

# name of the config files for backend and frontend of l4fwd app
L4FWD_BE_CFG_FILE=$(mktemp)
L4FWD_FE_CFG_FILE=$(mktemp)

# directory on remote to store tmp files - default /tmp/
REMOTE_DIR=/tmp/l4fwd_test
# directory on remote to store output files
REMOTE_OUTDIR=${REMOTE_DIR}/out
# directory on remote to store results
REMOTE_RESDIR=${REMOTE_DIR}/results

# checks done on environment variables-----------------------------------------

# check ETH_DEV
if [[ -z "${ETH_DEV}" ]]
then
	echo "ETH_DEV is invalid"
	exit 127
fi

# check if L4FWD_PATH points to an executable
if [[ ! -x ${L4FWD_PATH} ]]
then
	echo "${L4FWD_PATH} is not executable"
	exit 127
fi

# check if REMOTE_HOST is reachable
ssh ${REMOTE_HOST} echo
st=$?
if [[ $st -ne 0 ]]
then
	echo "host ${REMOTE_HOST} is not reachable"
	exit $st
fi

# get ethernet address of REMOTE_HOST
REMOTE_MAC=$(ssh ${REMOTE_HOST} ip addr show dev ${REMOTE_IFACE})
st=$?
REMOTE_MAC=$(echo ${REMOTE_MAC} | sed -e 's/^.*ether //' -e 's/ brd.*$//')
if [[ $st -ne 0 || -z "${REMOTE_MAC}" ]]
then
	echo "could not retrive ethernet address from ${REMOTE_IFACE}"
	exit 127
fi

# check if FECORE is set - default 0
L4FWD_FECORE=${L4FWD_FECORE:-0}

# check if BECORE is set - default FECORE
L4FWD_BECORE=${L4FWD_BECORE:-${L4FWD_FECORE}}

# l4fwd app settings-----------------------------------------------------------

# set file for l4fwd app output
L4FWD_OUT_FILE=./l4fwd.out
# set rbufs/sbufs/streams to open for l4fwd
L4FWD_STREAMS='--rbufs 0x100 --sbufs 0x100 --streams 0x100'

# set lcores for DPDK to start
if [[ ${L4FWD_FECORE} -ne ${L4FWD_BECORE} ]]
then
	L4FWD_LCORE="${L4FWD_FECORE},${L4FWD_BECORE}"
else
	L4FWD_LCORE="${L4FWD_FECORE}"
fi

# set EAL parameters
L4FWD_CMD_EAL_PRM="--lcores='${L4FWD_LCORE}' -n 4 ${ETH_DEV}"

# l4fwd parameters (listen, TCP only, enable arp, promiscuous)
L4FWD_CMD_PRM="--listen --tcp --enable-arp --promisc ${L4FWD_STREAMS}"

# l4fwd config files
L4FWD_CONFIG="--fecfg ${L4FWD_FE_CFG_FILE} --becfg ${L4FWD_BE_CFG_FILE}"

# port parameters
if [[ ${ipv4} -eq 1 ]]
then
	L4FWD_PORT_PRM="port=${DPDK_PORT},lcore=${L4FWD_BECORE},rx_offload=0x0\
,tx_offload=0x0,ipv4=${LOCAL_IPV4}"
elif [[ ${ipv6} -eq 1 ]]
then
	L4FWD_PORT_PRM="port=${DPDK_PORT},lcore=${L4FWD_BECORE},rx_offload=0x0\
,tx_offload=0x0,ipv6=${LOCAL_IPV6}"
fi

# other variables--------------------------------------------------------------

# check if directories on remote are set, if not make one
ssh ${REMOTE_HOST} mkdir -p {${REMOTE_OUTDIR},${REMOTE_RESDIR}}

# <tc qdisc ... netem ...> instruction to set
netem="ssh ${REMOTE_HOST} tc qdisc add dev ${REMOTE_IFACE} root netem"

# setting for scp which suppresses output of scp when not in verbose mode
if [[ ${verbose} -eq 1 ]]
then
	scp_suppress=""
else
	scp_suppress="-q"
fi

# setting for dd which suppresses output of dd when not in verbose mode
if [[ ${verbose} -eq 1 ]]
then
	dd_suppress=""
else
	dd_suppress="status=none"
fi

# set address to use by netcat
if [[ ${ipv4} -eq 1 ]]
then
	nc_addr=${LOCAL_IPV4}
elif [[ ${ipv6} -eq 1 ]]
then
	nc_addr=${LOCAL_IPV6}
fi

# helper functions-------------------------------------------------------------

# function to check if verbose is set and run command if yes
if_verbose()
{
	if [[ ${verbose} -eq 1 ]]
	then
		$@
	fi
}

# update results file
update_results()
{
	file=$1
	status=$2
	it=$3

	# get only 'real' time in results file
	$(ssh ${REMOTE_HOST} "awk '/real/{print \$2}' \
		${REMOTE_RESDIR}/${file}.result.${it} \
		>> ${REMOTE_RESDIR}/results.out")

	# add file and status of test to results
	if [[ ${status} -ne 0 ]]
	then
		$(ssh ${REMOTE_HOST} "sed -i '$ s_.*_[FAIL]\t&_' \
			${REMOTE_RESDIR}/results.out")
	else
		$(ssh ${REMOTE_HOST} "sed -i '$ s_.*_[OK]\t&_' \
			${REMOTE_RESDIR}/results.out")
	fi

	length=$(expr length "${file}")
	if [[ ${length} -lt 16 ]]
	then
		tab="\t\t"
	else
		tab="\t"
	fi

	$(ssh ${REMOTE_HOST} "sed -i '$ s_.*_${file}${tab}&_' \
		${REMOTE_RESDIR}/results.out")
}

# start l4fwd app
l4fwd_start()
{
	# create temporary file for command running l4fwd
	L4FWD_EXEC_FILE=$(mktemp)

	# store run command
	cat << EOF > ${L4FWD_EXEC_FILE}
stdbuf -o0 ${L4FWD_PATH} ${L4FWD_CMD_EAL_PRM} -- ${L4FWD_CMD_PRM} \
${L4FWD_CONFIG} ${L4FWD_PORT_PRM} > ${L4FWD_OUT_FILE} 2>&1 &
echo \$!
EOF

	# visual break
	if_verbose echo -e "\nApp l4fwd started with command:"
	if_verbose cat ${L4FWD_EXEC_FILE}
	if_verbose echo ""

	# run l4fwd app and get process ID of it
	L4FWD_PID=$(/bin/bash ${L4FWD_EXEC_FILE})

	# wait 2s and check if l4fwd is still running (parsing and init OK)
	sleep 2
	if [[ ${L4FWD_PID} -ne $(pgrep -o l4fwd) ]]
	then
		echo "ERROR: l4fwd app have crashed during initialization"
		rm -f ${L4FWD_EXEC_FILE}
		exit 127
	fi
}

# stop l4fwd app
l4fwd_stop()
{
	# kill runnning l4fwd app
	kill ${L4FWD_PID}

	# remove temporary files
	rm -f ${L4FWD_EXEC_FILE}
	rm -f ${L4FWD_FE_CFG_FILE}
	rm -f ${L4FWD_BE_CFG_FILE}
}

# configure IPv4 remote machine
configure_ip4_remote()
{
	# visual break of the output
	if_verbose echo "Setting interface on remote"

	# set remote interface with correct IP address
	ssh ${REMOTE_HOST} ip link set ${REMOTE_IFACE} down
	ssh ${REMOTE_HOST} ip addr flush dev ${REMOTE_IFACE}
	ssh ${REMOTE_HOST} ip addr add ${REMOTE_IPV4}/${MASK_IPV4} \
		dev ${REMOTE_IFACE}
	ssh ${REMOTE_HOST} ip link set ${REMOTE_IFACE} up
	if_verbose ssh ${REMOTE_HOST} ip addr show dev ${REMOTE_IFACE}

	ssh ${REMOTE_HOST} ip neigh flush dev ${REMOTE_IFACE}
	ssh ${REMOTE_HOST} iptables --flush

	# construct <tc qdisc ... nete ...> instruction
	if [[ set_netem -eq 1 ]]
	then
		# remove netem settings from remote interface if any
		check_netem=$(ssh ${REMOTE_HOST} "tc qdisc show dev \
			${REMOTE_IFACE} | grep netem")
		if [[ -n ${check_netem} ]]
		then
			ssh ${REMOTE_HOST} tc qdisc del dev ${REMOTE_IFACE} \
				root netem
		fi

		# set appropriate delay/loss/reorder if specified
		if [[ ${delay} -ne 0 ]]
		then
			netem="${netem} delay ${delay}ms"
		fi
		if [[ ${loss} -ne 0 ]]
		then
			netem="${netem} loss ${loss}%"
		fi
		if [[ ${reorder} -ne 0 ]]
		then
			netem="${netem} reorder 100% gap ${reorder}"
		fi

		# set netem on remote
		${netem}

		# visual break of the output
		if_verbose echo -e "\nNetwork rules on remote set to:"

		# print current netem settings
		if_verbose ssh ${REMOTE_HOST} tc qdisc show dev ${REMOTE_IFACE}
	fi

	# give linux 1 sec to handle all network settings
	sleep 1
}

# configure IPv6 remote machine
configure_ip6_remote()
{
	# visual break of the output
	if_verbose echo "Setting interface on remote"

	# set remote interface with correct IP address
	ssh ${REMOTE_HOST} ip link set ${REMOTE_IFACE} down
	ssh ${REMOTE_HOST} sysctl -q -w \
		net.ipv6.conf.${REMOTE_IFACE}.disable_ipv6=0
	ssh ${REMOTE_HOST} ip addr flush dev ${REMOTE_IFACE}
	ssh ${REMOTE_HOST} ip -6 addr add ${REMOTE_IPV6}/${MASK_IPV6} \
		dev ${REMOTE_IFACE}
	ssh ${REMOTE_HOST} ip -6 link set ${REMOTE_IFACE} up
	if_verbose ssh ${REMOTE_HOST} ip addr show dev ${REMOTE_IFACE}

	ssh ${REMOTE_HOST} ip neigh flush dev ${REMOTE_IFACE}
	ssh ${REMOTE_HOST} ip -6 neigh add ${LOCAL_IPV6} dev ${REMOTE_IFACE} \
		lladdr ${LOCAL_MAC}
	ssh ${REMOTE_HOST} iptables --flush
	ssh ${REMOTE_HOST} ip6tables --flush

	# construct <tc qdisc ... nete ...> instruction
	if [[ set_netem -eq 1 ]]
	then
		# remove netem settings from remote interface if any
		check_netem=$(ssh ${REMOTE_HOST} "tc qdisc show dev \
			${REMOTE_IFACE} | grep netem")
		if [[ -n ${check_netem} ]]
		then
			ssh ${REMOTE_HOST} tc qdisc del dev ${REMOTE_IFACE} \
				root netem
		fi


		# set appropriate delay/loss/reorder if specified
		if [[ ${delay} -ne 0 ]]
		then
			netem="${netem} delay ${delay}ms"
		fi
		if [[ ${loss} -ne 0 ]]
		then
			netem="${netem} loss ${loss}%"
		fi
		if [[ ${reorder} -ne 0 ]]
		then
			netem="${netem} reorder 100% gap ${reorder}"
		fi

		# set netem on remote
		${netem}

		# visual break of the output
		if_verbose echo -e "Network rules on remote set to:"

		# print current netem settings
		if_verbose ssh ${REMOTE_HOST} tc qdisc show dev ${REMOTE_IFACE}
	fi

	# give linux 1 sec to handle all network settings
	sleep 1
}

# configure remote
configure_remote()
{
	# call proper configuration
	if [[ ${ipv4} -eq 1 ]]
	then
		configure_ip4_remote

		if_verbose echo -e "\nBE configuration:"
		config4_be

		if_verbose echo -e "\nFE configuration:"
		config4_fe
	elif [[ ${ipv6} -eq 1 ]]
	then
		configure_ip6_remote

		if_verbose echo -e "\nBE configuration:"
		config6_be

		if_verbose echo -e "\nFE configuration:"
		config6_fe
	fi

	# create empty results file on remote
	$(ssh ${REMOTE_HOST} "> ${REMOTE_RESDIR}/results.out")
}

# restore netem settings to default
restore_netem()
{
	if [[ ${set_netem} -eq 1 ]]
	then
		ssh ${REMOTE_HOST} tc qdisc del dev ${REMOTE_IFACE} root netem
	fi
}

# remove created directories after test is done
remove_directories()
{
	ssh ${REMOTE_HOST} rm -fr ${REMOTE_DIR}
}

# configuration of be/fe config------------------------------------------------
config4_be()
{
	cat <<EOF > ${L4FWD_BE_CFG_FILE}
port=${DPDK_PORT},masklen=${MASK_IPV4},addr=${REMOTE_IPV4},mac=${REMOTE_MAC}
EOF

	if_verbose cat ${L4FWD_BE_CFG_FILE}
}

config6_be()
{
	cat <<EOF > ${L4FWD_BE_CFG_FILE}
port=${DPDK_PORT},masklen=${MASK_IPV6},addr=${REMOTE_IPV6},mac=${REMOTE_MAC}
EOF

	if_verbose cat ${L4FWD_BE_CFG_FILE}
}

config4_fe()
{
	cat <<EOF > ${L4FWD_FE_CFG_FILE}
lcore=${L4FWD_FECORE},belcore=${L4FWD_BECORE},op=echo,laddr=${LOCAL_IPV4}\
,lport=${TCP_PORT},raddr=${REMOTE_IPV4},rport=0
EOF

	if_verbose cat ${L4FWD_FE_CFG_FILE}
}

config6_fe()
{
	cat <<EOF > ${L4FWD_FE_CFG_FILE}
lcore=${L4FWD_FECORE},belcore=${L4FWD_BECORE},op=echo,laddr=${LOCAL_IPV6}\
,lport=${TCP_PORT},raddr=${REMOTE_IPV6},rport=0
EOF

	if_verbose cat ${L4FWD_FE_CFG_FILE}
}

#! /bin/bash

# hardcoded variables which can be changed by the user if needed---------------

# DPDK port to be used
DPDK_PORT=0

# TCP port to be used
TCP_PORT=6000

# local interface addresses to set
L4FWD_IPV4=192.168.2.60
L4FWD_IPV6=fd12:3456:789a:0002:0000:0000:0000:0060

# remote interface addresses to set
LINUX_IPV4=192.168.2.64
LINUX_IPV6=fd12:3456:789a:0002:0000:0000:0000:0064

# mask length for addresses of each IP version
MASK_IPV4=24
MASK_IPV6=64

# Interface tap/remote
IFACE=""

# should tap mode be used (1 - use tap interface, 0 - use real NIC)
USE_TAP=0

# MAC address for tap interface - filled when tap is created
LINUX_MAC="00:64:74:61:70:30"
# fake MAC address to provide in neighbours
FAKE_MAC="00:64:74:61:70:33"

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

# set interface based on mode used
if [[ "${ETH_DEV}" == "tap" ]]
then
	IFACE=l4fwd_tap0
	USE_TAP=1
else
	IFACE=${REMOTE_IFACE}
fi

# check if L4FWD_PATH points to an executable
if [[ ! -x ${L4FWD_PATH} ]]
then
	echo "${L4FWD_PATH} is not executable"
	exit 127
fi

# neccesary check for real NIC mode
if [[ ${USE_TAP} -eq 0 ]]
then
	# check if REMOTE_HOST is reachable
	ssh ${REMOTE_HOST} echo
	st=$?
	if [[ $st -ne 0 ]]
	then
		echo "host ${REMOTE_HOST} is not reachable"
		exit $st
	fi

	# get ethernet address of REMOTE_HOST
	LINUX_MAC=$(ssh ${REMOTE_HOST} ip addr show dev ${IFACE})
	st=$?
	LINUX_MAC=$(echo ${LINUX_MAC} | sed -e 's/^.*ether //' -e 's/ brd.*$//')
	if [[ $st -ne 0 || -z "${LINUX_MAC}" ]]
	then
		echo "could not retrive ethernet address from ${IFACE}"
		exit 127
	fi
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

L4FWD_TAP=""

# set eal parameters specific for mode used
if [[ ${USE_TAP} -eq 0 ]]
then
	L4FWD_DEV="${ETH_DEV}"
else
	L4FWD_DEV="--no-pci --vdev=\"net_tap0,iface=${IFACE},\
mac=\"${LINUX_MAC}\"\""
fi

# set EAL parameters
L4FWD_CMD_EAL_PRM="--lcores='${L4FWD_LCORE}' -n 4 ${L4FWD_DEV}"

# interface to wait for until it is set up properly
L4FWD_WAIT_VDEV="${IFACE}"

# l4fwd parameters (listen, TCP only, enable arp, promiscuous)
L4FWD_CMD_PRM="--listen --tcp --enable-arp --promisc ${L4FWD_STREAMS}"

# l4fwd config files
L4FWD_CONFIG="--fecfg ${L4FWD_FE_CFG_FILE} --becfg ${L4FWD_BE_CFG_FILE}"

# port parameters
if [[ ${ipv4} -eq 1 ]]
then
	L4FWD_PORT_PRM="port=${DPDK_PORT},lcore=${L4FWD_BECORE},rx_offload=0x0\
,tx_offload=0x0,ipv4=${L4FWD_IPV4}"
elif [[ ${ipv6} -eq 1 ]]
then
	L4FWD_PORT_PRM="port=${DPDK_PORT},lcore=${L4FWD_BECORE},rx_offload=0x0\
,tx_offload=0x0,ipv6=${L4FWD_IPV6}"
fi

# other variables--------------------------------------------------------------

# function to run command with ssh <remote> if needed
use_ssh()
{
	if [[ ${USE_TAP} -eq 1 ]]
	then
		"$@"
	else
		ssh ${REMOTE_HOST} "$*"
	fi
}

# check if directories on remote are set, if not make one
use_ssh mkdir -p {${REMOTE_OUTDIR},${REMOTE_RESDIR}}

# <tc qdisc ... netem ...> instruction to set
netem="tc qdisc add dev ${IFACE} root netem limit 100000"

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
	nc_addr=${L4FWD_IPV4}
elif [[ ${ipv6} -eq 1 ]]
then
	nc_addr=${L4FWD_IPV6}
fi

# calculate network address
let "ipv4_elem=(${MASK_IPV4}/8)"
let "ipv6_elem=(${MASK_IPV6}/16)"
let "ipv4_elem_rev=4-${ipv4_elem}"

ipv4_append=""
while [[ ${ipv4_elem_rev} -ne 0 ]]; do
	ipv4_append="${ipv4_append}.0"
	let "ipv4_elem_rev=${ipv4_elem_rev}-1"
done

ipv4_network=$(echo ${LINUX_IPV4} | cut -d. -f-${ipv4_elem} | \
	sed 's#.*#&'"${ipv4_append}"'#')
ipv6_network=$(echo ${LINUX_IPV6} | cut -d: -f-${ipv6_elem} | sed 's#.*#&::#')

# create temporary result file for tap mode, and/or set common file name
if [[ ${USE_TAP} -eq 0 ]]
then
	common_result_file="${REMOTE_RESDIR}/results.out"
else
	> ${local_result_file}
	common_result_file=${local_result_file}
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
	if [[ ${USE_TAP} -eq 0 ]]
	then
		$(ssh ${REMOTE_HOST} "awk '/real/{print \$2}' \
${REMOTE_RESDIR}/${file}.result.${it} >> ${common_result_file}")
	else
		awk '/real/{print $2}' ${REMOTE_RESDIR}/${file}.result.${it} \
			>> ${common_result_file}
	fi

	# add file and status of test to results
	if [[ ${status} -ne 0 ]]
	then
		if [[ ${USE_TAP} -eq 0 ]]
		then
			$(ssh ${REMOTE_HOST} "sed -i '$ s_.*_[FAIL]\t&_' \
${common_result_file}")
		else
			sed -i '$ s_.*_[FAIL]\t&_' ${common_result_file}
		fi
	else
		if [[ ${USE_TAP} -eq 0 ]]
		then
			$(ssh ${REMOTE_HOST} "sed -i '$ s_.*_[OK]\t&_' \
${common_result_file}")
		else
			sed -i '$ s_.*_[OK]\t&_' ${common_result_file}
		fi
	fi

	length=$(expr length "${file}")
	if [[ ${length} -lt 16 ]]
	then
		tab="\t\t"
	else
		tab="\t"
	fi

	if [[ ${USE_TAP} -eq 0 ]]
	then
		$(ssh ${REMOTE_HOST} "sed -i '$ s_.*_${file}${tab}&_' \
${common_result_file}")
	else
		sed -i "$ s_.*_${file}${tab}&_" ${common_result_file}
	fi
}

# start l4fwd app
l4fwd_start()
{
	# make configuration files for be/fe
	configure_be_fe

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

	if [[ ${USE_TAP} -eq 1 ]]
	then
		# check if tap interface is up
		i=0
		st=1
		while [[ ${i} -ne 5 && ${st} -ne 0 ]]
		do
			sleep 1
			ip link show dev ${L4FWD_WAIT_VDEV} > /dev/null 2>&1
			st=$?
			let i++
		done
	fi
}

# stop l4fwd app
l4fwd_stop()
{
	# kill runnning l4fwd app
	kill -s SIGINT ${L4FWD_PID}
	sleep 1
	# remove temporary files
	rm -f ${L4FWD_EXEC_FILE}
	rm -f ${L4FWD_FE_CFG_FILE}
	rm -f ${L4FWD_BE_CFG_FILE}
}

# helper function to set netem on remote
setup_netem()
{
	# remove netem settings from interface
	use_ssh tc qdisc del dev ${IFACE} root

	# set default delay for reorder
	if [[ ${reorder} -ne 0 && ${delay} -eq 0 ]]
	then
		delay=20
	fi

	# set appropriate delay/loss/reorder if specified
	if [[ ${delay} -ne 0 ]]
	then
		netem="${netem} delay ${delay}ms"
	fi

	if [[ ${loss} -ne 0 ]]
	then
		# calculate parameters for Simplified Gilbert model
		loss_to_set=$(( $(( ${loss} * ${loss_burst} )) \
/ $(( 100 - ${loss} )) ))

		if [[ ${loss_to_set} -gt 100 ]]
		then
			loss_to_set=100
		fi
		netem="${netem} loss gemodel ${loss_to_set}% ${loss_burst}%"
	fi

	if [[ ${reorder} -ne 0 ]]
	then
		netem="${netem} reorder 100% gap ${reorder}"
	fi

	# set netem
	use_ssh ${netem}

	# visual break of the output
	if_verbose echo -e "\nNetwork rules on remote set to:"

	# print current netem settings
	if_verbose use_ssh tc qdisc show dev ${IFACE}
}

# configure IPv4 interface
configure_l4fwd_ip4()
{
	# visual break of the output
	if_verbose echo "Setting IPv4 interface"

	# set remote interface with correct IP address
	if [[ ${USE_TAP} -eq 0 ]]
	then
		ssh ${REMOTE_HOST} ip link set ${IFACE} down
		ssh ${REMOTE_HOST} ip addr flush dev ${IFACE}
		ssh ${REMOTE_HOST} ip addr add ${LINUX_IPV4}/${MASK_IPV4} \
dev ${IFACE}
		ssh ${REMOTE_HOST} ip link set ${IFACE} up
		ssh ${REMOTE_HOST} ip neigh flush dev ${IFACE}
	else
		ip addr add ${LINUX_IPV4}/${MASK_IPV4} dev ${IFACE}
		ip link set ${IFACE} up
		ip neigh flush dev ${IFACE}
		ip neigh add ${L4FWD_IPV4} dev ${IFACE} lladdr ${FAKE_MAC}
	fi

	use_ssh iptables --flush
	use_ssh ip route change ${ipv4_network}/${MASK_IPV4} dev ${IFACE} \
rto_min 30ms
	if_verbose use_ssh ip addr show dev ${IFACE}

	# construct <tc qdisc ... nete ...> instruction
	if [[ set_netem -eq 1 ]]
	then
		setup_netem
	fi

	# give linux 1 sec to handle all network settings
	sleep 1
}

# configure IPv6 interface
configure_l4fwd_ip6()
{
	# visual break of the output
	if_verbose echo "Setting IPv6 interface"

	# set remote interface with correct IP address
	if [[ ${USE_TAP} -eq 0 ]]
	then
		ssh ${REMOTE_HOST} ip link set ${IFACE} down
		ssh ${REMOTE_HOST} sysctl -q -w \
net.ipv6.conf.${IFACE}.disable_ipv6=0
		ssh ${REMOTE_HOST} ip addr flush dev ${IFACE}
		ssh ${REMOTE_HOST} ip -6 addr add ${LINUX_IPV6}/${MASK_IPV6} \
dev ${IFACE}
		ssh ${REMOTE_HOST} ip -6 link set ${IFACE} up
		ssh ${REMOTE_HOST} ip neigh flush dev ${IFACE}
		ssh ${REMOTE_HOST} ip -6 neigh add ${L4FWD_IPV6} dev ${IFACE} \
lladdr ${LOCAL_MAC}
	else
		sysctl -q -w net.ipv6.conf.${IFACE}.disable_ipv6=0
		ip addr flush dev ${IFACE}
		ip -6 addr add ${LINUX_IPV6}/${MASK_IPV6} dev ${IFACE}
		ip -6 link set ${IFACE} up
		ip neigh flush dev ${IFACE}
		ip -6 neigh add ${L4FWD_IPV6} dev ${IFACE} lladdr ${FAKE_MAC}
	fi

	use_ssh iptables --flush
	use_ssh ip6tables --flush

	use_ssh ip route change ${ipv6_network}/${MASK_IPV6} dev \
${IFACE} proto kernel metric 256 rto_min 30ms
	if_verbose use_ssh ip addr show dev ${IFACE}

	# construct <tc qdisc ... nete ...> instruction
	if [[ set_netem -eq 1 ]]
	then
		setup_netem
	fi

	# give linux 3 sec to handle all network settings
	sleep 3
}


# configure tap interfaces
configure_interfaces()
{
	# call proper configuration
	if [[ ${ipv4} -eq 1 ]]
	then
		configure_l4fwd_ip4
	elif [[ ${ipv6} -eq 1 ]]
	then
		configure_l4fwd_ip6
	fi

	# create empty results file on remote
	$(ssh ${REMOTE_HOST} "> ${common_result_file}")
}

# restore netem settings to default
restore_netem()
{
	if [[ ${set_netem} -eq 1 ]]
	then
		use_ssh tc qdisc del dev ${IFACE} root
	fi
}

# remove created directories after test is done
remove_directories()
{
	use_ssh rm -fr ${REMOTE_DIR}
}

# configuration of be/fe config------------------------------------------------
configure_be_fe()
{
	# call proper configuration
	if [[ ${ipv4} -eq 1 ]]
	then
		if_verbose echo -e "\nBE configuration:"
		config4_be

		if_verbose echo -e "\nFE configuration:"
		config4_fe
	elif [[ ${ipv6} -eq 1 ]]
	then
		if_verbose echo -e "\nBE configuration:"
		config6_be

		if_verbose echo -e "\nFE configuration:"
		config6_fe
	fi
}

config4_be()
{
		cat <<EOF > ${L4FWD_BE_CFG_FILE}
port=${DPDK_PORT},masklen=${MASK_IPV4},addr=${LINUX_IPV4},mac=${LINUX_MAC}
EOF

	if_verbose cat ${L4FWD_BE_CFG_FILE}
}

config6_be()
{
		cat <<EOF > ${L4FWD_BE_CFG_FILE}
port=${DPDK_PORT},masklen=${MASK_IPV6},addr=${LINUX_IPV6},mac=${LINUX_MAC}
EOF

	if_verbose cat ${L4FWD_BE_CFG_FILE}
}

config4_fe()
{
	cat <<EOF > ${L4FWD_FE_CFG_FILE}
lcore=${L4FWD_FECORE},belcore=${L4FWD_BECORE},op=echo,laddr=${L4FWD_IPV4}\
,lport=${TCP_PORT},raddr=${LINUX_IPV4},rport=0
EOF

	if_verbose cat ${L4FWD_FE_CFG_FILE}
}

config6_fe()
{
	cat <<EOF > ${L4FWD_FE_CFG_FILE}
lcore=${L4FWD_FECORE},belcore=${L4FWD_BECORE},op=echo,laddr=${L4FWD_IPV6}\
,lport=${TCP_PORT},raddr=${LINUX_IPV6},rport=0
EOF

	if_verbose cat ${L4FWD_FE_CFG_FILE}
}

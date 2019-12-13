#! /bin/bash

# hardcoded variables which can be changed by the user if needed---------------

# DPDK port to be used
DPDK_PORT=0

# TCP port to be used
TCP_PORT=6000

# l4fwd addresses to set
L4FWD_IPV4=192.168.2.60
L4FWD_IPV6=fd12:3456:789a:0002:0000:0000:0000:0060

# linux/tap interface addresses to set
LINUX_IPV4=192.168.2.64
LINUX_IPV6=fd12:3456:789a:0002:0000:0000:0000:0064

# mask length for addresses of each IP version
MASK_IPV4=24
MASK_IPV6=64

# local tap interface
TAP_IFACE_L4FWD=l4fwd_tap0

# MAC address for tap interface - filled when tap is created
L4FWD_MAC="00:64:74:61:70:30"
# fake MAC address to provide in neighbours
FAKE_MAC="00:64:74:61:70:33"

# name of the config files for backend and frontend of l4fwd app
L4FWD_BE_CFG_FILE=$(mktemp)
L4FWD_FE_CFG_FILE=$(mktemp)

# directory to store tmp files - default /tmp/
REMOTE_DIR=/tmp/l4fwd_test
# directory to store output files
REMOTE_OUTDIR=${REMOTE_DIR}/out
# directory to store results
REMOTE_RESDIR=${REMOTE_DIR}/results

# checks done on environment variables-----------------------------------------

# check if L4FWD_PATH points to an executable
if [[ ! -x ${L4FWD_PATH} ]]
then
	echo "${L4FWD_PATH} is not executable"
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
L4FWD_CMD_EAL_PRM="--lcores='${L4FWD_LCORE}' -n 4 --no-pci \
--vdev=\"net_tap0,iface=${TAP_IFACE_L4FWD},mac=\"${L4FWD_MAC}\"\""

L4FWD_WAIT_VDEV="${TAP_IFACE_L4FWD}"

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

# check if directories are set, if not make one
mkdir -p {${REMOTE_OUTDIR},${REMOTE_RESDIR}}

# <tc qdisc ... netem ...> instruction to set
netem="tc qdisc add dev ${TAP_IFACE_L4FWD} root netem limit 100000"

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

# create temporary result file
> ${local_result_file}

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
	awk '/real/{print $2}' ${REMOTE_RESDIR}/${file}.result.${it} \
		>> ${local_result_file}

	# add file and status of test to results
	if [[ ${status} -ne 0 ]]
	then
		sed -i '$ s_.*_[FAIL]\t&_' ${local_result_file}
	else
		sed -i '$ s_.*_[OK]\t&_' ${local_result_file}
	fi

	length=$(expr length "${file}")
	if [[ ${length} -lt 16 ]]
	then
		tab="\t\t"
	else
		tab="\t"
	fi

	sed -i "$ s_.*_${file}${tab}&_" ${local_result_file}
}

# start l4fwd app
l4fwd_start()
{
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

# helper function to set netem
setup_netem()
{
	# remove netem settings from tap interface
	tc qdisc del dev ${TAP_IFACE_L4FWD} root

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
	${netem}

	# visual break of the output
	if_verbose echo -e "\nNetwork rules set to:"

	# print current netem settings
	if_verbose tc qdisc show dev ${TAP_IFACE_L4FWD}
}

# configure interface IPv4 tap managed by l4fwd
configure_l4fwd_ip4_tap()
{
	# visual break of the output
	if_verbose echo "Setting IPv4 interface"

	# set tap interface with correct IP address
	ip addr add ${LINUX_IPV4}/${MASK_IPV4} dev ${TAP_IFACE_L4FWD}
	ip link set ${TAP_IFACE_L4FWD} up
	ip neigh flush dev ${TAP_IFACE_L4FWD}
	ip neigh add ${L4FWD_IPV4} dev ${TAP_IFACE_L4FWD} lladdr ${FAKE_MAC}
	iptables --flush

	ip route change ${ipv4_network}/${MASK_IPV4} dev ${TAP_IFACE_L4FWD} \
		rto_min 30ms

	if_verbose ip addr show dev ${TAP_IFACE_L4FWD}

	# construct <tc qdisc ... nete ...> instruction
	if [[ set_netem -eq 1 ]]
	then
		setup_netem
	fi

	# give linux 1 sec to handle all network settings
	sleep 1
}

# configure interface for IPv6 tap managed by l4fwd
configure_l4fwd_ip6_tap()
{
	# visual break of the output
	if_verbose echo "Setting IPv6 interface"

	# set tap interface with correct IP address
	sysctl -q -w net.ipv6.conf.${TAP_IFACE_L4FWD}.disable_ipv6=0
	ip addr flush dev ${TAP_IFACE_L4FWD}
	ip -6 addr add ${LINUX_IPV6}/${MASK_IPV6} dev ${TAP_IFACE_L4FWD}
	ip -6 link set ${TAP_IFACE_L4FWD} up

	ip neigh flush dev ${TAP_IFACE_L4FWD}
	ip -6 neigh add ${L4FWD_IPV6} dev ${TAP_IFACE_L4FWD} lladdr ${FAKE_MAC}
	iptables --flush
	ip6tables --flush

	ip route change ${ipv6_network}/${MASK_IPV6} dev ${TAP_IFACE_L4FWD} \
		proto kernel metric 256 rto_min 30ms

	if_verbose ip addr show dev ${TAP_IFACE_L4FWD}

	# construct <tc qdisc ... nete ...> instruction
	if [[ set_netem -eq 1 ]]
	then
		setup_netem
	fi

	# give linux 1 sec to handle all network settings
	sleep 3
}


# configure tap interface
configure_interface()
{
	# call proper configuration
	if [[ ${ipv4} -eq 1 ]]
	then
		configure_l4fwd_ip4_tap
	elif [[ ${ipv6} -eq 1 ]]
	then
		configure_l4fwd_ip6_tap
	fi
}

# restore netem settings to default
restore_netem()
{
	if [[ ${set_netem} -eq 1 ]]
	then
		tc qdisc del dev ${TAP_IFACE_L4FWD} root
	fi
}

# remove created directories after test is done
remove_directories()
{
	rm -fr ${REMOTE_DIR}
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
port=${DPDK_PORT},masklen=${MASK_IPV4},addr=${LINUX_IPV4},mac=${L4FWD_MAC}
EOF

	if_verbose cat ${L4FWD_BE_CFG_FILE}
}

config6_be()
{
	cat <<EOF > ${L4FWD_BE_CFG_FILE}
port=${DPDK_PORT},masklen=${MASK_IPV6},addr=${LINUX_IPV6},mac=${L4FWD_MAC}
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

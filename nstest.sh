#!/bin/sh
#
# Prepare dnsmasq for running dhscript.py
# Requires root privileges, netns support and dnsmasq installed

PYTHON=${PYTHON:-python}
DNSMASQ=dnsmasq

export DNSMASQ_TEST=1

start() {
	ip netns add server
	if ! ip netns | grep server
	then
		echo "Requires CAPS_NET_ADMIN privileges, use sudo"
		exit 1
	fi
	ip netns add client
	ON_SERVER="ip netns exec server"
	ON_CLIENT="ip netns exec client"
	$ON_CLIENT ip link set lo up
	$ON_CLIENT ip link add eth0 type veth peer name veth0
	$ON_CLIENT ip address add 10.0.2.1/24 dev eth0
	$ON_CLIENT ip link set eth0 up
	$ON_CLIENT ip link set veth0 netns server
	$ON_SERVER ip link set lo up
	$ON_SERVER ip address add 10.0.2.2/24 dev veth0
	$ON_SERVER ip link set veth0 up

	$ON_SERVER $DNSMASQ -C dnsmasq.conf --pid-file=$PWD/dnsmasq.pid --dhcp-leasefile=$PWD/dnsmasq.leases --log-facility=$PWD/dnsmasq.log
}

stop() {
	test -f dnsmasq.pid && pkill -F $PWD/dnsmasq.pid
	ip netns del server
	ip netns del client
}

pytest() {
	ON_CLIENT="ip netns exec client"
	$ON_CLIENT $PYTHON ./dhscript.py
}

check() {
	start
	pytest
	stop
}

help() {
	cat << EOF
usage: ${0} <start | stop | test | check>
start - prepare netns and start dhcp server
stop - stop dhcp server and remove netns
test - run test in client namespace
check - run previous 3 steps
EOF
}

case "$1" in
	start) start ;;
	stop)  stop  ;;
	restart)  stop; start ;;
	test)	pytest ;;
	test2) PYTHON=python2 pytest ;;
	test3) PYTHON=python3 pytest ;;
	check) check ;;
	help|--help|-h|"") help ;;
esac

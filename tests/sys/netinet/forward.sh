#!/usr/bin/env atf-sh
#-
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2020 Alexander V. Chernikov
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
#

. $(atf_get_srcdir)/../common/vnet.subr

atf_test_case "fwd_ip_icmp_iface_fast_success" "cleanup"
fwd_ip_icmp_iface_fast_success_head() {

	atf_set descr 'Test valid IPv4 on-stick fastforwarding to iface'
	atf_set require.user root
	atf_set require.progs scapy
}

fwd_ip_icmp_iface_fast_success_body() {

	vnet_init

	ip4a="192.0.2.1"
	ip4b="192.0.2.2"
	plen=29
	src_ip="192.0.2.3"

	script_name="../common/sender.py"

	epair=$(vnet_mkepair)
	ifconfig ${epair}a up
	ifconfig ${epair}a inet ${ip4a}/${plen}

	jname="v4t-fwd_ip_icmp_iface_fast_success"
	vnet_mkjail ${jname} ${epair}b
	jexec ${jname} ifconfig ${epair}b up
	jexec ${jname} ifconfig ${epair}b inet ${ip4b}/${plen}

	# Get router ip/mac
	jail_ip=${ip4b}
	jail_mac=`jexec ${jname} ifconfig ${epair}b ether | awk '$1~/ether/{print$2}'`

	our_mac=`ifconfig ${epair}a ether | awk '$1~/ether/{print$2}'`

	jexec ${jname} sysctl net.inet.ip.forwarding=1
	# As we're doing router-on-the-stick, turn sending IP redirects off:
	jexec ${jname} sysctl net.inet.ip.redirect=0

	# echo "LOCAL: ${local_ip} ${local_mac}"
	# echo "REMOTE: ${remote_rtr_ip} ${remote_rtr_mac}"

	atf_check -s exit:0 $(atf_get_srcdir)/${script_name} \
		--test_name fwd_ip_icmp_fast \
		--smac ${our_mac} --dmac ${jail_mac} \
		--sip ${src_ip} --dip ${ip4a} \
		--iface ${epair}a 

	# check counters are valid
	atf_check -o match:'1 packet forwarded \(1 packet fast forwarded\)' jexec ${jname} netstat -sp ip
}

fwd_ip_icmp_iface_fast_success_cleanup() {

	vnet_cleanup
}

atf_test_case "fwd_ip_icmp_gw_fast_success" "cleanup"
fwd_ip_icmp_gw_fast_success_head() {

	atf_set descr 'Test valid IPv4 on-stick fastforwarding to gw'
	atf_set require.user root
	atf_set require.progs scapy
}

fwd_ip_icmp_gw_fast_success_body() {

	vnet_init

	ip4a="192.0.2.1"
	ip4b="192.0.2.2"
	plen=29
	src_ip="192.0.2.3"
	dst_ip="192.0.2.4"

	script_name="../common/sender.py"

	epair=$(vnet_mkepair)
	ifconfig ${epair}a up
	ifconfig ${epair}a inet ${ip4a}/${plen}

	jname="v4t-fwd_ip_icmp_gw_fast_success"
	vnet_mkjail ${jname} ${epair}b
	jexec ${jname} ifconfig ${epair}b up
	jexec ${jname} ifconfig ${epair}b inet ${ip4b}/${plen}

	# Get router ip/mac
	jail_ip=${ip4b}
	jail_mac=`jexec ${jname} ifconfig ${epair}b ether | awk '$1~/ether/{print$2}'`

	our_mac=`ifconfig ${epair}a ether | awk '$1~/ether/{print$2}'`

	jexec ${jname} sysctl net.inet.ip.forwarding=1
	# As we're doing router-on-the-stick, turn sending IP redirects off:
	jexec ${jname} sysctl net.inet.ip.redirect=0

	# Add host route
	jexec ${jname} route -4 add -host ${dst_ip} ${ip4a}

	# echo "LOCAL: ${local_ip} ${local_mac}"
	# echo "REMOTE: ${remote_rtr_ip} ${remote_rtr_mac}"

	atf_check -s exit:0 $(atf_get_srcdir)/${script_name} \
		--test_name fwd_ip_icmp_fast \
		--smac ${our_mac} --dmac ${jail_mac} \
		--sip ${src_ip} --dip ${dst_ip} \
		--iface ${epair}a 

	# check counters are valid
	atf_check -o match:'1 packet forwarded \(1 packet fast forwarded\)' jexec ${jname} netstat -sp ip
}

fwd_ip_icmp_gw_fast_success_cleanup() {

	vnet_cleanup
}

atf_test_case "fwd_ip_icmp_iface_slow_success" "cleanup"
fwd_ip_icmp_iface_slow_success_head() {

	atf_set descr 'Test valid IPv4 on-stick "slow" forwarding to iface'
	atf_set require.user root
	atf_set require.progs scapy
}

fwd_ip_icmp_iface_slow_success_body() {

	vnet_init

	ip4a="192.0.2.1"
	ip4b="192.0.2.2"
	plen=29
	src_ip="192.0.2.3"

	script_name="../common/sender.py"

	epair=$(vnet_mkepair)
	ifconfig ${epair}a up
	ifconfig ${epair}a inet ${ip4a}/${plen}

	jname="v4t-fwd_ip_icmp_iface_slow_success"
	vnet_mkjail ${jname} ${epair}b
	jexec ${jname} ifconfig ${epair}b up
	jexec ${jname} ifconfig ${epair}b inet ${ip4b}/${plen}

	# Get router ip/mac
	jail_ip=${ip4b}
	jail_mac=`jexec ${jname} ifconfig ${epair}b ether | awk '$1~/ether/{print$2}'`

	our_mac=`ifconfig ${epair}a ether | awk '$1~/ether/{print$2}'`

	jexec ${jname} sysctl net.inet.ip.forwarding=1
	# As we're doing router-on-the-stick, turn sending IP redirects off:
	jexec ${jname} sysctl net.inet.ip.redirect=0

	# Generate packet with options to force slow-path
	atf_check -s exit:0 $(atf_get_srcdir)/${script_name} \
		--test_name fwd_ip_icmp_slow \
		--smac ${our_mac} --dmac ${jail_mac} \
		--sip ${src_ip} --dip ${ip4a} \
		--iface ${epair}a 

	# check counters are valid
	atf_check -o match:'1 packet forwarded \(0 packets fast forwarded\)' jexec ${jname} netstat -sp ip
}

fwd_ip_icmp_iface_slow_success_cleanup() {

	vnet_cleanup
}

atf_test_case "fwd_ip_icmp_gw_slow_success" "cleanup"
fwd_ip_icmp_gw_slow_success_head() {

	atf_set descr 'Test valid IPv4 on-stick "slow" forwarding to gw'
	atf_set require.user root
	atf_set require.progs scapy
}

fwd_ip_icmp_gw_slow_success_body() {

	vnet_init

	ip4a="192.0.2.1"
	ip4b="192.0.2.2"
	plen=29
	src_ip="192.0.2.3"
	dst_ip="192.0.2.4"

	script_name="../common/sender.py"

	epair=$(vnet_mkepair)
	ifconfig ${epair}a up
	ifconfig ${epair}a inet ${ip4a}/${plen}

	jname="v4t-fwd_ip_icmp_gw_slow_success"
	vnet_mkjail ${jname} ${epair}b
	jexec ${jname} ifconfig ${epair}b up
	jexec ${jname} ifconfig ${epair}b inet ${ip4b}/${plen}

	# Get router ip/mac
	jail_ip=${ip4b}
	jail_mac=`jexec ${jname} ifconfig ${epair}b ether | awk '$1~/ether/{print$2}'`

	our_mac=`ifconfig ${epair}a ether | awk '$1~/ether/{print$2}'`

	jexec ${jname} sysctl net.inet.ip.forwarding=1
	# As we're doing router-on-the-stick, turn sending IP redirects off:
	jexec ${jname} sysctl net.inet.ip.redirect=0

	# Add host route
	jexec ${jname} route -4 add -host ${dst_ip} ${ip4a}

	# echo "LOCAL: ${local_ip} ${local_mac}"
	# echo "REMOTE: ${remote_rtr_ip} ${remote_rtr_mac}"

	atf_check -s exit:0 $(atf_get_srcdir)/${script_name} \
		--test_name fwd_ip_icmp_fast \
		--smac ${our_mac} --dmac ${jail_mac} \
		--sip ${src_ip} --dip ${dst_ip} \
		--iface ${epair}a 

	# check counters are valid
	atf_check -o match:'1 packet forwarded \(1 packet fast forwarded\)' jexec ${jname} netstat -sp ip
}

fwd_ip_icmp_gw_slow_success_cleanup() {

	vnet_cleanup
}

atf_test_case "fwd_ip_via_v6" "cleanup"
fwd_ip_via_v6_head() {
	atf_set descr 'Test using an IPv6 gateway for IPv4 routing'
	atf_set require.user root
}

fwd_ip_via_v6_body() {
	vnet_init

	j="fwd_ip_via_v6_"

	epair_one=$(vnet_mkepair)
	epair_two=$(vnet_mkepair)

	vnet_mkjail ${j}c ${epair_one}a
	jexec ${j}c ifconfig ${epair_one}a 192.0.2.2/24 up
	jexec ${j}c ifconfig ${epair_one}a inet6 2001:db8::2/64 up no_dad
	atf_check -s exit:0 -o ignore \
	    jexec ${j}c route add -6 -net -inet 0.0.0.0/0 -inet6 2001:db8::1

	vnet_mkjail ${j}r ${epair_one}b ${epair_two}a
	jexec ${j}r ifconfig ${epair_one}b 192.0.2.1/24 up
	jexec ${j}r ifconfig ${epair_one}b inet6 2001:db8::1/64 up no_dad
	jexec ${j}r ifconfig ${epair_two}a 198.51.100.1/24 up
	jexec ${j}r sysctl net.inet.ip.forwarding=1

	vnet_mkjail ${j}s ${epair_two}b
	jexec ${j}s ifconfig ${epair_two}b 198.51.100.2/24 up
	jexec ${j}s route add default 198.51.100.1

	# Sanity checking
	atf_check -s exit:0 -o ignore \
	    jexec ${j}c ping -c 1 192.0.2.1
	atf_check -s exit:0 -o ignore \
	    jexec ${j}c ping6 -c 1 2001:db8::1

	atf_check -s exit:0 -o ignore \
	    jexec ${j}r ping -c 1 198.51.100.2

	# Actual test, can we ping server jail?
	atf_check -s exit:0 -o ignore \
	    jexec ${j}c ping -c 3 198.51.100.2

	jexec ${j}c netstat -rn
}

fwd_ip_via_v6_cleanup() {
	vnet_cleanup
}

atf_init_test_cases()
{

	atf_add_test_case "fwd_ip_icmp_iface_fast_success"
	atf_add_test_case "fwd_ip_icmp_gw_fast_success"
	atf_add_test_case "fwd_ip_icmp_iface_slow_success"
	atf_add_test_case "fwd_ip_icmp_gw_slow_success"
	atf_add_test_case "fwd_ip_via_v6"
}

# end


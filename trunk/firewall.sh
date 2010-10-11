#!/bin/bash

# firewall.sh - builds firewall rules

# source config file before doing anything else!
if [ -r /usr/local/sbin/zfw/firewall.conf ]; then 
	source /usr/local/sbin/zfw/firewall.conf
else
	echo "firewall.sh: ERROR: config file not found!"
	exit 1 
fi

# find the iptables install
ipt=$(which iptables)

#
# FIREWALL FUNCTIONS: define rules to be run. 
#
ipt_load_modules() {
	# for virtual servers, the modules are built in
	# module list pulled from config 	
	modprobe=$(whereis modprobe)

	for module in ${enable_module_list}; do 
		$modprobe $module
	done
}

ipt_clean_tables() {
	# dump any previous rules
	# --flush removes all rules in all chains
	$ipt --flush
}

ipt_set_policy() {
	# set the default policies
	$ipt -P INPUT $policy_input
	$ipt -P OUTPUT $policy_output
	$ipt -P FORWARD $policy_forward
}

ipt_allow_localhost() {
	# allow connections from localhost
	$ipt -A INPUT -i $lo_iface -j ACCEPT
	$ipt -A OUTPUT -j ACCEPT
	$ipt -A INPUT -i $lo_iface -p ALL -s $lo_ip

	# allow child connections that we generate to come back to us.
	$ipt -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

	# let ICMP echo (ping) work properly
	for iface in ${lo_iface} ${pub_iface} ${pvt_iface}; do 
		$ipt -A INPUT -i $iface -p icmp -s 0.0.0.0/0 -j ACCEPT
	done

	for ip in ${pub_ip} ${pvt_ip}; do 
		$ipt -A INPUT -d $ip -p icmp -s 0.0.0.0/0 -j ACCEPT
	done
}

ipt_network_allow() {
	# allow our own DNS servers to talk to us
	for ip in ${pub_ip}; do 
		for dns_svr in $(egrep "nameserver" /etc/resolv.conf | awk '{print $2}'); do
			$ipt -A INPUT -d $ip -p udp --sport 53 --dport 1024:65535 \
			-m state --state ESTABLISHED -s $dns_svr -j ACCEPT
		done
	done

	# try to prevent brute forcing from getting excessive
	# count connections on $port in 600s, if connections are more than
	# -hitcount value, then reject. blanket ruleset.
	if [ -n "${brute_ports}" ]; then 
		for ip in ${pub_ip}; do
			for port in ${brute_ports}; do
				$ipt -A INPUT -p tcp --dport $port -d $ip \
				-m state --state NEW -m recent --set
				$ipt -A INPUT -p tcp --dport $port -i $ip \
				-m state --state NEW -m recent --update --seconds 600 --hitcount 10 -j DROP
			done
		done
	fi

	# trust some networks w/o question
	# create whitelist for dogooders
	$ipt -N WHITELIST
	if [ -n "${trust_nets}" ]; then
		for ip in ${pub_ip}; do
			for net in ${trust_nets}; do
				$ipt -A WHITELIST -d $ip -p ALL -s $net -j ACCEPT
			done
		done
	fi

	# ALLOW PUBLIC ACCESS 
	if [ -n "${pub_ip}" ]; then 
		for ip in ${pub_ip}; do 
			for port in ${pub_ports}; do
				$ipt -A INPUT -p tcp -d $ip --dport $port -j ACCEPT
				$ipt -A INPUT -p udp -d $ip --dport $port -j ACCEPT
			done
		done
	fi

	# ALLOW PRIVATE ACCESS
	if [ -n "${pvt_ip}" ]; then
		for ip in ${pvt_ip}; do 
			for net in ${pvt_nets}; do 
				for port in ${pvt_ports}; do 
					$ipt -A INPUT -p tcp -d $ip --dport $port -s $net -j ACCEPT
					$ipt -A INPUT -p udp -d $ip --dport $port -s $net -j ACCEPT
				done
			done
		done
	fi

}

enable_ftp() {
	# the ip_conntrack_ftp module is required
	modprobe ip_conntrack_ftp
	# this keeps ftp running properly on ALL interfaces
	if [ -n ${pub_ip} ]; then 
		for ip in ${pub_ip}; do 
			$ipt -A INPUT -d $ip -p tcp -s 0.0.0.0/0 --dport 20:21 -j ACCEPT
			$ipt -A INPUT -d $ip -m helper --helper ftp -j ACCEPT
		done
	fi

	if [ -n ${pvt_ip} ]; then 
		for ip in ${pvt_ip}; do 
			$ipt -A INPUT -d $ip -p tcp -s 0.0.0.0/0 --dport 20:21 -j ACCEPT
			$ipt -A INPUT -d $ip -m helper --helper ftp -j ACCEPT
		done
	fi
}

enable_torrent() {
	# allow torrent trackers to contact standard torrent ports, and ports 10000-11000
	if [ -n "${pub_ip}" ]; then
		for ip in ${pub_ip}; do
			$ipt -I INPUT -d $ip -p tcp --tcp-flags SYN,RST,ACK SYN --dport 6881:6999 -j ACCEPT
			$ipt -I INPUT -d $ip -p tcp --tcp-flags SYN,RST,ACK SYN --dport 10001:11001 -j ACCEPT
			$ipt -I INPUT -d $ip -p udp --dport 6881:6999 -m state --state NEW -j ACCEPT
			$ipt -I INPUT -d $ip -p udp --dport 10001:11001 -m state --state NEW -j ACCEPT
		done
	fi
}

enable_logging() {
	$ipt -A INPUT -p tcp -j LOG --log-level info --log-prefix 'ipt_tcp_drop: ' --log-ip-options --log-tcp-options
	$ipt -A INPUT -p udp -j LOG --log-level info --log-prefix 'ipt_udp_drop: '
}

enable_blacklist() {
	# is target readable?
	if [ -r ${blacklist_files} ]; then 
		# target is a file
		if [ -f ${blacklist_files} ]; then 
			# create chain for evildoers
			$ipt -N BLACKLIST
			# read file, look for cidr nets first, /32 included	
			for net in $(egrep -v "^#" $file | egrep "/[0-9]{1}[0-9]{0,1}$"); do
				$ipt -A BLACKLIST -s $net -j DROP 
			done
			# then single IP addresses
			for ip in $(egrep -v "^#" $file | egrep -v "/[0-9]{1}[0-9]{0,1}$"); do
				$ipt -A BLACKLIST -s $ip -j DROP
			done
		# target is a dir
		elif [ -d ${blacklist_files} ]; then 
			# create chain for evildoers
			$ipt -N BLACKLIST
			# look at files in dir
			for file in $(ls -1 ${blacklist_files}); do
				for ip in ${pub_ip}; do
					# look for cidr nets first, /32 included	
					for net in $(egrep -v "^#" ${blacklist_files}/$file | egrep "/[0-9]{1}[0-9]{0,1}$"); do
						$ipt -A BLACKLIST -s $net -j DROP 
					done
					# then single IP addresses
					for ip in $(egrep -v "^#" ${blacklist_files}/$file | egrep -v "/[0-9]{1}[0-9]{0,1}$"); do
						$ipt -A BLACKLIST -s $ip -j DROP
					done
				done
			done
		# an error has occoured
		else 
			echo "* $0: ${blacklist_files} is not a file or directory!"
			exit 1
		fi
	fi
}

enable_bcast_block() {
	# needs xt_pkttype module 
	$ipt -A INPUT -m pkttype --pkt-type broadcast -j DROP
	$ipt -A INPUT -m pkttype --pkt-type multicast -j DROP 
}

enable_ntp() {
	# let ntp-client and ntpd to work (on all interfaces).
	$ipt -A INPUT -p tcp --dport 123 -j ACCEPT
	$ipt -A INPUT -p udp --dport 123 -j ACCEPT
}

# no more functions to define!

#
# EXECUTE FUNCTIONS: order of ops is important here
#
# do we need to load ipt modules first?
case ${enable_module_load} in 
	[yY][eE][sS]) 	ipt_load_modules ;;
	*) continue ;; 
esac 
# clean house, set policy
ipt_clean_tables
ipt_set_policy
ipt_allow_localhost
# blocks to run before allows
case ${enable_blacklist} in 
	[yY][eE][sS])	enable_blacklist ;;
	*) continue ;; 
esac
# run allows
ipt_network_allow
# enable ftp 
case ${enable_ftp} in
	[yY][eE][sS])	enable_ftp ;;
	*) continue ;; 
esac
# enable torrent
case ${enable_torrent} in 
	[yY][eE][sS])	enable_torrent ;;
	*) continue ;; 
esac
# enable broadcast packet blocks
case ${enable_bcast_block} in
	[yY][eE][sS])	enable_bcast_block ;;
	*) continue ;; 
esac
# enable NTP functionality
case ${enable_ntp} in
	[yY][eE][sS])	enable_ntp ;;
	*) continue ;; 
esac
# enable logging, MUST BE LAST
case ${enable_logging} in
	[yY][eE][sS])	enable_logging ;;
	*) continue ;; 
esac


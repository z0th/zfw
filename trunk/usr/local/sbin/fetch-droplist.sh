der: /usr/local/sbin/RCS/fetch-droplist.sh,v 1.14 2009/02/19 17:39:15 root Exp $
# 
#!/bin/bash
#
# FETCH-DROPLIST.SH - fetch lists of 'bad' address and process them for use by /etc/firewall.conf 
#

# common file to dump blocks into.
CMN_BL_FILE="/tmp/firewall.fetched.tmp"
TGT_BL_FILE="/etc/firewall.fetched"
# make sure the common file is empty.
echo "" > $CMN_BL_FILE

#
# FUNCTIONS
#
iptables_reload() {
	/etc/init.d/iptables stop
	sh /etc/firewall.conf && 
	/etc/init.d/iptables save
	/etc/init.d/iptables start
}

bogon_list() {
	# get the list, 
	curl http://www.cymru.com/Documents/bogon-bn-agg.txt --silent --output /tmp/firewall.bogon.tmp
	# the list is just cidr nets, no processing needed. 
	mv /tmp/firewall.bogon.tmp /etc/firewall.bogon
}

ipdeny_country() {
	# fetch lists of blocks for various TL country domains.
	curl http://www.ipdeny.com/ipblocks/data/countries/ru.zone --silent >> /tmp/firewall.country.tmp
	curl http://www.ipdeny.com/ipblocks/data/countries/kr.zone --silent >> /tmp/firewall.country.tmp
	curl http://www.ipdeny.com/ipblocks/data/countries/cn.zone --silent >> /tmp/firewall.country.tmp
	curl http://www.ipdeny.com/ipblocks/data/countries/my.zone --silent >> /tmp/firewall.country.tmp
	curl http://www.ipdeny.com/ipblocks/data/countries/tw.zone --silent >> /tmp/firewall.country.tmp
	curl http://www.ipdeny.com/ipblocks/data/countries/br.zone --silent >> /tmp/firewall.country.tmp
	curl http://www.ipdeny.com/ipblocks/data/countries/co.zone --silent >> /tmp/firewall.country.tmp
	curl http://www.ipdeny.com/ipblocks/data/countries/ch.zone --silent >> /tmp/firewall.country.tmp
	curl http://www.ipdeny.com/ipblocks/data/countries/jp.zone --silent >> /tmp/firewall.country.tmp
	# these are lists of CIDR blocks, no procesing needed
	sort -n /tmp/firewall.country.tmp | uniq > /etc/firewall.country
}

fetch_blacklist() {

	#### SSH BLACKLIST ####
	curl http://atlas-public.ec2.arbor.net/public/ssh_attackers --silent --output /tmp/firewall.ssh_arbor.tmp 
	curl http://www.infiltrated.net/blacklisted --silent --output /tmp/firewall.infiltrated_ssh.tmp
	curl http://danger.rulez.sk/projects/bruteforceblocker/blist.php --silent --output /tmp/firewall.ssh_rulez.tmp
	# process the arbor list
	awk '{print $1}' /tmp/firewall.ssh_arbor.tmp | grep -v "other" >> $CMN_BL_FILE
	if [[ -f /tmp/firewall.ssh_arbor.tmp ]]; then 
		rm -f /tmp/firewall.ssh_arbor.tmp
	fi
	# process the infiltrated.net list, grep for ip addr patterns
	grep "\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b" /tmp/firewall.infiltrated_ssh.tmp >> $CMN_BL_FILE 
	if [[ -f /tmp/firewall.infiltrated_ssh.tmp ]]; then 
		rm -f /tmp/firewall.infiltrated_ssh.tmp
	fi
	# process the rulez.sk list, have to slice comments.
	awk '!/^\#/ {print $1}' /tmp/firewall.ssh_rulez.tmp >> $CMN_BL_FILE	
	if [[ -f /tmp/firewall.rulez.tmp ]]; then
		rm /tmp/firewall.ssh_rulez.tmp
	fi
	
	##### ZOMBIE BLACKLIST ####
	curl http://www.spamhaus.org/drop/drop.lasso --silent --output /tmp/firewall.zombie.tmp   
	# process the list into something useable. 
	cat /tmp/firewall.zombie.tmp | grep -v "^\;" | awk -F\; '{print $1}' >> $CMN_BL_FILE
	# remove the temp 
	if [ -f /tmp/firewall.zombie.tmp ]; then
        	rm -rf /tmp/firewall.zombie.tmp
	fi

	#### POST PROCESSING ####
	# now that we have a list, sort it for dupes and drop it in etc.
	sort -n $CMN_BL_FILE | uniq > $TGT_BL_FILE 
	if [[ -e $CMN_BL_FILE ]]; then 
		rm -f $CMN_BL_FILE 
	fi
}

# start running our gets
bogon_list 
ipdeny_country
fetch_blacklist

# when done fetching all files, issue a restart to the firewall
iptables_reload

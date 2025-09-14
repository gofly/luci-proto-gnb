#!/bin/sh

[ -x /usr/bin/gnb ] || exit 0

[ -n "$INCLUDE_ONLY" ] || {
	. /lib/functions.sh
	. ../netifd-proto.sh
	init_proto "$@"
}

prefix2netmask() {
	local prefix=$1
	local mask=$((0xffffffff << (32 - prefix) & 0xffffffff))
	printf "%d.%d.%d.%d\n" \
		$((mask >> 24)) \
		$((mask >> 16 & 0xff)) \
		$((mask >> 8 & 0xff)) \
		$((mask & 0xff))
}

proto_gnb_append() {
	append "$3" "$1" "~"
}

proto_gnb_peer_address() {
	local section="$1" this_node_id="$2"
	local disabled node_id nodetype address

	config_get disabled "$section" disabled
	config_get node_id "$section" node_id
	config_get nodetype "$section" node_type
	config_get address "$section" address

	[ "$disabled" != '1' ] && [ -n "$address" ] && [ "$this_node_id" != "$node_id" ] && \
		for addr in $address; do
				echo "${nodetype// /}|$node_id|${addr%:*}|${addr#*:}"
		done
}

proto_gnb_peer_route() {
	local section="$1" this_node_id="$2"
	local disabled node_id ipaddr subnet

	config_get disabled "$section" disabled
	config_get node_id "$section" node_id
	config_get ipaddr "$section" ipaddr
	config_get subnet "$section" subnet

	[ "$disabled" != '1' ] && {
		[ "$this_node_id" != "$node_id" ] && [ -n "$ipaddr" ] && \
			echo "$node_id|${ipaddr%/*}|$(prefix2netmask ${ipaddr#*/})"
		[ -n "$subnet" ] && {
			for sub in $subnet; do
				echo "$node_id|${sub%/*}|$(prefix2netmask ${sub#*/})"
			done
		}
	}
}

proto_gnb_peer_public_key() {
	local section="$1" this_node_id="$2" keydir="$3"
	local disabled node_id public_key

	config_get disabled "$section" disabled
	config_get node_id "$section" node_id
	config_get public_key "$section" public_key

	[ "$disabled" != '1' ] && [ "$this_node_id" != "$node_id" ] && echo "$node_id~$public_key"
}

proto_gnb_peer_script() {
	local section="$1" this_node_id="$2"
	local disabled node_id ipaddr route_subnet subnet

	config_get disabled "$section" disabled
	config_get node_id "$section" node_id
	config_get ipaddr "$section" ipaddr
	config_get route_subnet "$section" route_subnet
	config_get subnet "$section" subnet

	[ "$disabled" != '1' ] && [ "$route_subnet" != '0' ] && [ "$this_node_id" != "$node_id" ] && {
		for sub in $subnet; do
				echo "proto_add_ipv4_route ${sub%/*} $(prefix2netmask ${sub#*/}) ${ipaddr%/*}"
		done
	}
}

proto_gnb_init_config() {
	proto_config_add_int 'node_id:range(1000,9999)'
	proto_config_add_string private_key
	proto_config_add_string public_key
	proto_config_add_string 'ipaddr:cidr4'
	proto_config_add_string passcode
	proto_config_add_string crypto
	proto_config_add_boolean 'multisocket:bool'
	proto_config_add_int 'mtu:uinteger'
	proto_config_add_array 'listen:list(uinteger)'

	no_device=1
	available=1
}

proto_gnb_setup() {
	local network="$1"

	local node_id private_key public_key ipaddr passcode crypto \
		multisocket mtu listen listens
	json_get_vars node_id private_key public_key ipaddr \
		passcode crypto multisocket mtu
	json_for_each_item proto_gnb_append listen listens

		local iface="gnb-$network" \
				confdir="/var/etc/gnb/$network"

	rm -rf $confdir/*
	mkdir -p $confdir/security $confdir/ed25519 $confdir/scripts \
		/var/run/gnb /tmp/log/gnb/$network

	{
		echo "nodeid $node_id"
		[ -n "$listens" ] && echo $listens | sed 's/~/\n/g' | while read line; do echo listen $line; done
		[ -n "$passcode" ] && echo "passcode $passcode"
		[ -n "$crypto" ] && echo "crypto $crypto"
		[ "$multisocket" = 1 ] && echo "multi-socket on" || echo "multi-socket off"
		[ -n "$mtu" ] && echo "mtu $mtu"
		echo "ctl-block /var/run/gnb/${network}.map"
		echo "node-cache-file /var/run/gnb/${network}.nodes"
		echo "pid-file /var/run/gnb/${network}.pid"
		echo "log-file-path /tmp/log/gnb/${network}"
	} > $confdir/node.conf

	echo $private_key > $confdir/security/$node_id.private
	echo $public_key > $confdir/security/$node_id.public

	config_load network
	config_foreach proto_gnb_peer_address "gnb_$network" $node_id > $confdir/address.conf
	{
		echo "$node_id|${ipaddr%/*}|$(prefix2netmask ${ipaddr#*/})"
		config_foreach proto_gnb_peer_route "gnb_$network" $node_id
	}> $confdir/route.conf
	config_foreach proto_gnb_peer_public_key "gnb_$network" $node_id | while read line; do
		echo ${line#*~} > $confdir/ed25519/${line%~*}.public
	done

	{
		cat << EOF
#!/bin/sh
. /lib/netifd/netifd-proto.sh
proto_init_update $iface 1
proto_add_ipv4_address ${ipaddr%/*} ${ipaddr#*/}
$(config_foreach proto_gnb_peer_script "gnb_$network" $node_id)
proto_send_update $network
EOF
	} > $confdir/scripts/if_up_linux.sh

	chmod 755 $confdir/scripts/if_up_linux.sh

	proto_run_command "$network" /usr/bin/gnb -c $confdir -i "$iface" -q
}

proto_gnb_teardown() {
	local network="$1"
	local confdir="/var/etc/gnb/$network"

	logger -t gnb "stopping..."
	proto_kill_command "$network"
	rm -rf $confdir
	logger -t gnb "stopped."
}

proto_gnb_renew() {
	local iface="$1"
	logger -t gnb "renew $iface ..."
}

[ -n "$INCLUDE_ONLY" ] || {
	add_protocol gnb
}

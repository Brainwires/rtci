#!/usr/bin/env bash
# Network topology of the test environment, built from Linux network namespaces inside the
# test container (never on the host). `topology.sh up` / `topology.sh down` / `topology.sh show`.
#
#                         wan (bridge br-wan, 203.0.113.0/24, TEST-NET-3)
#     +--------------+--------------+------------------+-------------------------+
#   turn            open-a         open-b       r-<nat>-<x> (8 NAT routers)
#   .10 coturn      .50            .51           WAN .20-.27, LAN 10.<n>.0.1/24
#   (STUN/TURN      (public hosts: browser            |
#    UDP/TCP/TLS)    and Rust peers, netem)        h-<nat>-<x>   10.<n>.0.2 (a host behind it)
#
#   mdns: bridge br-mdns (10.99.0.0/24, a LAN with multicast) joining m-a (.2) and m-b (.3).
#
# NAT types (iptables in the router namespace, RFC 4787 behaviour):
#   fullcone        endpoint-independent mapping and filtering: SNAT, every inbound packet to
#                   the mapped port is forwarded to the host.
#   restricted      endpoint-independent mapping, address-dependent filtering: inbound only
#                   from addresses the host has sent to (an ipset the outbound path fills).
#   portrestricted  endpoint-independent mapping, address-and-port-dependent filtering (Linux
#                   conntrack with port-preserving MASQUERADE).
#   symmetric       address-and-port-dependent mapping (MASQUERADE --random-fully: a new
#                   external port per destination) and filtering.
set -euo pipefail

NATS=(fullcone restricted portrestricted symmetric)
SIDES=(a b)
TURN_IP=203.0.113.10
OPEN_A_IP=203.0.113.50
OPEN_B_IP=203.0.113.51

VETH_N=0
ns() { ip netns exec "$@"; }

add_ns() {
  ip netns add "$1"
  ns "$1" ip link set lo up
  # Hosts never answer for anything but their own addresses; no IPv6 noise in captures.
  ns "$1" sysctl -qw net.ipv6.conf.all.disable_ipv6=1
}

# veth from namespace $1 (interface $2, address $3) to the bridge $4 in namespace $5.
attach() {
  local nsname=$1 ifname=$2 addr=$3 bridge=$4 brns=$5
  VETH_N=$((VETH_N + 1))
  local peer="vb$VETH_N"
  ip link add "$ifname" netns "$nsname" type veth peer name "$peer" netns "$brns"
  ns "$brns" ip link set "$peer" master "$bridge" up
  ns "$nsname" ip addr add "$addr" dev "$ifname"
  ns "$nsname" ip link set "$ifname" up
}

up() {
  modprobe -q sch_netem 2>/dev/null || true
  add_ns wan
  ns wan ip link add br-wan type bridge
  ns wan ip link set br-wan up

  add_ns turn
  attach turn eth0 "$TURN_IP/24" br-wan wan
  add_ns open-a
  attach open-a eth0 "$OPEN_A_IP/24" br-wan wan
  add_ns open-b
  attach open-b eth0 "$OPEN_B_IP/24" br-wan wan

  local n=0
  for nat in "${NATS[@]}"; do
    for side in "${SIDES[@]}"; do
      local r="r-$nat-$side" h="h-$nat-$side" wan_ip="203.0.113.$((20 + n))" lan="10.$((10 + n)).0"
      add_ns "$r"
      add_ns "$h"
      attach "$r" wan0 "$wan_ip/24" br-wan wan
      ip link add lan0 netns "$r" type veth peer name eth0 netns "$h"
      ns "$r" ip addr add "$lan.1/24" dev lan0
      ns "$r" ip link set lan0 up
      ns "$h" ip addr add "$lan.2/24" dev eth0
      ns "$h" ip link set eth0 up
      ns "$h" ip route add default via "$lan.1"
      ns "$r" sysctl -qw net.ipv4.ip_forward=1
      nat_rules "$r" "$nat" "$wan_ip" "$lan.2"
      n=$((n + 1))
    done
  done

  add_ns mdns
  ns mdns ip link add br-mdns type bridge
  ns mdns ip link set br-mdns up
  add_ns m-a
  attach m-a eth0 10.99.0.2/24 br-mdns mdns
  add_ns m-b
  attach m-b eth0 10.99.0.3/24 br-mdns mdns
  for h in m-a m-b; do
    # Multicast (mDNS, 224.0.0.251) leaves through the LAN interface.
    ns "$h" ip route add 224.0.0.0/4 dev eth0
  done
}

nat_rules() {
  local r=$1 nat=$2 wan_ip=$3 host=$4
  local ipt="ip netns exec $r iptables"
  $ipt -P FORWARD DROP
  $ipt -A FORWARD -i lan0 -o wan0 -j ACCEPT
  $ipt -A FORWARD -i wan0 -o lan0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  case "$nat" in
    fullcone)
      $ipt -t nat -A POSTROUTING -o wan0 -j SNAT --to-source "$wan_ip"
      $ipt -t nat -A PREROUTING -i wan0 -j DNAT --to-destination "$host"
      $ipt -A FORWARD -i wan0 -o lan0 -d "$host" -j ACCEPT
      ;;
    restricted)
      ip netns exec "$r" ipset create contacted hash:ip timeout 300
      $ipt -t nat -A POSTROUTING -o wan0 -j SNAT --to-source "$wan_ip"
      $ipt -I FORWARD 1 -i lan0 -o wan0 -j SET --add-set contacted dst --exist
      $ipt -t nat -A PREROUTING -i wan0 -m set --match-set contacted src -j DNAT --to-destination "$host"
      $ipt -A FORWARD -i wan0 -o lan0 -d "$host" -m set --match-set contacted src -j ACCEPT
      ;;
    portrestricted)
      $ipt -t nat -A POSTROUTING -o wan0 -j SNAT --to-source "$wan_ip"
      ;;
    symmetric)
      $ipt -t nat -A POSTROUTING -o wan0 -j SNAT --to-source "$wan_ip" --random-fully
      ;;
    *) echo "unknown NAT type $nat" >&2; exit 2 ;;
  esac
}

down() {
  for n in $(ip netns list | awk '{print $1}'); do ip netns del "$n" 2>/dev/null || true; done
}

show() {
  ip netns list
  for nat in "${NATS[@]}"; do
    for side in "${SIDES[@]}"; do
      echo "== r-$nat-$side"
      ip netns exec "r-$nat-$side" iptables -t nat -S | grep -v '^-P'
    done
  done
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  show) show ;;
  *) echo "usage: $0 up|down|show" >&2; exit 2 ;;
esac

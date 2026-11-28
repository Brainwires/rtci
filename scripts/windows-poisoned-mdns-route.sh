#!/usr/bin/env bash
# Windows only (Git bash on a CI runner, Python on PATH). Leaves the host's route for the mDNS
# group 224.0.0.251 on loopback (a datagram sent to the group from a socket bound to 127.0.0.1:
# the destination-cache entry it leaves behind outlives the process), checks that it did, then
# runs the tests that must hold on such a host, and deletes the entry again when the shell is
# elevated (GitHub-hosted Windows is). Exits 1 if the host could not be put in that state, so a
# run that proves nothing cannot pass. The delete runs from an EXIT trap, so a failing test,
# an interrupted run or a failed precondition still leaves the host as it found it.
#
# First, while the route is still where the host had it, the stream driver's two loopback tests
# (ignored on Windows elsewhere): with the 0.3.0 default the drivers on 127.0.0.1 must leave the
# route off loopback (that test asserts the route is off loopback before it starts, so a host
# already in that state fails it), then the drivers asked for mDNS on loopback
# (`mdns_on_loopback_on_windows`) must resolve each other there; what that does to the route is
# printed.
set -u
answer() { python -c "import socket as k; s=k.socket(k.AF_INET,k.SOCK_DGRAM); s.connect(('224.0.0.251',5353)); print(s.getsockname()[0])"; }
show() {
  echo "### [$1] group answer: $(answer)"
  netsh interface ipv4 show destinationcache address=224.0.0.251 2>&1 | grep -v '^\s*$' | sed "s/^/### [$1] destcache /"
}
# shellcheck disable=SC2329 # run by the EXIT trap
clean() {
  trap - EXIT
  local loopback_index
  loopback_index=$(netsh interface ipv4 show interfaces 2>&1 | awk '/Loopback/ {print $1; exit}')
  if netsh interface ipv4 delete destinationcache interface="$loopback_index" address=224.0.0.251 >/dev/null 2>&1; then
    show cleaned
  else
    echo '### not elevated: the destination-cache entry stays (administrator prompt needed)'
  fi
}
show before
trap clean EXIT
trap 'exit 130' INT TERM
status=0
driver_test() {
  echo "### run: driver test $1"
  RTCI_EXPECT_HOST_MULTICAST=windows cargo test -p rtci-stream-driver --test mdns -- --ignored --exact "$1" --nocapture || status=1
}
driver_test by_default_drivers_on_loopback_leave_the_group_route_off_loopback
show after-default-drivers
driver_test drivers_on_loopback_resolve_each_other_on_the_loopback_interface
show after-drivers-asked-for-loopback-mdns
# As agent-test run 46049992555 measured it: a socket joined to the group on 127.0.0.1 is
# open, and another, bound to 127.0.0.1, sends to the group.
python -c "import socket as k; a=k.socket(k.AF_INET,k.SOCK_DGRAM); a.setsockopt(k.SOL_SOCKET,k.SO_REUSEADDR,1); a.bind(('0.0.0.0',5353)); a.setsockopt(k.IPPROTO_IP,k.IP_ADD_MEMBERSHIP,k.inet_aton('224.0.0.251')+k.inet_aton('127.0.0.1')); b=k.socket(k.AF_INET,k.SOCK_DGRAM); b.bind(('127.0.0.1',0)); b.sendto(bytes(12),('224.0.0.251',5353)); b.close(); a.close()"
show poisoned
if [ "$(answer)" != 127.0.0.1 ]; then
  echo '### PRECONDITION NOT MET: the route for 224.0.0.251 is not on loopback'
  exit 1
fi
cargo test -p rtci-mdns --test multicast_interface -- --ignored --nocapture || status=1
for cmd in "$@"; do
  echo "### run: $cmd"
  bash -c "$cmd" || status=1
done
exit $status

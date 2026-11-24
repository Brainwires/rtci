#!/usr/bin/env bash
# Starts coturn in the "turn" namespace with a fresh self-signed CA and server certificate
# (SAN IP:203.0.113.10, DNS:turn.rtc.test). The CA is what TURN-over-TLS clients trust.
set -euo pipefail
D=/run/rtc-env
mkdir -p "$D"
cd "$D"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
  -subj "/CN=rtc test-env CA" -keyout ca.key -out ca.crt 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj "/CN=turn.rtc.test" -keyout turn.key -out turn.csr 2>/dev/null
printf 'subjectAltName=IP:203.0.113.10,DNS:turn.rtc.test\nextendedKeyUsage=serverAuth\n' > ext.cnf
openssl x509 -req -in turn.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 \
  -extfile ext.cnf -out turn.crt 2>/dev/null
ip netns exec turn turnserver -c "$(dirname "$0")/turnserver.conf" > "$D/turnserver.log" 2>&1 &
# The short-nonce server for tests/testenv_turn.rs (turnserver-stale.conf).
ip netns exec turn turnserver -c "$(dirname "$0")/turnserver-stale.conf" > "$D/turnserver-stale.log" 2>&1 &
# The server for tests/testenv_turn_client.rs (turnserver-client.conf). Its IPv6 relay address
# lives on the namespace's loopback; the topology turns IPv6 off everywhere else.
{ ip netns exec turn sysctl -qw net.ipv6.conf.lo.disable_ipv6=0 \
  && ip -n turn -6 addr add fd00:203:113::10/128 dev lo; } \
  || echo "no IPv6 address on the turn namespace's loopback: the IPv6 relay tests will fail" >&2
ip netns exec turn turnserver -c "$(dirname "$0")/turnserver-client.conf" > "$D/turnserver-client.log" 2>&1 &
# The TLS 1.2-only server for tests/testenv_turn_streams.rs (turnserver-tls12.conf): coturn has
# no highest-version option, so its libssl is configured to stop at TLS 1.2.
OPENSSL_CONF="$(dirname "$0")/openssl-tls12.cnf" \
  ip netns exec turn turnserver -c "$(dirname "$0")/turnserver-tls12.conf" > "$D/turnserver-tls12.log" 2>&1 &
wait_for() {
  local port=$1 log=$2 proto=${3:-u}
  for _ in $(seq 1 50); do
    if ip netns exec turn ss -ln"$proto" | grep -q "203.0.113.10:$port"; then return 0; fi
    sleep 0.2
  done
  echo "coturn on $port did not start:" >&2; cat "$log" >&2; return 1
}
wait_for 3478 "$D/turnserver.log" && wait_for 5349 "$D/turnserver.log" \
  && wait_for 5349 "$D/turnserver.log" t \
  && wait_for 3479 "$D/turnserver-stale.log" \
  && wait_for 3480 "$D/turnserver-client.log" \
  && wait_for 5350 "$D/turnserver-tls12.log" t \
  && echo "coturn $(turnserver --version) up (3478, 5349 TLS and DTLS, 3479, 3480, 5350 TLS 1.2 only)"

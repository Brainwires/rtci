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
for _ in $(seq 1 50); do
  if ip netns exec turn ss -lun | grep -q '203.0.113.10:3478'; then echo "coturn up"; exit 0; fi
  sleep 0.2
done
echo "coturn did not start:" >&2; cat "$D/turnserver.log" >&2; exit 1

#!/usr/bin/env bash
# The aiortc peer runs on the image's venv (scripts/test-env/Dockerfile: exactly the wheels
# image/requirements.txt pins). Nothing to compile: this checks the venv imports and writes the
# launcher.
set -euo pipefail
OUT=$1
HERE=$(cd "$(dirname "$0")" && pwd)
PY=/opt/peers/aiortc/venv/bin/python
"$PY" -I -c 'import aiortc, aioice, av, OpenSSL, pylibsrtp, websockets; print("aiortc", aiortc.__version__, "av", av.__version__, "OpenSSL", OpenSSL.__version__, "codecs", sorted(av.codecs_available & {"libvpx", "libopus", "libx264", "libopenh264", "h264"}))'
cat > "$OUT/aiortc-peer" <<LAUNCH
#!/usr/bin/env bash
exec $PY -I "$HERE/peer.py" "\$@"
LAUNCH
chmod +x "$OUT/aiortc-peer"

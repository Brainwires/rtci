"""aiortc-peer: the aiortc (Python) peer of the interop matrix.

Runs one plan (scripts/test-env/peers/README.md) against examples/interop-peer over the browser
page's WebSocket signalling and prints the result as the last line of stdout. Media comes from
aiortc's own sources and encoders (its test tracks: 640x480 frames at 30 fps, silence) through
PyAV, so aiortc's encoders and payloaders are what Rust receives.

aiortc exposes no RTCP to the application; the result's `rtcp` counts are taken by wrapping the
RTP sender's and receiver's RTCP handlers (observation only: each packet is passed on).
"""

import asyncio
import json
import logging
import os
import re
import ssl
import struct
import sys
import time
from collections import defaultdict

import websockets
from aiortc import (
    RTCConfiguration,
    RTCIceServer,
    RTCPeerConnection,
    RTCRtpSender,
    RTCSessionDescription,
)
from aiortc import rtcrtpreceiver, rtcrtpsender
from aiortc.mediastreams import AudioStreamTrack, MediaStreamError, VideoStreamTrack
from aiortc.rtcconfiguration import RTCBundlePolicy, RTCIceTransportPolicy
from aiortc.rtp import (
    RTCP_PSFB_FIR,
    RTCP_PSFB_PLI,
    RTCP_RTPFB_NACK,
    RtcpByePacket,
    RtcpPsfbPacket,
    RtcpRrPacket,
    RtcpRtpfbPacket,
    RtcpSdesPacket,
    RtcpSrPacket,
)
from aiortc.sdp import candidate_from_sdp

log = logging.getLogger("aiortc-peer")

RTCP_IN = defaultdict(int)


def rtcp_name(p):
    if isinstance(p, RtcpSrPacket):
        return "sr"
    if isinstance(p, RtcpRrPacket):
        return "rr"
    if isinstance(p, RtcpSdesPacket):
        return "sdes"
    if isinstance(p, RtcpByePacket):
        return "bye"
    if isinstance(p, RtcpRtpfbPacket):
        return {RTCP_RTPFB_NACK: "nack", 15: "twcc"}.get(p.fmt, f"rtpfb/{p.fmt}")
    if isinstance(p, RtcpPsfbPacket):
        return {RTCP_PSFB_PLI: "pli", RTCP_PSFB_FIR: "fir", 15: "remb"}.get(p.fmt, f"psfb/{p.fmt}")
    return type(p).__name__


def instrument(cls):
    orig = cls._handle_rtcp_packet

    async def counted(self, packet):
        RTCP_IN[rtcp_name(packet)] += 1
        return await orig(self, packet)

    cls._handle_rtcp_packet = counted


instrument(rtcrtpreceiver.RTCRtpReceiver)
instrument(rtcrtpsender.RTCRtpSender)

# OpenSSL names of the suites aiortc's DTLS offers, as IANA names (the W3C dtlsCipher form).
IANA = {
    "ECDHE-ECDSA-AES128-GCM-SHA256": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "ECDHE-RSA-CHACHA20-POLY1305": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "ECDHE-ECDSA-AES128-SHA": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "ECDHE-ECDSA-AES256-SHA": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
}
VERSIONS = {"DTLSv1.2": "FEFD", "DTLSv1": "FEFF"}
MIMES = {"opus": "audio/opus", "vp8": "video/vp8", "vp9": "video/vp9", "h264": "video/h264"}


class Failure(Exception):
    pass


class NotApplicable(Exception):
    def __init__(self, reason, cite):
        super().__init__(reason)
        self.reason, self.cite = reason, cite


def strip_bundle(sdp):
    return re.sub(r"(?m)^a=group:BUNDLE[^\r\n]*\r?\n", "", sdp)


def ufrag_of(sdp):
    m = re.search(r"(?m)^a=ice-ufrag:(\S+)", sdp or "")
    return m.group(1) if m else None


def rust_port(sdp):
    m = re.search(r"(?mi)^a=candidate:\S+ \d+ udp \d+ \S+ (\d+) typ host", sdp or "")
    return int(m.group(1)) if m else 0


class Peer:
    def __init__(self, plan):
        self.plan = plan
        self.cfg = plan.get("config") or {}
        self.deadline = time.monotonic() + plan.get("timeout_ms", 60000) / 1000
        self.ws = None
        self.pc = None
        self.inbox = asyncio.Queue()
        self.scenario_sent = False
        self.impolite = False
        self.munge_remote = ""
        self.dcs = {}
        self.local_labels = set()
        self.tracks = {}  # kind -> (track, transceiver)
        self.answers_got = 0
        self.answers_sent = 0
        self.reports = 0
        self.res = {
            "ok": False, "error": None, "na": None, "version": None, "connectionState": None,
            "steps": [], "datachannels": {}, "remoteChannels": {}, "rtp": {}, "rtpSent": {},
            "coverage": [], "rtcp": {}, "rtcpSent": defaultdict(int), "twccSent": False,
            "selectedPair": None, "dtls": None, "sctp": None, "localCandidates": [], "trickled": 0,
            "descriptions": [], "remoteOffers": 0, "ignoredOffers": 0, "rust": None, "rustErrors": [],
        }

    # ---- setup ----

    async def setup(self):
        try:
            import aiortc

            self.res["version"] = f"aiortc {aiortc.__version__}"
        except Exception:
            pass
        if self.cfg.get("caFile"):
            # OpenSSL's default verify paths read SSL_CERT_FILE: the TURN-over-TLS server's CA.
            os.environ["SSL_CERT_FILE"] = self.cfg["caFile"]
            # The environment's coturn answers every TLS 1.3 ClientHello with a
            # handshake_failure (tests/testenv/mod.rs); aioice's TLS goes through asyncio's
            # default context, so that context offers TLS 1.2 at most.
            orig = ssl.create_default_context

            def tls12(*a, **k):
                c = orig(*a, **k)
                c.maximum_version = ssl.TLSVersion.TLSv1_2
                return c

            ssl.create_default_context = tls12
        servers = [
            RTCIceServer(urls=s["urls"], username=s.get("username"), credential=s.get("credential"))
            for s in self.cfg.get("iceServers") or []
        ]
        policy = RTCIceTransportPolicy.RELAY if self.cfg.get("iceTransportPolicy") == "relay" else RTCIceTransportPolicy.ALL
        bundle = {
            "max-compat": RTCBundlePolicy.MAX_COMPAT,
            "max-bundle": RTCBundlePolicy.MAX_BUNDLE,
        }.get(self.cfg.get("bundlePolicy"), RTCBundlePolicy.BALANCED)
        self.pc = RTCPeerConnection(RTCConfiguration(iceServers=servers, iceTransportPolicy=policy, bundlePolicy=bundle))

        @self.pc.on("datachannel")
        def on_dc(dc):
            self.dcs.setdefault(dc.label, dc)
            self.watch(dc, remote=True)

        @self.pc.on("track")
        def on_track(track):
            async def sink():
                while True:
                    try:
                        await track.recv()
                    except MediaStreamError:
                        return

            asyncio.ensure_future(sink())

        self.ws = await websockets.connect(self.plan["ws"], max_size=64 << 20)

        async def reader():
            try:
                async for text in self.ws:
                    await self.inbox.put(json.loads(text))
            finally:
                await self.inbox.put(None)

        asyncio.ensure_future(reader())

    def watch(self, dc, remote):
        label = dc.label

        @dc.on("message")
        def on_message(m):
            if remote and label not in self.local_labels and label not in self.res["remoteChannels"]:
                self.res["remoteChannels"][label] = m if isinstance(m, str) else m.decode("utf-8", "replace")
            e = self.res["datachannels"].setdefault(label, {"got": [], "sizes": []})
            if isinstance(m, str):
                e["got"].append(m)
                e["sizes"].append(len(m.encode()))
            else:
                e["got"].append(struct.unpack(">I", m[:4])[0] if len(m) >= 4 else -1)
                e["sizes"].append(len(m))

    # ---- signalling ----

    async def send(self, m):
        if m["type"] in ("offer", "request-offer") and not self.scenario_sent:
            m["scenario"] = self.plan.get("scenario") or {}
            self.scenario_sent = True
        await self.ws.send(json.dumps(m))

    def record(self, d, t, sdp):
        self.res["descriptions"].append([d, t, sdp])

    async def send_description(self, typ, sdp):
        # aiortc gathers every candidate while it applies a description: they are all in it,
        # and none is trickled.
        self.record("sent", typ, sdp)
        self.res["localCandidates"] += [
            l[2:] for l in sdp.splitlines() if l.startswith("a=candidate:")
        ]
        await self.send({"type": typ, "sdp": sdp})
        if typ == "answer":
            self.answers_sent += 1

    async def handle(self, m):
        t = m.get("type")
        if t == "answer":
            sdp = m["sdp"]
            self.record("received", "answer", sdp)
            await self.pc.setRemoteDescription(RTCSessionDescription(sdp=sdp, type="answer"))
            self.answers_got += 1
        elif t == "offer":
            sdp = m["sdp"]
            self.res["remoteOffers"] += 1
            if self.impolite and self.pc.signalingState != "stable":
                self.res["ignoredOffers"] += 1
                self.record("ignored", "offer", sdp)
                return
            if self.munge_remote == "strip-bundle":
                sdp = strip_bundle(sdp)
            self.munge_remote = ""
            self.record("received", "offer", sdp)
            await self.pc.setRemoteDescription(RTCSessionDescription(sdp=sdp, type="offer"))
            await self.pc.setLocalDescription(await self.pc.createAnswer())
            await self.send_description("answer", self.pc.localDescription.sdp)
        elif t == "candidate":
            c = m.get("candidate") or {}
            line = c.get("candidate") or ""
            if line:
                cand = candidate_from_sdp(line.split(":", 1)[1])
                cand.sdpMid = c.get("sdpMid")
                cand.sdpMLineIndex = c.get("sdpMLineIndex")
                await self.pc.addIceCandidate(cand)
        elif t == "report":
            self.res["rust"] = m
            self.reports += 1
        elif t == "error":
            self.res["rustErrors"].append(str(m.get("error")))

    async def pump(self, until, what, cond):
        until = min(until, self.deadline)
        while True:
            v = cond()
            if asyncio.iscoroutine(v):
                v = await v
            if v:
                return
            if time.monotonic() > until:
                raise Failure(f"timed out waiting for {what}")
            try:
                m = await asyncio.wait_for(self.inbox.get(), 0.05)
            except asyncio.TimeoutError:
                continue
            if m is None:
                raise Failure(f"the signalling connection closed while waiting for {what}")
            await self.handle(m)

    async def wait(self, ms):
        try:
            await self.pump(time.monotonic() + ms / 1000, "", lambda: False)
        except Failure as e:
            if not str(e).startswith("timed out"):
                raise

    # ---- stats ----

    async def inbound(self):
        out = defaultdict(lambda: [0, 0])
        ssrcs = defaultdict(list)
        for s in (await self.pc.getStats()).values():
            if s.type == "inbound-rtp":
                out[s.kind][0] += s.packetsReceived
                ssrcs[s.kind].append(s.ssrc)
        return out, ssrcs

    async def rtp_count(self, kind):
        out, _ = await self.inbound()
        return out[kind][0]

    def rust_rtp(self, kind):
        rtp = (self.res["rust"] or {}).get("rtp") or {}
        return sum(v for k, v in rtp.items() if k.startswith(f"{kind}:"))

    async def report(self):
        n0 = self.reports
        await self.send({"type": "report"})
        await self.pump(time.monotonic() + 5, "Rust's report", lambda: self.reports > n0)

    # ---- steps ----

    def prefer(self, transceiver, kind, codec):
        mime = MIMES[codec]
        caps = RTCRtpSender.getCapabilities(kind).codecs
        first = [c for c in caps if c.mimeType.lower() == mime]
        if not first:
            raise NotApplicable(
                f"aiortc has no {mime} codec",
                f"aiortc {self.res['version']} RTCRtpSender.getCapabilities(\"{kind}\") lists no {mime}",
            )
        rtx = [c for c in caps if c.mimeType.lower() == f"{kind}/rtx"]
        transceiver.setCodecPreferences(first + rtx)

    async def control(self, ev):
        print(json.dumps(ev), flush=True)
        line = await asyncio.get_running_loop().run_in_executor(None, sys.stdin.readline)
        reply = json.loads(line or "{}")
        if not reply.get("ok"):
            raise Failure(f"the runner refused {ev['event']}: {reply.get('error')}")
        return reply

    async def offer(self, st):
        await self.pc.setLocalDescription(await self.pc.createOffer())
        local = self.pc.localDescription.sdp
        self.record("local", "offer", local)
        got = self.answers_got
        await self.send_description("offer", strip_bundle(local) if st.get("munge") == "strip-bundle" else local)
        await self.pump(
            time.monotonic() + st.get("ms", 15000) / 1000,
            "the answer",
            lambda: self.answers_got > got and self.pc.signalingState == "stable",
        )

    async def echo(self, st):
        label, count, size = st["label"], st.get("count", 1), st.get("size", 0)
        until = time.monotonic() + st.get("ms", 20000) / 1000
        await self.pump(until, f"channel {label} to open", lambda: label in self.dcs and self.dcs[label].readyState == "open")
        dc = self.dcs[label]
        base = len(self.res["datachannels"].get(label, {}).get("got", []))
        for i in range(count):
            if size:
                b = bytearray([i % 251]) * size
                b[:4] = struct.pack(">I", i)
                dc.send(bytes(b))
            else:
                dc.send(f"msg-{i}")
            while dc.bufferedAmount > 1 << 20:
                await self.wait(5)
        await self.pump(
            until,
            f"{count} echoed messages on {label}",
            lambda: len(self.res["datachannels"].get(label, {}).get("got", [])) - base >= count,
        )

    async def step(self, st):
        op = st["op"]
        extra = {}
        if op == "dc":
            kw = {"ordered": st.get("ordered", True)}
            if st.get("maxRetransmits") is not None:
                kw["maxRetransmits"] = st["maxRetransmits"]
            if st.get("maxPacketLifeTime") is not None:
                kw["maxPacketLifeTime"] = st["maxPacketLifeTime"]
            if st.get("negotiated") is not None:
                kw["negotiated"], kw["id"] = True, st["negotiated"]
            dc = self.pc.createDataChannel(st["label"], **kw)
            self.dcs[st["label"]] = dc
            self.local_labels.add(st["label"])
            self.watch(dc, remote=False)
        elif op == "track":
            kind, codec = st["kind"], st["codec"].lower()
            if st.get("simulcast"):
                raise NotApplicable("aiortc does not send simulcast", "aiortc RTCRtpSender sends one encoding")
            track = AudioStreamTrack() if kind == "audio" else VideoStreamTrack()
            # A transceiver now, so an offer from Rust attaches to it (setRemoteDescription
            # takes an unassigned transceiver of the kind) and the codec preference holds.
            tr = self.pc.addTransceiver(track, direction="sendrecv")
            self.prefer(tr, kind, codec)
            self.tracks[kind] = (track, tr)
        elif op == "transceiver":
            self.pc.addTransceiver(st["kind"], direction=st.get("direction", "recvonly"))
        elif op == "remove-track":
            track, tr = self.tracks.pop(st["kind"])
            await tr.sender.replaceTrack(None)
            tr.direction = "recvonly"
            track.stop()
        elif op == "offer":
            if st.get("iceRestart"):
                raise NotApplicable("aiortc has no ICE restart", "aiortc RTCPeerConnection has no restartIce")
            await self.offer(st)
        elif op == "request-offer":
            m = {"type": "request-offer"}
            if st.get("tracks"):
                m["tracks"] = st["tracks"]
            if st.get("iceRestart"):
                m["ice_restart"] = True
            self.munge_remote = st.get("munge", "")
            before = self.answers_sent
            await self.send(m)
            await self.pump(
                time.monotonic() + st.get("ms", 15000) / 1000,
                "Rust's offer, answered",
                lambda: self.answers_sent > before and self.pc.signalingState == "stable",
            )
        elif op == "connected":
            def connected():
                if self.pc.connectionState == "failed":
                    raise Failure("connection failed")
                return self.pc.connectionState == "connected"

            await self.pump(time.monotonic() + st.get("ms", 30000) / 1000, "the connection", connected)
        elif op == "echo":
            await self.echo(st)
        elif op == "await-channel":
            label = st["label"]
            await self.pump(
                time.monotonic() + st.get("ms", 15000) / 1000,
                f"channel {label} and its first message",
                lambda: label in self.res["remoteChannels"],
            )
        elif op == "await-rtp":
            kind = st["kind"]
            want = st.get("packets", 0)
            if st.get("more") is not None:
                want = await self.rtp_count(kind) + st["more"]
            until = time.monotonic() + st.get("ms", 20000) / 1000
            while await self.rtp_count(kind) < want:
                if time.monotonic() > until:
                    raise Failure(f"{await self.rtp_count(kind)} of {want} {kind} packets from Rust")
                await self.wait(200)
        elif op == "await-rust-rtp":
            kind, want = st["kind"], st.get("packets", 0)
            until = time.monotonic() + st.get("ms", 20000) / 1000
            while self.rust_rtp(kind) < want:
                if time.monotonic() > until:
                    raise Failure(f"Rust has {self.rust_rtp(kind)} of {want} {kind} packets")
                await self.report()
                await self.wait(300)
        elif op == "rtcp":
            _, ssrcs = await self.inbound()
            receivers = [t.receiver for t in self.pc.getTransceivers() if t.kind == "video"]
            if not ssrcs["video"] or not receivers:
                raise Failure("no video from Rust to send feedback about")
            for _ in range(3):
                for kind in st.get("types", []):
                    if kind != "pli":
                        # aiortc's receiver sends PLI and NACK only (RTCRtpReceiver).
                        continue
                    for ssrc in ssrcs["video"]:
                        for r in receivers:
                            await r._send_rtcp_pli(ssrc)
                        self.res["rtcpSent"]["pli"] += 1
                await self.wait(200)
        elif op == "impair":
            remote = self.pc.remoteDescription.sdp if self.pc.remoteDescription else ""
            await self.control({"event": "impair", "direction": st.get("direction"), "rustPort": rust_port(remote)})
            try:
                await self.wait(st.get("ms", 10000))
            finally:
                await self.control({"event": "unimpair"})
        elif op == "rollback":
            raise NotApplicable(
                "aiortc cannot roll back a description",
                "aiortc setLocalDescription / setRemoteDescription take only offers and answers (no \"rollback\" type)",
            )
        elif op == "glare":
            self.impolite = True
            await self.pc.setLocalDescription(await self.pc.createOffer())
            local = self.pc.localDescription.sdp
            self.record("local", "offer", local)
            await self.send({"type": "request-offer"})
            got = self.answers_got
            await self.send_description("offer", local)
            await self.pump(
                time.monotonic() + st.get("ms", 20000) / 1000,
                "the answer to our colliding offer",
                lambda: self.answers_got > got and self.pc.signalingState == "stable",
            )
        elif op == "wait":
            await self.wait(st.get("ms", 1000))
        elif op == "report":
            await self.report()
        else:
            raise Failure(f"unknown step {op!r}")
        return extra

    async def run(self):
        await self.setup()
        for i, st in enumerate(self.plan.get("steps", [])):
            t0 = time.monotonic()
            entry = {"op": st["op"], "ok": True}
            try:
                entry.update(await self.step(st))
            except NotApplicable:
                entry["ok"] = False
                self.res["steps"].append(entry)
                raise
            except Exception as e:
                entry["ok"], entry["error"] = False, f"{type(e).__name__}: {e}"
                entry["ms"] = int((time.monotonic() - t0) * 1000)
                self.res["steps"].append(entry)
                raise Failure(f"step {i} ({st['op']}): {type(e).__name__}: {e}") from e
            entry["ms"] = int((time.monotonic() - t0) * 1000)
            self.res["steps"].append(entry)

    async def collect(self):
        """What aiortc negotiated: its stats, its DTLS connection and nominated pair."""
        if not self.pc:
            return
        self.res["connectionState"] = self.pc.connectionState
        out, _ = await self.inbound()
        answers = [d[2] for d in self.res["descriptions"] if d[1] == "answer"]
        for kind, (packets, _) in out.items():
            codec = None
            if answers:
                sec = next((s for s in answers[-1].split("\nm=")[1:] if s.startswith(kind)), "")
                pts = sec.split("\n")[0].split()[3:4]
                m = re.search(rf"(?m)^a=rtpmap:{pts[0]} ([^/\s]+)/", sec) if pts else None
                codec = f"{kind}/{m.group(1)}".lower() if m else None
            self.res["rtp"][kind] = {"packets": packets, "bytes": None, "codec": codec}
        for s in (await self.pc.getStats()).values():
            if s.type == "outbound-rtp":
                e = self.res["rtpSent"].setdefault(s.kind, {"packets": 0, "bytes": 0})
                e["packets"] += s.packetsSent
                e["bytes"] += s.bytesSent
        self.res["rtcp"] = dict(RTCP_IN)
        dtls = None
        transports = [t.receiver.transport for t in self.pc.getTransceivers()]
        if self.pc.sctp:
            transports.append(self.pc.sctp.transport)
        for t in transports:
            try:
                s = t._ssl
                if s is None or t.state != "connected":
                    continue
                profile = s.get_selected_srtp_profile()
                dtls = {
                    "version": VERSIONS.get(s.get_protocol_version_name()),
                    "cipher": IANA.get(s.get_cipher_name(), s.get_cipher_name()),
                    "srtpProfile": profile.decode() if profile else None,
                    "role": t._role,
                }
                ice = t.transport._connection
                pair = ice._nominated.get(1)
                if pair:
                    lc, rc = pair.local_candidate, pair.remote_candidate
                    self.res["selectedPair"] = {
                        "local": {"candidateType": lc.type, "protocol": lc.transport, "address": lc.host, "port": lc.port, "relayProtocol": None},
                        "remote": {"candidateType": rc.type, "protocol": rc.transport, "address": rc.host, "port": rc.port},
                    }
                break
            except Exception as e:  # private attributes: report what can be read
                log.warning("reading DTLS / ICE state: %s", e)
        self.res["dtls"] = dtls
        if self.pc.sctp:
            self.res["sctp"] = {"maxMessageSize": self.pc.sctp.getCapabilities().maxMessageSize}


async def main():
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(asctime)s %(name)s %(message)s")
    with open(sys.argv[1]) as f:
        plan = json.load(f)
    p = Peer(plan)
    try:
        await asyncio.wait_for(p.run(), plan.get("timeout_ms", 60000) / 1000 + 5)
        p.res["ok"] = True
    except NotApplicable as e:
        p.res["na"] = {"reason": e.reason, "cite": e.cite}
    except asyncio.TimeoutError:
        p.res["error"] = "the plan's timeout passed"
    except Exception as e:
        p.res["error"] = str(e)
        log.exception("run failed")
    try:
        await asyncio.wait_for(p.collect(), 5)
    except Exception as e:
        log.warning("collect: %s", e)
    print(json.dumps({"result": p.res}, default=str), flush=True)
    try:
        if p.pc:
            await asyncio.wait_for(p.pc.close(), 3)
        if p.ws:
            await p.ws.close()
    except Exception:
        pass


if __name__ == "__main__":
    asyncio.run(main())

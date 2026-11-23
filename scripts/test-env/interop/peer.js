// In-page side of the interop tests: an RTCPeerConnection signalling with
// examples/interop-peer over a WebSocket. The browser offers; the Rust peer answers (and
// offers only when asked with "request-offer").
(() => {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  async function until(fn, ms, what) {
    const end = Date.now() + ms;
    while (Date.now() < end) {
      const v = await fn();
      if (v) return v;
      await sleep(100);
    }
    throw new Error(`timed out waiting for ${what}`);
  }

  function canvasStream(width = 320, height = 240) {
    const c = document.createElement("canvas");
    c.width = width;
    c.height = height;
    document.body.appendChild(c);
    const g = c.getContext("2d");
    let n = 0;
    setInterval(() => {
      n++;
      g.fillStyle = `hsl(${(n * 7) % 360} 80% 50%)`;
      g.fillRect(0, 0, width, height);
      g.fillStyle = "#fff";
      g.font = "40px sans-serif";
      g.fillText(String(n), 20 + (n % 200), 120);
    }, 33);
    return c.captureStream(30);
  }

  function audioStream() {
    const ctx = new AudioContext();
    const osc = ctx.createOscillator();
    osc.frequency.value = 440;
    const dst = ctx.createMediaStreamDestination();
    osc.connect(dst);
    osc.start();
    ctx.resume();
    return dst.stream;
  }

  function hasCodec(kind, mime, dir = "sender") {
    const caps = (dir === "sender" ? RTCRtpSender : RTCRtpReceiver).getCapabilities(kind);
    return !!caps && caps.codecs.some((c) => c.mimeType.toLowerCase() === mime.toLowerCase());
  }

  // Prefers `mime` and keeps the RTX format (RFC 4588): setCodecPreferences offers only what
  // its list has, so a list of the primary alone leaves RTX out of the offer, and the answer
  // then has none either (RFC 9429 section 5.3.1).
  function prefer(transceiver, kind, mime) {
    const caps = RTCRtpReceiver.getCapabilities(kind).codecs;
    const first = caps.filter((c) => c.mimeType.toLowerCase() === mime.toLowerCase());
    if (!first.length) throw new Error(`no ${mime}`);
    const rtx = caps.filter((c) => c.mimeType.toLowerCase() === `${kind}/rtx`);
    if (transceiver.setCodecPreferences) transceiver.setCodecPreferences([...first, ...rtx]);
  }

  // Whether trickled candidate `c` (RTCIceCandidateInit) belongs to description `sdp`: a media
  // section with its sdpMid (else at its sdpMLineIndex) whose ICE ufrag (the section's, else
  // the session's) is the candidate's usernameFragment, when it names one.
  function candidateFits(c, sdp) {
    if (!sdp) return false;
    const [session, ...media] = sdp.split(/\r?\nm=/);
    const ufrag = (text) => (text.match(/^a=ice-ufrag:(\S+)/m) || [])[1];
    let section;
    if (c.sdpMid !== null && c.sdpMid !== undefined) {
      section = media.find((m) => (m.match(/^a=mid:(\S+)/m) || [])[1] === c.sdpMid);
    } else if (c.sdpMLineIndex !== null && c.sdpMLineIndex !== undefined) section = media[c.sdpMLineIndex];
    else return true;
    if (section === undefined) return false;
    return !c.usernameFragment || (ufrag(section) || ufrag(session)) === c.usernameFragment;
  }

  // opts: insertableStreams (Chromium's encoded streams), rtc (more RTCConfiguration members:
  // iceServers, iceTransportPolicy, ...).
  async function open(url, scenario, opts = {}) {
    const pc = new RTCPeerConnection({ encodedInsertableStreams: !!opts.insertableStreams, ...(opts.rtc || {}) });
    const ws = new WebSocket(url);
    await new Promise((res, rej) => {
      ws.onopen = res;
      ws.onerror = () => rej(new Error(`websocket ${url} failed`));
    });
    const s = {
      pc,
      ws,
      reports: [],
      errors: [],
      remoteOffers: 0,
      ignoredOffers: 0,
      makingOffer: false,
      sentScenario: false,
      localCandidates: [],
      // Perfect negotiation's impolite peer: an offer that arrives while ours is outstanding
      // is ignored (the Rust side is the polite one and rolls back).
      impolite: false,
      // Edits the answer from Rust before it is applied (a test of a wrong fingerprint).
      mungeAnswer: null,
      // Edits an offer from Rust before it is applied (an answerer that does not bundle).
      mungeRemoteOffer: null,
    };
    const send = (m) => ws.send(JSON.stringify(m));
    // Trickled candidates follow the description they belong to (RFC 8838 section 4): one is
    // sent only once the Rust side has the description whose media section (mid) and ICE
    // ufrag it names. Until then it waits; one of a description that was never sent (a local
    // offer rolled back before it went out) is dropped, since Rust would rightly refuse a
    // candidate naming no media section of its remote description.
    let sentSdp = null;
    let held = [];
    const flushCandidates = () => {
      const keep = [];
      for (const c of held) {
        if (c === null) {
          if (keep.length === 0) send({ type: "candidate", candidate: null });
          else keep.push(c);
        } else if (candidateFits(c, sentSdp)) send({ type: "candidate", candidate: c });
        else if (candidateFits(c, pc.localDescription && pc.localDescription.sdp)) keep.push(c);
      }
      held = keep;
    };
    const sendDescription = (type, sdp) => {
      const msg = { type, sdp };
      if (type === "offer" && !s.sentScenario) {
        msg.scenario = scenario;
        s.sentScenario = true;
      }
      send(msg);
      sentSdp = sdp;
      flushCandidates();
    };
    pc.onicecandidate = (e) => {
      if (e.candidate && e.candidate.candidate) s.localCandidates.push(e.candidate.candidate);
      held.push(e.candidate ? e.candidate.toJSON() : null);
      flushCandidates();
    };
    ws.onmessage = async (ev) => {
      const m = JSON.parse(ev.data);
      try {
        if (m.type === "answer") {
          await pc.setRemoteDescription({ type: "answer", sdp: s.mungeAnswer ? s.mungeAnswer(m.sdp) : m.sdp });
        } else if (m.type === "offer") {
          s.remoteOffers++;
          if (s.impolite && pc.signalingState !== "stable") {
            s.ignoredOffers++;
            return;
          }
          await pc.setRemoteDescription({ type: "offer", sdp: s.mungeRemoteOffer ? s.mungeRemoteOffer(m.sdp) : m.sdp });
          await pc.setLocalDescription();
          sendDescription("answer", pc.localDescription.sdp);
        } else if (m.type === "report") s.reports.push(m);
        else if (m.type === "error") s.errors.push(m.error);
      } catch (e) {
        s.errors.push(String(e));
      }
    };
    // Makes an offer and applies it locally, without sending it.
    s.makeOffer = async () => {
      await pc.setLocalDescription(await pc.createOffer());
    };
    // Sends the local offer (munged by `mungeOffer` when given: what Rust receives, not what
    // this side applied) and waits for the answer.
    s.sendOffer = async (mungeOffer) => {
      const sdp = mungeOffer ? mungeOffer(pc.localDescription.sdp) : pc.localDescription.sdp;
      sendDescription("offer", sdp);
      // A Rust-side error (an {"type":"error"} message) or a refused answer is the reason an
      // answer never applies: name them instead of only the timeout.
      await until(() => pc.signalingState === "stable", 15000, "the answer").catch((e) => {
        throw new Error(`${e.message}; errors: ${JSON.stringify(s.errors)}`);
      });
    };
    s.negotiate = async (mungeOffer) => {
      await s.makeOffer();
      await s.sendOffer(mungeOffer);
    };
    s.send = send;
    s.connected = () =>
      until(() => pc.connectionState === "connected" || (pc.connectionState === "failed" && "failed"), 30000,
        "connection").then((v) => {
        if (v === "failed") throw new Error("connection failed");
      });
    s.report = async () => {
      const n = s.reports.length;
      send({ type: "report" });
      await until(() => s.reports.length > n, 5000, "report");
      return s.reports[s.reports.length - 1];
    };
    s.close = () => {
      pc.close();
      ws.close();
    };
    return s;
  }

  // Sends `count` messages on `dc` and waits for the echo; returns them in arrival order.
  async function echo(dc, count, size = 0) {
    const got = [];
    dc.binaryType = "arraybuffer";
    dc.onmessage = (e) => got.push(typeof e.data === "string" ? e.data : new Uint8Array(e.data));
    if (dc.readyState !== "open") await new Promise((r) => (dc.onopen = r));
    for (let i = 0; i < count; i++) {
      if (size) {
        const b = new Uint8Array(size);
        b.fill(i % 251);
        new DataView(b.buffer).setUint32(0, i);
        dc.send(b);
      } else dc.send(`msg-${i}`);
      while (dc.bufferedAmount > 1 << 20) await sleep(5);
    }
    return { got, wait: (n, ms) => until(() => got.length >= n, ms, `${n} echoed messages (have ${got.length})`) };
  }

  async function inbound(pc, kind) {
    const stats = await pc.getStats();
    let rtp = null;
    const codecs = {};
    stats.forEach((r) => {
      if (r.type === "inbound-rtp" && r.kind === kind && (!rtp || (r.packetsReceived || 0) > (rtp.packetsReceived || 0))) rtp = r;
      if (r.type === "codec") codecs[r.id] = r.mimeType;
    });
    return rtp ? { ...rtp, mimeType: codecs[rtp.codecId] } : null;
  }

  // The selected candidate pair's local and remote candidate stats (transport's
  // selectedCandidatePairId; Firefox marks the pair itself with `selected`).
  async function selectedPair(pc) {
    const stats = await pc.getStats();
    const all = new Map();
    let pairId = null;
    stats.forEach((r) => {
      all.set(r.id, r);
      if (r.type === "transport" && r.selectedCandidatePairId) pairId = r.selectedCandidatePairId;
    });
    let pair = pairId ? all.get(pairId) : null;
    if (!pair) {
      for (const r of all.values()) {
        if (r.type === "candidate-pair" && (r.selected || (r.nominated && r.state === "succeeded"))) pair = r;
      }
    }
    if (!pair) return null;
    return { pair, local: all.get(pair.localCandidateId), remote: all.get(pair.remoteCandidateId) };
  }

  // The first byte of every a=fingerprint hash changed: the certificate no longer matches it.
  function wrongFingerprint(sdp) {
    return sdp.replace(/^(a=fingerprint:\S+ )([0-9A-Fa-f]{2})/gm, (_, head, b) =>
      head + (b.toUpperCase() === "00" ? "FF" : "00"));
  }

  // The m-lines of a description: kind, port, direction and mid.
  function mlines(sdp) {
    return sdp.split(/\r\n(?=m=)/).slice(1).map((sec) => ({
      kind: sec.match(/^m=(\S+)/)[1],
      port: Number(sec.match(/^m=\S+ (\d+)/)[1]),
      dir: (sec.match(/^a=(sendrecv|sendonly|recvonly|inactive)\r?$/m) || [, "sendrecv"])[1],
      mid: (sec.match(/^a=mid:(\S+)/m) || [, null])[1],
      rtx: /^a=rtpmap:\d+ rtx\//im.test(sec),
    }));
  }

  async function transport(pc) {
    const stats = await pc.getStats();
    let t = null;
    stats.forEach((r) => {
      if (r.type === "transport") t = r;
    });
    return t;
  }

  function sink(stream) {
    const v = document.createElement(stream.getVideoTracks().length ? "video" : "audio");
    v.muted = true;
    v.autoplay = true;
    v.playsInline = true;
    v.srcObject = stream;
    document.body.appendChild(v);
    v.play().catch(() => {});
  }

  // XOR every encoded frame's payload past its first bytes (the "SFrame-like" end-to-end
  // transform): the Rust peer forwards bytes it cannot decode, the receiving transform undoes it.
  function xorTransform() {
    return new TransformStream({
      transform(frame, ctl) {
        const d = new Uint8Array(frame.data);
        for (let i = 10; i < d.length; i++) d[i] ^= 0x5a;
        frame.data = d.buffer;
        ctl.enqueue(frame);
      },
    });
  }

  function attachTransform(senderOrReceiver) {
    if (senderOrReceiver.createEncodedStreams) {
      const { readable, writable } = senderOrReceiver.createEncodedStreams();
      readable.pipeThrough(xorTransform()).pipeTo(writable);
      return "createEncodedStreams";
    }
    if (window.RTCRtpScriptTransform) {
      const src = `onrtctransform = (e) => { const t = e.transformer; t.readable.pipeThrough(new TransformStream({
        transform(frame, ctl) { const d = new Uint8Array(frame.data); for (let i = 10; i < d.length; i++) d[i] ^= 0x5a;
        frame.data = d.buffer; ctl.enqueue(frame); } })).pipeTo(t.writable); };`;
      const w = new Worker(URL.createObjectURL(new Blob([src], { type: "text/javascript" })));
      senderOrReceiver.transform = new RTCRtpScriptTransform(w, {});
      return "RTCRtpScriptTransform";
    }
    return null;
  }

  window.Interop = {
    open, echo, until, sleep, canvasStream, audioStream, hasCodec, prefer, inbound, transport, sink, attachTransform,
    selectedPair, wrongFingerprint, mlines,
  };
})();

// Browser <-> webrtc-rs-rtc interop beyond plain media and data: Cryptex, loss recovery with a
// browser sender, TURN relay, ICE-TCP, the browser as the answerer, transceiver stop and m-line
// reuse, direction changes, rollback and glare, large messages, a wrong fingerprint either way,
// simulcast with RTX, the browser's getStats() against the Rust side's counters, and a
// transport per section when the browser's offer is not bundled.
//
// Every skip goes through na.mjs with its kind and citation (gate.mjs fails an uncited one).
import { test, expect } from "@playwright/test";
import { naBrowser, naEnv } from "./na.mjs";
import { WS, TURN, setupPage, rustUdpPort, impair, netemDrops } from "./common.mjs";

setupPage();

// ---- Cryptex (RFC 9335) ----

test("cryptex: header extensions encrypted both ways", async ({ page }) => {
  const r = await page.evaluate(async (ws) => {
    // webrtc-extensions: RTCConfiguration.rtpHeaderEncryptionPolicy. A browser that does not
    // know the member ignores it, and its offer then carries no a=cryptex.
    const s = await Interop.open(
      ws,
      { media: "reflect", video: "VP8", cryptex: "require" },
      { rtc: { rtpHeaderEncryptionPolicy: "negotiate" } },
    );
    const tr = s.pc.addTransceiver(Interop.canvasStream().getVideoTracks()[0], { direction: "sendrecv" });
    Interop.prefer(tr, "video", "video/VP8");
    s.pc.ontrack = (e) => Interop.sink(new MediaStream([e.track]));
    await s.makeOffer();
    const offered = /^a=cryptex\r?$/m.test(s.pc.localDescription.sdp);
    if (!offered) {
      s.close();
      return { offered };
    }
    await s.sendOffer();
    await s.connected();
    const rtp = await Interop.until(async () => {
      const r = await Interop.inbound(s.pc, "video");
      return r && r.framesDecoded > 15 && r;
    }, 25000, "15 decoded frames").catch(async (e) => ({ error: String(e), last: await Interop.inbound(s.pc, "video") }));
    const report = await s.report();
    const answered = /^a=cryptex\r?$/m.test(s.pc.remoteDescription.sdp);
    s.close();
    return { offered, answered, rtp, cryptex: report.cryptex, errors: report.errors };
  }, WS);
  naBrowser(
    !r.offered,
    "this browser does not offer Cryptex",
    "its own offer, made with rtpHeaderEncryptionPolicy \"negotiate\", has no a=cryptex (RFC 9335 section 4)",
  );
  expect(r.answered, "the Rust answer must carry a=cryptex when the offer did").toBe(true);
  expect(r.cryptex, JSON.stringify(r)).toBe(true);
  expect(r.rtp.error, JSON.stringify(r)).toBeUndefined();
  expect(r.errors).toEqual([]);
});

// ---- loss recovery with a browser sender (NACK + RTX, RFC 4585 / RFC 4588) ----

test("loss recovery: NACK and RTX repair a browser's video under netem", async ({ page }) => {
  await page.evaluate(async (ws) => {
    const s = await Interop.open(ws, { media: "reflect", video: "VP8" });
    window.S = s;
    const tr = s.pc.addTransceiver(Interop.canvasStream(640, 480).getVideoTracks()[0], { direction: "sendrecv" });
    Interop.prefer(tr, "video", "video/VP8");
    s.pc.ontrack = (e) => Interop.sink(new MediaStream([e.track]));
    await s.negotiate();
    await s.connected();
  }, WS);
  const answer = await page.evaluate(() => S.pc.remoteDescription.sdp);
  const dropsBefore = netemDrops();
  const restore = impair(rustUdpPort(answer));
  let r;
  try {
    r = await page.evaluate(async () => {
      await Interop.sleep(12000);
      let out = null;
      (await S.pc.getStats()).forEach((x) => {
        if (x.type === "outbound-rtp" && x.kind === "video") out = x;
      });
      const report = await S.report();
      return { out, report, rtx: Interop.mlines(S.pc.remoteDescription.sdp)[0].rtx };
    });
  } finally {
    restore();
  }
  const drops = netemDrops() - dropsBefore;
  await page.evaluate(() => S.close());
  expect(drops, "netem dropped nothing: the filter did not apply").toBeGreaterThan(0);
  expect(r.rtx, "the Rust answer negotiates no RTX for the video").toBe(true);
  const video = r.report.coverage.filter((c) => c.key.startsWith("video:"));
  expect(video.length, JSON.stringify(r.report.coverage)).toBeGreaterThan(0);
  const v = video.reduce((a, b) => (b.span > a.span ? b : a));
  // Enough packets that 5% loss drops several: Chromium and WebKit send 30+ a second from the
  // canvas, Firefox about 20 (250 in the run, a 200-packet span once the newest 50 are left out).
  expect(v.span, JSON.stringify(v)).toBeGreaterThan(150);
  // After repair nothing older than the newest 50 packets may still be missing.
  expect(v.missing / v.span, `still missing after NACK/RTX: ${JSON.stringify(v)}`).toBeLessThan(0.005);
  // The browser saw our NACKs and answered them (webrtc-stats: nackCount,
  // retransmittedPacketsSent; checked where the browser reports them).
  if (r.out?.nackCount !== undefined) expect(r.out.nackCount, JSON.stringify(r.out)).toBeGreaterThan(0);
  if (r.out?.retransmittedPacketsSent !== undefined) {
    expect(r.out.retransmittedPacketsSent, JSON.stringify(r.out)).toBeGreaterThan(0);
  }
});

// ---- TURN: relay-only through coturn ----

test("relay only: the browser reaches Rust through coturn", async ({ page }) => {
  const r = await page.evaluate(
    async ([ws, turn]) => {
      const s = await Interop.open(ws, {}, { rtc: { iceServers: [turn], iceTransportPolicy: "relay" } });
      const dc = s.pc.createDataChannel("relay");
      await s.negotiate();
      await s.connected();
      const e = await Interop.echo(dc, 30);
      await e.wait(30, 15000);
      const sel = await Interop.selectedPair(s.pc);
      s.close();
      return { echoed: e.got.length, local: sel?.local, candidates: s.localCandidates };
    },
    [WS, TURN],
  );
  expect(r.candidates.every((c) => / typ relay/.test(c)), JSON.stringify(r.candidates)).toBe(true);
  expect(r.echoed).toBe(30);
  expect(r.local?.candidateType, JSON.stringify(r.local)).toBe("relay");
});

// ---- ICE-TCP (RFC 6544) ----

test("ICE-TCP: the browser's active candidate reaches Rust's passive one", async ({ page }) => {
  const r = await page.evaluate(async (ws) => {
    // The Rust side offers only a passive TCP candidate: no UDP path exists.
    const s = await Interop.open(ws, { ice_tcp: true, udp: false });
    const dc = s.pc.createDataChannel("tcp");
    await s.negotiate();
    const tcpCandidates = () => s.localCandidates.filter((c) => / tcp /i.test(c));
    await Interop.until(() => tcpCandidates().length > 0 || s.pc.iceGatheringState === "complete", 10000, "gathering")
      .catch(() => {});
    if (tcpCandidates().length === 0) {
      s.close();
      return { noTcp: true, candidates: s.localCandidates };
    }
    await s.connected();
    const e = await Interop.echo(dc, 30, 32768);
    await e.wait(30, 20000);
    const sel = await Interop.selectedPair(s.pc);
    s.close();
    return { echoed: e.got.length, local: sel?.local, remote: sel?.remote };
  }, WS);
  naBrowser(
    r.noTcp,
    "this browser gathered no TCP candidate",
    `its icecandidate events: ${JSON.stringify(r.candidates)}`,
  );
  expect(r.echoed).toBe(30);
  expect((r.local?.protocol || "").toLowerCase(), JSON.stringify(r)).toBe("tcp");
});

// ---- the browser as the answerer for media ----

test("Rust offers media, the browser answers and decodes it", async ({ page }) => {
  const r = await page.evaluate(async (ws) => {
    const s = await Interop.open(ws, {});
    s.pc.createDataChannel("first");
    await s.negotiate();
    await s.connected();
    s.pc.ontrack = (e) => Interop.sink(new MediaStream([e.track]));
    s.send({ type: "request-offer", tracks: ["VP8", "OPUS"] });
    await Interop.until(() => s.remoteOffers > 0 && s.pc.signalingState === "stable", 15000, "Rust's offer");
    await Interop.sleep(500);
    const video = await Interop.until(async () => {
      const v = await Interop.inbound(s.pc, "video");
      return v && v.framesDecoded > 30 && v;
    }, 25000, "30 decoded frames").catch(async (e) => ({ error: String(e), last: await Interop.inbound(s.pc, "video") }));
    // Opus is 50 packets a second: 30 decoded video frames take about a second, so the audio
    // has its own wait for 100 packets (the check below).
    const audio = await Interop.until(async () => {
      const a = await Interop.inbound(s.pc, "audio");
      return a && a.packetsReceived > 100 && a;
    }, 15000, "100 audio packets").catch(() => Interop.inbound(s.pc, "audio"));
    const kinds = Interop.mlines(s.pc.remoteDescription.sdp).map((m) => m.kind);
    s.close();
    return { video, audio, kinds, errors: s.errors };
  }, WS);
  expect(r.errors).toEqual([]);
  expect(r.kinds).toEqual(expect.arrayContaining(["video", "audio"]));
  expect(r.video.error, JSON.stringify(r)).toBeUndefined();
  expect(r.video.mimeType.toLowerCase()).toBe("video/vp8");
  expect(r.audio?.packetsReceived || 0, JSON.stringify(r.audio)).toBeGreaterThan(100);
});

// ---- transceiver stop() and m-line reuse (RFC 9429 5.2.2, W3C 5.4) ----

test("transceiver stop, then a new transceiver reuses or keeps the m-line", async ({ page }) => {
  const r = await page.evaluate(async (ws) => {
    const s = await Interop.open(ws, { media: "reflect", video: "VP8", audio: true });
    const t1 = s.pc.addTransceiver(Interop.canvasStream().getVideoTracks()[0], { direction: "sendrecv" });
    Interop.prefer(t1, "video", "video/VP8");
    await s.negotiate();
    await s.connected();
    t1.stop();
    await s.negotiate();
    const afterStop = { offer: Interop.mlines(s.pc.localDescription.sdp), answer: Interop.mlines(s.pc.remoteDescription.sdp) };
    s.pc.addTransceiver(Interop.audioStream().getAudioTracks()[0], { direction: "sendrecv" });
    await s.negotiate();
    const afterAdd = { offer: Interop.mlines(s.pc.localDescription.sdp), answer: Interop.mlines(s.pc.remoteDescription.sdp) };
    let report;
    await Interop.until(async () => {
      report = await s.report();
      return Object.keys(report.rtp).some((k) => k.startsWith("audio:") && report.rtp[k] > 50);
    }, 15000, "50 audio packets at Rust").catch(() => {});
    // What a failure needs to be read: both descriptions, both sides' states, what the browser
    // says it sent.
    const diag = {
      offer: s.pc.localDescription.sdp,
      answer: s.pc.remoteDescription.sdp,
      browser: { connection: s.pc.connectionState, ice: s.pc.iceConnectionState },
      rust: { state: report?.state, stats: report?.stats, errors: report?.errors },
      sent: [],
    };
    (await s.pc.getStats()).forEach((x) => {
      if (x.type === "outbound-rtp") diag.sent.push({ kind: x.kind, ssrc: x.ssrc, mid: x.mid, packetsSent: x.packetsSent });
    });
    s.close();
    return { afterStop, afterAdd, rtp: report?.rtp, errors: s.errors, diag };
  }, WS);
  expect(r.errors).toEqual([]);
  for (const step of [r.afterStop, r.afterAdd]) {
    // An answer has the offer's m-lines, in order and of the same kinds (RFC 9429 5.3.1), and a
    // section the offer rejected (port 0) stays rejected.
    expect(step.answer.map((m) => m.kind), JSON.stringify(step)).toEqual(step.offer.map((m) => m.kind));
    step.offer.forEach((m, i) => {
      if (m.port === 0) expect(step.answer[i].port, JSON.stringify(step)).toBe(0);
    });
  }
  expect(r.afterStop.offer[0].port, "the stopped transceiver's m-line is rejected").toBe(0);
  expect(
    Object.keys(r.rtp || {}).some((k) => k.startsWith("audio:") && r.rtp[k] > 50),
    `${JSON.stringify(r.rtp)} ${JSON.stringify(r.diag)}`,
  ).toBe(true);
});

// ---- direction changes (RFC 9429 5.3.1, RFC 3264 6.1) ----

test("direction changes are answered with the complementary direction", async ({ page }) => {
  const r = await page.evaluate(async (ws) => {
    const s = await Interop.open(ws, { media: "reflect", video: "VP8" });
    const tr = s.pc.addTransceiver(Interop.canvasStream().getVideoTracks()[0], { direction: "sendrecv" });
    Interop.prefer(tr, "video", "video/VP8");
    s.pc.ontrack = (e) => Interop.sink(new MediaStream([e.track]));
    await s.negotiate();
    await s.connected();
    const steps = [];
    for (const dir of ["sendonly", "recvonly", "inactive", "sendrecv"]) {
      tr.direction = dir;
      await s.negotiate();
      steps.push({ dir, answered: Interop.mlines(s.pc.remoteDescription.sdp)[0].dir, current: tr.currentDirection });
    }
    const before = (await Interop.inbound(s.pc, "video"))?.framesDecoded || 0;
    await Interop.sleep(4000);
    const after = (await Interop.inbound(s.pc, "video"))?.framesDecoded || 0;
    s.close();
    return { steps, resumed: after - before, errors: s.errors };
  }, WS);
  expect(r.errors).toEqual([]);
  const complement = { sendonly: "recvonly", recvonly: "sendonly", inactive: "inactive", sendrecv: "sendrecv" };
  for (const st of r.steps) {
    expect(st.answered, JSON.stringify(r.steps)).toBe(complement[st.dir]);
    expect(st.current, JSON.stringify(r.steps)).toBe(st.dir);
  }
  expect(r.resumed, "reflected video did not resume after going back to sendrecv").toBeGreaterThan(10);
});

// ---- rollback and glare (RFC 9429 4.1.8.2, 5.7) ----

test("rollback: an abandoned local offer leaves the session usable", async ({ page }) => {
  const r = await page.evaluate(async (ws) => {
    const s = await Interop.open(ws, {});
    const a = s.pc.createDataChannel("first");
    await s.negotiate();
    await s.connected();
    s.pc.addTransceiver("audio", { direction: "recvonly" });
    await s.makeOffer();
    await s.pc.setLocalDescription({ type: "rollback" });
    const afterRollback = s.pc.signalingState;
    await s.negotiate();
    const e = await Interop.echo(a, 10);
    await e.wait(10, 10000);
    const kinds = Interop.mlines(s.pc.remoteDescription.sdp).map((m) => m.kind);
    s.close();
    return { afterRollback, echoed: e.got.length, kinds, errors: s.errors };
  }, WS);
  expect(r.afterRollback).toBe("stable");
  expect(r.errors).toEqual([]);
  expect(r.kinds).toEqual(["application", "audio"]);
  expect(r.echoed).toBe(10);
});

test("glare: Rust rolls its offer back, answers, and offers again", async ({ page }) => {
  const r = await page.evaluate(async (ws) => {
    const s = await Interop.open(ws, {});
    s.pc.createDataChannel("first");
    await s.negotiate();
    await s.connected();
    s.impolite = true;
    const hello = new Promise((res) => {
      s.pc.ondatachannel = (e) => {
        e.channel.onmessage = (m) => res([e.channel.label, m.data]);
      };
    });
    // Our offer is applied first; then Rust is asked to offer, and gets ours right after its
    // own went out: both sides have an offer outstanding.
    s.pc.addTransceiver("audio", { direction: "recvonly" });
    await s.makeOffer();
    s.send({ type: "request-offer" });
    await s.sendOffer();
    const result = await Promise.race([hello, Interop.sleep(20000).then(() => "timeout")]);
    const report = await s.report();
    s.close();
    return { result, ignored: s.ignoredOffers, offers: s.remoteOffers, rollbacks: report.rollbacks, errors: s.errors };
  }, WS);
  expect(r.errors).toEqual([]);
  expect(r.ignored, "the browser (impolite) must have ignored Rust's colliding offer").toBeGreaterThan(0);
  expect(r.rollbacks, "Rust (polite) must have rolled its offer back").toBeGreaterThan(0);
  expect(r.offers).toBeGreaterThan(1);
  expect(r.result).toEqual(["from-rust", "hello-from-rust"]);
});

// ---- a 256 KiB message and max-message-size (RFC 8841 6.1, W3C 6.1 / 6.2) ----

test("data channel 256 KiB message within both sides' max-message-size", async ({ page }) => {
  const r = await page.evaluate(async (ws) => {
    const s = await Interop.open(ws, {});
    const dc = s.pc.createDataChannel("big", { ordered: true });
    await s.negotiate();
    await s.connected();
    const mms = (sdp) => {
      const m = sdp.match(/^a=max-message-size:(\d+)/m);
      return m ? Number(m[1]) : 65536; // RFC 8841 6: absent means 64 KiB
    };
    const offered = mms(s.pc.localDescription.sdp);
    const answered = mms(s.pc.remoteDescription.sdp);
    const effective = s.pc.sctp?.maxMessageSize;
    if (dc.readyState !== "open") await new Promise((res) => (dc.onopen = res));
    const size = 256 * 1024;
    let threw = null;
    let echoed = null;
    if (effective !== undefined && effective >= size) {
      const e = await Interop.echo(dc, 1, size);
      await e.wait(1, 20000).catch(() => {});
      echoed = e.got[0] ? { length: e.got[0].length, first: new DataView(e.got[0].buffer).getUint32(0), fill: e.got[0][size - 1] } : null;
    } else {
      try {
        dc.send(new Uint8Array(size));
      } catch (e) {
        threw = e.name;
      }
    }
    s.close();
    return { offered, answered, effective, echoed, threw };
  }, WS);
  naBrowser(
    r.offered < 256 * 1024,
    `this browser states a max-message-size of ${r.offered}`,
    "its own offer's a=max-message-size (RFC 8841 section 6)",
  );
  // The browser's view of the limit is the smaller of the two statements (W3C 6.1.1).
  if (r.effective !== undefined) expect(r.effective).toBe(Math.min(r.offered, r.answered));
  expect(r.answered, "the Rust side states less than 256 KiB").toBeGreaterThanOrEqual(256 * 1024);
  expect(r.echoed, JSON.stringify(r)).toEqual({ length: 256 * 1024, first: 0, fill: 0 });
});

// ---- several transports (RFC 9429 4.1.1, 5.3.1; RFC 9143 7; RFC 8835 4.2) ----

// The browser offers under "max-compat" (a transport per m= section) and Rust receives the
// offer without its BUNDLE group, as from a peer that does not bundle: Rust answers each
// section on a transport of its own (its own ICE credentials, candidates and DTLS), and video
// and data each travel over theirs.
test("unbundled: max-compat without a BUNDLE group, a transport per section", async ({ page }) => {
  const r = await page.evaluate(async (ws) => {
    const s = await Interop.open(ws, { media: "reflect", video: "VP8" }, { rtc: { bundlePolicy: "max-compat" } });
    const tr = s.pc.addTransceiver(Interop.canvasStream().getVideoTracks()[0], { direction: "sendrecv" });
    Interop.prefer(tr, "video", "video/VP8");
    s.pc.ontrack = (e) => Interop.sink(new MediaStream([e.track]));
    const dc = s.pc.createDataChannel("unbundled", { ordered: true });
    await s.negotiate((sdp) => sdp.replace(/^a=group:BUNDLE[^\r\n]*\r?\n/m, ""));
    await s.connected();
    if (dc.readyState !== "open") await new Promise((res) => (dc.onopen = res));
    const e = await Interop.echo(dc, 1, 1024);
    await e.wait(1, 20000).catch(() => {});
    const rtp = await Interop.until(async () => {
      const v = await Interop.inbound(s.pc, "video");
      return v && v.framesDecoded > 15 && v;
    }, 25000, "15 decoded frames").catch(async (err) => ({ error: String(err), last: await Interop.inbound(s.pc, "video") }));
    const answer = s.pc.remoteDescription.sdp;
    const ufrags = new Set([...answer.matchAll(/^a=ice-ufrag:(\S+)/gm)].map((m) => m[1]));
    const stats = await s.pc.getStats();
    const transportStats = [...stats.values()].filter((x) => x.type === "transport");
    const transports = transportStats.filter((x) => x.dtlsState === "connected").length;
    const sameTransport = tr.sender.transport === s.pc.sctp?.transport;
    const report = await s.report();
    s.close();
    return {
      grouped: /^a=group:BUNDLE/m.test(answer),
      ufrags: ufrags.size,
      transports,
      transportStats: transportStats.length,
      sameTransport,
      echoed: e.got.length,
      rtp,
      rust: { transportsConnected: report.transportsConnected, stats: report.stats },
      errors: report.errors,
    };
  }, WS);
  expect(r.grouped, "Rust answers an offer without a BUNDLE group without one").toBe(false);
  expect(r.ufrags, JSON.stringify(r)).toBe(2);
  expect(r.sameTransport, "video and data are on two transports").toBe(false);
  // A browser that reports no RTCTransportStats is checked by its sender's and SCTP's
  // transport objects only.
  if (r.transportStats > 0) expect(r.transports, JSON.stringify(r)).toBe(2);
  // Rust's side: each transport fired its own DTLS "connected" (OnTransportEvent) and has a
  // transport stats object of its own with a selected candidate pair.
  expect(r.rust.transportsConnected, JSON.stringify(r.rust)).toBe(2);
  const rustTransports = r.rust.stats.transports.filter((t) => t.dtlsState === "connected");
  expect(rustTransports.length, JSON.stringify(r.rust.stats.transports)).toBe(2);
  expect(rustTransports.every((t) => t.selectedCandidatePairId !== ""), JSON.stringify(rustTransports)).toBe(true);
  expect(r.echoed, JSON.stringify(r)).toBe(1);
  expect(r.rtp.error, JSON.stringify(r)).toBeUndefined();
  expect(r.errors).toEqual([]);
});

// ---- a wrong DTLS fingerprint (RFC 5763 5, RFC 8122 5) ----

test("wrong fingerprint in Rust's answer: the browser fails the connection", async ({ page }) => {
  const r = await page.evaluate(async (ws) => {
    const s = await Interop.open(ws, {});
    s.pc.createDataChannel("fp");
    s.mungeAnswer = Interop.wrongFingerprint;
    await s.negotiate();
    const state = await Interop.until(
      () => (["failed", "connected"].includes(s.pc.connectionState) ? s.pc.connectionState : null),
      30000,
      "failed",
    ).catch(() => s.pc.connectionState);
    s.close();
    return { state };
  }, WS);
  expect(r.state).toBe("failed");
});

test("wrong fingerprint in the browser's offer: Rust fails the connection", async ({ page }) => {
  const r = await page.evaluate(async (ws) => {
    const s = await Interop.open(ws, {});
    s.pc.createDataChannel("fp");
    await s.negotiate(Interop.wrongFingerprint);
    let report;
    await Interop.until(async () => {
      report = await s.report();
      return report.state === "failed" || report.state === "connected";
    }, 30000, "Rust's state").catch(() => {});
    s.close();
    return { rust: report?.state, browser: s.pc.connectionState };
  }, WS);
  expect(r.rust, "Rust must end as failed (W3C 5.5.1), never connected").toBe("failed");
});

// ---- simulcast with RTX (RFC 8852 repaired-rtp-stream-id) ----

test("simulcast with RTX: every layer is repaired under netem", async ({ page }) => {
  await page.evaluate(async (ws) => {
    const s = await Interop.open(ws, { media: "count" });
    window.S = s;
    const track = Interop.canvasStream(1280, 720).getVideoTracks()[0];
    const tr = s.pc.addTransceiver(track, {
      direction: "sendonly",
      sendEncodings: [
        { rid: "q", scaleResolutionDownBy: 4.0, maxBitrate: 100000 },
        { rid: "h", scaleResolutionDownBy: 2.0, maxBitrate: 200000 },
        { rid: "f", maxBitrate: 400000 },
      ],
    });
    window.TR = tr;
    Interop.prefer(tr, "video", "video/VP8");
    const params = tr.sender.getParameters();
    try {
      params.degradationPreference = "maintain-resolution";
      await tr.sender.setParameters(params);
    } catch {}
    await s.negotiate();
    await s.connected();
  }, WS);
  const answer = await page.evaluate(() => S.pc.remoteDescription.sdp);
  const restore = impair(rustUdpPort(answer));
  let r;
  try {
    r = await page.evaluate(async () => {
      await Interop.sleep(15000);
      const sent = {};
      (await S.pc.getStats()).forEach((x) => {
        if (x.type === "outbound-rtp" && x.kind === "video" && x.rid) {
          sent[x.rid] = {
            packets: x.packetsSent || 0,
            width: x.frameWidth,
            retransmitted: x.retransmittedPacketsSent,
            nacks: x.nackCount,
            limit: x.qualityLimitationReason,
          };
        }
      });
      const report = await S.report();
      return {
        sent,
        report,
        accepted: (TR.sender.getParameters().encodings || []).map((e) => e.rid).filter(Boolean),
        offeredRids: [...S.pc.localDescription.sdp.matchAll(/^a=rid:(\S+) send/gm)].map((m) => m[1]),
        rrid: /urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id/.test(S.pc.remoteDescription.sdp),
        rtx: Interop.mlines(S.pc.remoteDescription.sdp)[0].rtx,
      };
    });
  } finally {
    restore();
  }
  await page.evaluate(() => S.close());
  naBrowser(
    r.accepted.length < 3 || r.offeredRids.length < 3,
    "this browser does not send three simulcast encodings",
    `getParameters().encodings ${JSON.stringify(r.accepted)}, offer a=rid ${JSON.stringify(r.offeredRids)}`,
  );
  naBrowser(
    r.sent.q?.width > 1280 / 2,
    `the browser encodes layer q at ${r.sent.q?.width} px wide, not a quarter of the 1280 px input: ` +
      "its encoder does not do simulcast (one stream from the full frame, on the first encoding)",
    `outbound-rtp.frameWidth of rid "q" against its scaleResolutionDownBy 4 (webrtc-pc 5.2; ` +
      `W3C webrtc-stats 7.3): ${JSON.stringify(r.sent)}`,
  );
  const quiet = ["q", "h", "f"].filter((x) => (r.sent[x]?.packets || 0) <= 20);
  naEnv(
    quiet.length > 0 && Object.values(r.sent).some((v) => v.limit === "cpu"),
    `the browser held back layer(s) ${quiet.join(",")} for lack of CPU in the test container`,
    `outbound-rtp.qualityLimitationReason = "cpu" (W3C webrtc-stats 7.3): ${JSON.stringify(r.sent)}`,
  );
  expect(quiet, JSON.stringify(r.sent)).toEqual([]);
  expect(r.rtx, "the Rust answer negotiates no RTX").toBe(true);
  expect(r.rrid, "the Rust answer has no repaired-rtp-stream-id extension").toBe(true);
  for (const rid of ["q", "h", "f"]) {
    const cov = r.report.coverage.filter((c) => c.key.startsWith(`video:${rid}:`));
    expect(cov.length, `no packets on ${rid}: ${JSON.stringify(r.report.coverage)}`).toBeGreaterThan(0);
    const c = cov.reduce((a, b) => (b.span > a.span ? b : a));
    expect(c.missing / Math.max(c.span, 1), `layer ${rid} still missing after RTX: ${JSON.stringify(c)}`).toBeLessThan(0.01);
    const s = r.sent[rid];
    if (s?.retransmitted !== undefined) expect(s.retransmitted, `layer ${rid}: ${JSON.stringify(s)}`).toBeGreaterThan(0);
  }
});

// ---- getStats() against the Rust side's counters (W3C webrtc-stats 7.3, 7.4) ----

test("getStats: RTP counters agree with the Rust side's", async ({ page }) => {
  const r = await page.evaluate(async (ws) => {
    const s = await Interop.open(ws, { media: "reflect", audio: true });
    s.pc.addTransceiver(Interop.audioStream().getAudioTracks()[0], { direction: "sendrecv" });
    s.pc.ontrack = (e) => Interop.sink(new MediaStream([e.track]));
    await s.negotiate();
    await s.connected();
    await Interop.sleep(6000);
    const browser = { outbound: [], inbound: [] };
    (await s.pc.getStats()).forEach((x) => {
      if (x.kind !== "audio") return;
      if (x.type === "outbound-rtp") browser.outbound.push({ ssrc: x.ssrc, packetsSent: x.packetsSent });
      if (x.type === "inbound-rtp") browser.inbound.push({ ssrc: x.ssrc, packetsReceived: x.packetsReceived });
    });
    const report = await s.report();
    s.close();
    return { browser, rust: report.stats };
  }, WS);
  const close = (a, b) => Math.abs(a - b) <= Math.max(25, 0.03 * Math.max(a, b));
  const bo = r.browser.outbound[0];
  const ri = r.rust.inbound.find((x) => x.ssrc === bo?.ssrc);
  expect(ri, `Rust has no inbound-rtp for the browser's SSRC ${bo?.ssrc}: ${JSON.stringify(r)}`).toBeTruthy();
  expect(bo.packetsSent).toBeGreaterThan(100);
  expect(close(bo.packetsSent, ri.packetsReceived), `browser sent ${bo.packetsSent}, Rust received ${ri.packetsReceived}`).toBe(true);
  const bi = r.browser.inbound[0];
  const ro = r.rust.outbound.find((x) => x.ssrc === bi?.ssrc);
  expect(ro, `Rust has no outbound-rtp for the SSRC the browser receives: ${JSON.stringify(r)}`).toBeTruthy();
  expect(close(ro.packetsSent, bi.packetsReceived), `Rust sent ${ro.packetsSent}, browser received ${bi.packetsReceived}`).toBe(true);
});

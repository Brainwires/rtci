// Browser <-> rtci interop beyond plain media and data: Cryptex, loss recovery with a
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

// ---- ULPFEC in RED for video (RFC 2198, RFC 5109 section 14.2) ----
//
// Rust is built with `?video_red_ulpfec=1` (`DefaultInterceptorOptions::video_red_ulpfec`, the
// `Chrome` profile's value): video `red` + `ulpfec` are answered and offered, ULPFEC in RED is
// sent and recovered. libwebrtc protects video with ULPFEC when NACK is off (or the round trip
// is long), so the offer Rust receives has no plain `nack` feedback: nobody retransmits, and only FEC brings back what netem drops (run.sh: 20 ms, 5% loss). The engine's
// counts are its report's `fec` (`RTCPeerConnection::fec_stats`) and its W3C stats.

async function skipUnlessRedUlpfec(page) {
  const caps = await page.evaluate(() =>
    ["Sender", "Receiver"].map((side) =>
      (side === "Sender" ? RTCRtpSender : RTCRtpReceiver)
        .getCapabilities("video")
        .codecs.map((c) => c.mimeType.toLowerCase()),
    ),
  );
  const both = caps.every((list) => list.includes("video/red") && list.includes("video/ulpfec"));
  naBrowser(
    !both,
    "this browser has no video RED + ULPFEC",
    'RTCRtpSender / RTCRtpReceiver.getCapabilities("video") lists no video/red or no video/ulpfec',
  );
}

test("ULPFEC in RED from the browser: its FEC rebuilds video netem drops, without NACK, counted by Rust", async ({ page }) => {
  await skipUnlessRedUlpfec(page);
  await page.evaluate(async (ws) => {
    const s = await Interop.open(ws, { media: "count" });
    window.S = s;
    s.pc.addTransceiver(Interop.canvasStream(640, 480).getVideoTracks()[0], { direction: "sendonly" });
    await s.negotiate((sdp) => sdp.replace(/^a=rtcp-fb:\d+ nack\r\n/gm, ""));
    await s.connected();
  }, `${WS}/?video_red_ulpfec=1`);
  const answer = await page.evaluate(() => S.pc.remoteDescription.sdp);
  const dropsBefore = netemDrops();
  const restore = impair(rustUdpPort(answer));
  let r;
  try {
    r = await page.evaluate(async () => {
      await Interop.sleep(15000);
      return { report: await S.report() };
    });
  } finally {
    restore();
  }
  const drops = netemDrops() - dropsBefore;
  await page.evaluate(() => S.close());
  expect(drops, "netem dropped nothing: the filter did not apply").toBeGreaterThan(0);
  expect(answer, "the Rust answer keeps red").toMatch(/^a=rtpmap:\d+ red\/90000\r?$/m);
  expect(answer, "the Rust answer keeps ulpfec").toMatch(/^a=rtpmap:\d+ ulpfec\/90000\r?$/m);
  expect(answer, "no NACK: only FEC repairs").not.toMatch(/^a=rtcp-fb:\d+ nack\r?$/m);
  const fec = r.report.fec.received;
  expect(fec.length, JSON.stringify(r.report.fec)).toBeGreaterThan(0);
  const f = fec.reduce((a, b) => (b.fecPacketsInRed > a.fecPacketsInRed ? b : a));
  // The browser sent FEC in RED; the engine took it apart and rebuilt lost packets from it.
  expect(f.fecPacketsInRed, JSON.stringify(f)).toBeGreaterThan(0);
  expect(f.packetsRecovered, `nothing rebuilt by FEC: ${JSON.stringify(f)}`).toBeGreaterThan(0);
  const inbound = r.report.stats.inbound.find((i) => i.ssrc === f.ssrc);
  expect(inbound?.w3c?.fecPacketsReceived, JSON.stringify(inbound)).toBe(f.fecPacketsReceived);
  expect(inbound?.w3c?.fecPacketsDiscarded, JSON.stringify(inbound)).toBe(f.fecPacketsDiscarded);
});

// The reverse cell (Rust sends RED + ULPFEC, the browser recovers) is not here: on Chromium
// with NACK off on both sides, Rust's FEC arrived (wire counts, `fec_stats`) and the browser
// still dropped the frames netem broke (framesDecoded 237 of 300, framesDropped 61; hosted run
// 45428686212, scripts/test-env/hosted-cell.sh): Chromium does not rebuild from it. Open: see
// the FEC handoff note (handoff/fec2.md) for what was checked.

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

test("ICE-TCP: built into the engine with UDP blocked, the browser reaches an engine-gathered TCP candidate", async ({ page }) => {
  const r = await page.evaluate(async (ws) => {
    // The Rust side adds only a UDP host candidate and drops all ICE UDP; its engine gathers
    // passive, simultaneous-open and active TCP candidates, trickles them, and drives the
    // connections through the stream interface and the tokio reference driver.
    const s = await Interop.open(ws, { engine_tcp: true, udp_blocked: true });
    const dc = s.pc.createDataChannel("engine-tcp");
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
  expect((r.remote?.protocol || "").toLowerCase(), JSON.stringify(r)).toBe("tcp");
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

// ---- media that overtakes its answer (RFC 3264 5.1, RFC 9429 4.1.11 / 5.9) ----

test("early media: the browser sends before Rust has its answer, and nothing is lost", async ({ page }) => {
  const r = await page.evaluate(async (ws) => {
    const s = await Interop.open(ws, {});
    s.pc.createDataChannel("first");
    await s.negotiate();
    await s.connected();
    // The track the browser sends in the section Rust offers to receive: a remote offer's
    // section takes a transceiver addTrack() made (RFC 9429 5.10).
    const stream = Interop.canvasStream();
    s.pc.addTrack(stream.getVideoTracks()[0], stream);
    const sentVideo = async () => {
      let sent = 0;
      (await s.pc.getStats()).forEach((x) => {
        if (x.type === "outbound-rtp" && x.kind === "video") sent += x.packetsSent || 0;
      });
      return sent;
    };
    // The browser sends from the moment it has applied its answer; the answer itself is held
    // back until at least ten packets have left and have had time to arrive.
    let sentBeforeAnswer = 0;
    s.beforeAnswer = async () => {
      await Interop.until(async () => (await sentVideo()) >= 10, 15000, "ten video packets sent before the answer");
      await Interop.sleep(500);
      sentBeforeAnswer = await sentVideo();
    };
    s.send({ type: "request-offer", receive: ["video"] });
    await Interop.until(() => s.answersSent > 0, 30000, "the held answer");
    const video = (report) => (report.coverage || []).filter((c) => (c.key || "").startsWith("video:"));
    let report;
    await Interop.until(async () => {
      report = await s.report();
      return video(report).reduce((n, c) => n + c.received, 0) >= sentBeforeAnswer + 30;
    }, 20000, "the video sent before and after the answer, at Rust").catch(() => {});
    const offer = s.descriptions.filter(([dir, type]) => dir === "received" && type === "offer").pop();
    s.close();
    return {
      sentBeforeAnswer,
      rtpBeforeAnswer: report?.rtpBeforeAnswer,
      discardedRtp: report?.discardedRtp,
      coverage: video(report || {}),
      rtp: report?.rtp,
      offered: offer ? Interop.mlines(offer[2]) : [],
      errors: s.errors,
      rustErrors: report?.errors,
    };
  }, WS);
  const diag = JSON.stringify(r);
  expect(r.errors, diag).toEqual([]);
  expect(r.offered.filter((m) => m.kind === "video").map((m) => m.dir), diag).toEqual(["recvonly"]);
  expect(r.sentBeforeAnswer, diag).toBeGreaterThanOrEqual(10);
  // Delivered while Rust's offer was still pending.
  expect(r.rtpBeforeAnswer, diag).toBeGreaterThan(0);
  // Every packet the browser had sent when it released the answer reached Rust's track, and
  // the stream has no hole (the newest 50 sequence numbers are left out: still in flight).
  expect(r.coverage.reduce((n, c) => n + c.received, 0), diag).toBeGreaterThanOrEqual(r.sentBeforeAnswer);
  for (const c of r.coverage) expect(c.missing, diag).toBe(0);
});

// ---- transceiver stop() and m-line reuse (RFC 9429 5.2.2, W3C 5.4) ----

// Stop the only transceiver (the answer rejects every m= section and closes the transport),
// then add one: the next exchange sets up a new transport. Under the default its DTLS
// association runs on a new 3-tuple (RFC 8842 section 5.1): Rust drops the previous candidates,
// refuses their addresses, and the interop peer gathers on a new port when the engine says so
// (`OnLocalCandidatesNeeded`) and trickles the candidate. `?previous_addresses=1` builds the
// Rust side with `with_dtls_new_association_on_previous_addresses(true)`: it keeps its
// candidates and their addresses, and its answer lists them again.
async function stopThenAdd(page, url) {
  return page.evaluate(async (ws) => {
    const s = await Interop.open(ws, { media: "reflect", video: "VP8", audio: true });
    const t1 = s.pc.addTransceiver(Interop.canvasStream().getVideoTracks()[0], { direction: "sendrecv" });
    Interop.prefer(t1, "video", "video/VP8");
    await s.negotiate();
    await s.connected();
    const firstAnswer = s.pc.remoteDescription.sdp;
    t1.stop();
    await s.negotiate();
    const afterStop = { offer: Interop.mlines(s.pc.localDescription.sdp), answer: Interop.mlines(s.pc.remoteDescription.sdp) };
    s.pc.addTransceiver(Interop.audioStream().getAudioTracks()[0], { direction: "sendrecv" });
    await s.negotiate();
    const afterAdd = { offer: Interop.mlines(s.pc.localDescription.sdp), answer: Interop.mlines(s.pc.remoteDescription.sdp) };
    const addAnswer = s.pc.remoteDescription.sdp;
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
    // The UDP host candidates (address port) an answer of Rust lists.
    const hosts = (sdp) => sdp.split(/\r?\n/)
      .filter((l) => l.startsWith("a=candidate:") && / udp /i.test(l) && / typ host/.test(l))
      .map((l) => l.split(" ").slice(4, 6).join(" "));
    return {
      afterStop,
      afterAdd,
      firstHosts: hosts(firstAnswer),
      addHosts: hosts(addAnswer),
      rtp: report?.rtp,
      errors: s.errors,
      rustErrors: report?.errors,
      diag,
    };
  }, url);
}

function expectStopThenAdd(r) {
  expect(r.errors).toEqual([]);
  // The interop peer's own gathering on OnLocalCandidatesNeeded did not fail.
  expect((r.rustErrors || []).filter((e) => e.startsWith("gathering anew")), JSON.stringify(r.rustErrors)).toEqual([]);
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
}

test("transceiver stop, then a new transceiver reuses or keeps the m-line", async ({ page }) => {
  const r = await stopThenAdd(page, WS);
  expectStopThenAdd(r);
  // The new transport's answer lists none of the previous candidates: Rust gathered on a new
  // port and trickled it.
  for (const host of r.firstHosts) expect(r.addHosts, JSON.stringify(r)).not.toContain(host);
});

test("transceiver stop, then a new transceiver, Rust on its previous addresses (with_dtls_new_association_on_previous_addresses(true))", async ({ page }) => {
  const r = await stopThenAdd(page, `${WS}/?previous_addresses=1`);
  expectStopThenAdd(r);
  // The new transport kept the candidates: the answer lists them again.
  expect(r.firstHosts.length, JSON.stringify(r)).toBeGreaterThan(0);
  for (const host of r.firstHosts) expect(r.addHosts, JSON.stringify(r)).toContain(host);
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
  // Rust's transports share one set of ICE credentials by default, as the browsers' do
  // (SettingEngineBuilder::with_unique_transport_credentials); they are two transports still.
  expect(r.ufrags, JSON.stringify(r)).toBe(1);
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

// ---- bundlePolicy "balanced" (RFC 9429 4.1.1, 5.2.1; W3C webrtc-pc 4.2.4) ----

// Rust's initial offer under the default policy gives the first section of each media type a
// transport of its own (its own candidates; by default the session's one set of ICE
// credentials, as the browsers write them). The browser gets the offer
// without its BUNDLE group, as a peer that does not bundle would, and answers each section on
// its own transport: audio and video each travel over theirs.
test("balanced: Rust's offer has a transport per media type, answered without BUNDLE", async ({ page }) => {
  const r = await page.evaluate(async (ws) => {
    const s = await Interop.open(ws, {});
    s.mungeRemoteOffer = (sdp) => sdp.replace(/^a=group:BUNDLE[^\r\n]*\r?\n/m, "");
    s.pc.ontrack = (e) => Interop.sink(new MediaStream([e.track]));
    s.send({ type: "request-offer", tracks: ["VP8", "OPUS"] });
    await Interop.until(() => s.remoteOffers > 0 && s.pc.signalingState === "stable", 15000, "Rust's offer");
    await s.connected();
    const video = await Interop.until(async () => {
      const v = await Interop.inbound(s.pc, "video");
      return v && v.framesDecoded > 15 && v;
    }, 25000, "15 decoded frames").catch(async (e) => ({ error: String(e), last: await Interop.inbound(s.pc, "video") }));
    const audio = await Interop.until(async () => {
      const a = await Interop.inbound(s.pc, "audio");
      return a && a.packetsReceived > 50 && a;
    }, 15000, "50 audio packets").catch(() => Interop.inbound(s.pc, "audio"));
    const offer = s.pc.remoteDescription.sdp;
    const ufrags = new Set([...offer.matchAll(/^a=ice-ufrag:(\S+)/gm)].map((m) => m[1]));
    const stats = await s.pc.getStats();
    const transportStats = [...stats.values()].filter((x) => x.type === "transport");
    const transports = transportStats.filter((x) => x.dtlsState === "connected").length;
    const report = await s.report();
    s.close();
    return {
      ufrags: ufrags.size,
      transports,
      transportStats: transportStats.length,
      video,
      audio,
      rust: { transportsConnected: report.transportsConnected },
      errors: report.errors.concat(s.errors),
    };
  }, WS);
  expect(r.ufrags, "audio and video share the session's ICE credentials").toBe(1);
  if (r.transportStats > 0) expect(r.transports, JSON.stringify(r)).toBe(2);
  expect(r.rust.transportsConnected, JSON.stringify(r.rust)).toBe(2);
  expect(r.video.error, JSON.stringify(r)).toBeUndefined();
  expect(r.audio?.packetsReceived || 0, JSON.stringify(r.audio)).toBeGreaterThan(50);
  expect(r.errors).toEqual([]);
});

// ---- bundlePolicy "balanced" against unbundled answers, with a rollback in each ----

// Rust's default offer (a transport per media type) reaches the browser with `unbundle`
// applied: no BUNDLE group at all (a peer that does not bundle), or a group without the video
// section (a peer that answers only some sections unbundled), so audio and video run on two
// transports. Then both sides offer at once, the browser being impolite: Rust rolls its offer
// back (RFC 9429 5.7), answers the browser's, and offers again, and the browser applies that
// offer. The rollback is checked where it happens, on the Rust side: its transports right
// after the rollback are the ones it had when it made the offer, all still connected. The
// browser's offer is sent as the browser wrote it: after an unbundled exchange, Chromium and
// WebKit offer to bundle every section again, with the tagged section's ICE credentials on
// the others (RFC 9143 7.5.1), which Rust accepts (RFC 9143 7.3); the same offer with its
// group edited out is no description a peer could have made, and answering it breaks ICE
// (train 8 round 7: the audio section's credentials changed, a restart to Rust), or
// libwebrtc refuses the answer ("cannot remove m= section ... from already-established
// BUNDLE group") when the edit takes the browser's tagged section out. Media keeps flowing
// through all of it.
async function balancedUnbundledWithRollback(page, unbundle) {
  return page.evaluate(async ([ws, unbundleSrc]) => {
    // eslint-disable-next-line no-new-func
    const munge = new Function("sdp", "Interop", unbundleSrc);
    const s = await Interop.open(ws, {});
    // Rust's first offer only: the set-up of two transports.
    s.mungeRemoteOffer = (sdp) => {
      s.mungeRemoteOffer = null;
      return munge(sdp, Interop);
    };
    s.pc.ontrack = (e) => Interop.sink(new MediaStream([e.track]));
    s.send({ type: "request-offer", tracks: ["VP8", "OPUS"] });
    await Interop.until(() => s.remoteOffers > 0 && s.pc.signalingState === "stable", 15000, "Rust's offer");
    await s.connected();
    const media = async (frames, packets) => {
      const video = await Interop.until(async () => {
        const v = await Interop.inbound(s.pc, "video");
        return v && v.framesDecoded > frames && v;
      }, 25000, `${frames} decoded frames`).catch(async (e) => ({ error: String(e), last: await Interop.inbound(s.pc, "video") }));
      const audio = await Interop.until(async () => {
        const a = await Interop.inbound(s.pc, "audio");
        return a && a.packetsReceived > packets && a;
      }, 15000, `${packets} audio packets`).catch(async (e) => ({ error: String(e), last: await Interop.inbound(s.pc, "audio") }));
      return { video, audio };
    };
    const before = await media(15, 50);
    const transportsOf = async () => {
      const stats = await s.pc.getStats();
      const all = [...stats.values()].filter((x) => x.type === "transport");
      const connected = all.filter((x) => x.dtlsState === "connected").map((x) => x.id);
      return { reported: all.length, connected: connected.length, ids: connected };
    };
    const transportsBefore = await transportsOf();
    // Glare: the browser's offer is applied first, Rust is asked to offer right after.
    s.impolite = true;
    s.pc.addTransceiver("audio", { direction: "recvonly" });
    await s.makeOffer();
    s.send({ type: "request-offer" });
    await s.sendOffer();
    // Rust's offer after its rollback: the third, applied (only the colliding second one is
    // ignored).
    await Interop.until(() => s.pc.signalingState === "stable" && s.remoteOffers - s.ignoredOffers > 1, 20000, "Rust's offer after its rollback").catch(() => {});
    const after = await media((before.video.framesDecoded || 15) + 30, (before.audio.packetsReceived || 50) + 100);
    const transportsAfter = await transportsOf();
    const report = await s.report();
    s.close();
    return {
      before, after, transportsBefore, transportsAfter,
      offers: s.remoteOffers, ignored: s.ignoredOffers,
      rollbacks: report.rollbacks,
      rust: {
        transportsConnected: report.transportsConnected,
        atRolledBackOffer: report.transportsAtRolledBackOffer,
        afterRollback: report.transportsAfterRollback,
        transports: report.stats.transports,
      },
      errors: report.errors.concat(s.errors),
      descriptions: Interop.transportLines(s.descriptions),
    };
  }, [WS, unbundle]);
}

function expectBalancedUnbundled(r) {
  // Every message carries the descriptions exchanged and both sides' transports.
  const ctx = JSON.stringify({ descriptions: r.descriptions, rust: r.rust, transportsBefore: r.transportsBefore, transportsAfter: r.transportsAfter, ignored: r.ignored, offers: r.offers, before: r.before, after: r.after });
  expect(r.before.video.error, ctx).toBeUndefined();
  expect(r.before.audio.error, ctx).toBeUndefined();
  if (r.transportsBefore.reported > 0) expect(r.transportsBefore.connected, ctx).toBe(2);
  expect(r.rust.transportsConnected, ctx).toBeGreaterThanOrEqual(2);
  expect(r.rollbacks, "Rust (polite) must have rolled its offer back").toBeGreaterThan(0);
  expect(r.ignored, "the browser ignores only Rust's colliding offer").toBe(1);
  expect(r.offers, "Rust offered again after its rollback").toBeGreaterThanOrEqual(3);
  // The rollback keeps both transports: right after it Rust has the transports it had when it
  // made the offer, each still connected.
  expect(r.rust.atRolledBackOffer.length, ctx).toBeGreaterThanOrEqual(2);
  expect(r.rust.afterRollback, ctx).toEqual(r.rust.atRolledBackOffer);
  expect(r.rust.afterRollback.every(([, state]) => state === "connected"), ctx).toBe(true);
  // Media flows through the browser's offer and Rust's re-offer.
  expect(r.after.video.error, ctx).toBeUndefined();
  expect(r.after.audio.error, ctx).toBeUndefined();
  if (r.transportsAfter.reported > 0) expect(r.transportsAfter.connected, ctx).toBeGreaterThanOrEqual(1);
  expect(r.errors).toEqual([]);
}

test("balanced, answered without BUNDLE: a rollback of Rust's offer keeps both transports", async ({ page }) => {
  const r = await balancedUnbundledWithRollback(page, `return sdp.replace(/^a=group:BUNDLE[^\\r\\n]*\\r?\\n/m, "");`);
  expectBalancedUnbundled(r);
});

test("balanced, video answered outside the group: a rollback of Rust's offer keeps both transports", async ({ page }) => {
  const r = await balancedUnbundledWithRollback(
    page,
    `const video = Interop.mlines(sdp).filter((m) => m.kind === "video").map((m) => m.mid);
     return sdp.replace(/^a=group:BUNDLE ([^\\r\\n]*)/m, (l, list) =>
       "a=group:BUNDLE " + list.split(" ").filter((t) => !video.includes(t)).join(" "));`,
  );
  expectBalancedUnbundled(r);
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

// ---- a codec of another clock rate mid-stream (RFC 7160 4.1, RFC 8834 4.3) ----

// Rust sends an Opus track and streams the fixture; then it goes on with a 440 Hz tone in PCMU
// (8 kHz) on the payload type the negotiation gave PCMU, then in PCMA (the same clock rate),
// and then back to Opus. By default the stream stays on one SSRC. With `?ssrc_per_clock_rate=1`
// (`with_ssrc_per_clock_rate(true)`, RFC 7160 section 4.1: "MUST use a different SSRC for each
// different clock rate") the switch to 8 kHz moves the stream to a new SSRC, PCMA stays on it,
// and the return to 48 kHz takes yet another one after a BYE. Either way the browser's receiver
// must keep receiving and playing: what it counts on its track's inbound-rtp and which SSRCs
// its getSynchronizationSources() saw (webrtc-pc 5.3).
//
// The one-SSRC form is the default because libwebrtc's receivers (Chromium, WebKit) do not
// follow the new SSRC: in train 9 round 4 their track stayed on the signalled SSRC and counted
// no packet from the switch on, in both offer directions, while Firefox followed. The RFC-form
// cells are n/a there, on that observation, and a real check on Firefox.
//
// The section has to carry Opus, PCMU and PCMA: the scenario's `audio_codecs` sets them as
// the Rust track's codec preferences (its encoding names Opus, which alone narrows the
// section to Opus). With `rustOffers` Rust offers and the browser answers; otherwise the
// browser offers (a recvonly audio transceiver) and Rust answers. Both descriptions' audio
// formats are in every result, so a failure shows what was negotiated.
const SWITCH_CODECS = ["OPUS", "PCMU", "PCMA"];

async function audioClockRateSwitch(page, url, rustOffers) {
  return page.evaluate(async ([ws, rustOffers, codecs]) => {
    const audioFormats = (sdp) => {
      const section = (sdp || "").split(/\r\n(?=m=)/).find((x) => x.startsWith("m=audio")) || "";
      return [...section.matchAll(/^a=rtpmap:\d+ ([^/\r\n]+)\/(\d+)/gm)].map((x) => `${x[1]}/${x[2]}`);
    };
    const caps = (RTCRtpReceiver.getCapabilities("audio")?.codecs || []).map((c) => `${c.mimeType}/${c.clockRate}`);
    const has = (mime) => caps.some((c) => c.toLowerCase().startsWith(`${mime.toLowerCase()}/`));
    const scenario = rustOffers
      ? { audio_codecs: codecs }
      : { media: "send", audio: true, audio_codecs: codecs };
    const s = await Interop.open(ws, scenario);
    let receiver = null;
    s.pc.ontrack = (e) => {
      receiver = e.receiver;
      Interop.sink(new MediaStream([e.track]));
    };
    if (rustOffers) {
      s.pc.createDataChannel("first");
      await s.negotiate();
      await s.connected();
      s.send({ type: "request-offer", tracks: ["OPUS"] });
      await Interop.until(() => s.remoteOffers > 0 && s.pc.signalingState === "stable" && receiver, 15000, "Rust's offer");
    } else {
      s.pc.addTransceiver("audio", { direction: "recvonly" });
      await s.negotiate();
      await s.connected();
      await Interop.until(() => receiver, 15000, "the browser's audio track");
    }
    const formats = {
      offer: audioFormats((rustOffers ? s.pc.remoteDescription : s.pc.localDescription)?.sdp),
      answer: audioFormats((rustOffers ? s.pc.localDescription : s.pc.remoteDescription)?.sdp),
    };
    const browser = { caps, pcmu: has("audio/PCMU"), pcma: has("audio/PCMA") };
    const negotiated = ["PCMU/8000", "PCMA/8000"].every((f) => formats.answer.some((a) => a.toUpperCase() === f));
    if (!browser.pcmu || !browser.pcma || !negotiated) {
      s.close();
      return { rustOffers, browser, formats, negotiated };
    }
    const snapshot = async () => {
      const stats = await receiver.getStats();
      const mimes = {};
      stats.forEach((x) => {
        if (x.type === "codec") mimes[x.id] = x.mimeType;
      });
      const out = { packets: 0, samples: undefined, concealed: undefined, inbound: [] };
      stats.forEach((x) => {
        if (x.type !== "inbound-rtp") return;
        out.packets += x.packetsReceived || 0;
        if (x.totalSamplesReceived !== undefined) out.samples = (out.samples || 0) + x.totalSamplesReceived;
        if (x.concealedSamples !== undefined) out.concealed = (out.concealed || 0) + x.concealedSamples;
        out.inbound.push({ ssrc: x.ssrc, packetsReceived: x.packetsReceived, mime: mimes[x.codecId] });
      });
      out.sources = receiver.getSynchronizationSources().map((x) => x.source);
      return out;
    };
    const wire = async () => {
      const report = await s.report();
      return { ssrc: report.sent.find((x) => /^audio\//i.test(x.mime))?.wireSsrc, errors: report.errors };
    };
    // Runs `ms` of one format: the packets and the played (not concealed) samples the
    // receiver counted over it, and the SSRC Rust sent it with.
    const phase = async (codec, ms) => {
      if (codec) s.send({ type: "switch-codec", codec });
      await Interop.sleep(700);
      const before = await snapshot();
      await Interop.sleep(ms);
      const after = await snapshot();
      const delta = (k) => (after[k] === undefined || before[k] === undefined ? undefined : after[k] - before[k]);
      const concealed = delta("concealed");
      const samples = delta("samples");
      const w = await wire();
      return {
        codec: codec || "OPUS",
        packets: after.packets - before.packets,
        played: samples === undefined ? undefined : samples - (concealed || 0),
        wire: w.ssrc,
        sources: after.sources,
        inbound: after.inbound,
        errors: w.errors,
      };
    };
    await Interop.until(async () => (await snapshot()).packets > 50, 15000, "50 Opus packets").catch(() => {});
    const opus = await phase(null, 3000);
    const pcmu = await phase("PCMU", 4000);
    const pcma = await phase("PCMA", 4000);
    const back = await phase("OPUS", 4000);
    s.close();
    return { rustOffers, browser, formats, negotiated, opus, pcmu, pcma, back, errors: back.errors.concat(s.errors) };
  }, [url, rustOffers, SWITCH_CODECS]);
}

function expectAudioFollowsTheSwitch(r) {
  // RFC 7874 section 4 has every WebRTC endpoint support PCMA and PCMU: only a browser whose
  // own capability API lacks one is n/a.
  naBrowser(
    !r.browser.pcmu || !r.browser.pcma,
    "this browser cannot receive PCMU and PCMA",
    `RTCRtpReceiver.getCapabilities("audio"): ${JSON.stringify(r.browser.caps)}`,
  );
  expect(r.negotiated, `the audio section did not negotiate PCMU and PCMA: ${JSON.stringify(r)}`).toBe(true);
  expect(r.errors, JSON.stringify(r)).toEqual([]);
  for (const p of [r.opus, r.pcmu, r.pcma, r.back]) {
    // 20 ms frames: about 50 packets a second, at least 100 in the four seconds measured.
    expect(p.packets, `${p.codec}: the browser's receiver stopped counting packets: ${JSON.stringify(r)}`)
      .toBeGreaterThan(p === r.opus ? 75 : 100);
    if (p.played !== undefined) {
      expect(p.played, `${p.codec}: the browser played only concealment: ${JSON.stringify(r)}`).toBeGreaterThan(0);
    }
    expect(p.sources, `${p.codec}: the receiver saw no packet of SSRC ${p.wire}: ${JSON.stringify(r)}`).toContain(p.wire);
    // The format the browser decoded the phase as: the payload type Rust put on its packets.
    // (Opus once went out on PCMU's number when Rust offered: the payload type was read from
    // the sender's parameters before the answer.)
    const mime = p.inbound.find((x) => x.ssrc === p.wire)?.mime;
    if (mime !== undefined) {
      expect(mime.toLowerCase(), `${p.codec}: the browser decoded it as ${mime}: ${JSON.stringify(r)}`).toBe(`audio/${p.codec.toLowerCase()}`);
    }
  }
}

function expectAnSsrcPerClockRate(r) {
  // libwebrtc keeps a single-stream receiver on the signalled SSRC: the phases Rust sent under
  // a new SSRC reach no track. n/a when that is what happened, so a libwebrtc that starts to
  // follow makes the cell a pass.
  const libwebrtc = /^(chromium|webkit)/.test(test.info().project.name);
  const moved = [r.pcmu, r.pcma, r.back].filter((p) => p && r.opus && p.wire !== r.opus.wire);
  const unfollowed = moved.filter((p) => p.packets <= 100);
  naBrowser(
    libwebrtc && r.opus?.packets > 75 && unfollowed.length > 0,
    "libwebrtc keeps the track on the signalled SSRC and stops counting when Rust moves to a new SSRC for another clock rate",
    `observed: Opus on SSRC ${r.opus?.wire} counted ${r.opus?.packets} packets; ` +
      unfollowed.map((p) => `${p.codec} on SSRC ${p.wire} counted ${p.packets}, the receiver saw sources ${JSON.stringify(p.sources)}`).join("; "),
  );
  expectAudioFollowsTheSwitch(r);
  expect(r.pcmu.wire, `8 kHz after 48 kHz is another SSRC (RFC 7160 4.1): ${JSON.stringify(r)}`).not.toBe(r.opus.wire);
  expect(r.pcma.wire, `PCMA after PCMU is the same clock rate, the same SSRC: ${JSON.stringify(r)}`).toBe(r.pcmu.wire);
  expect([r.opus.wire, r.pcmu.wire], `a return to 48 kHz takes a new SSRC (RFC 7160 4.1): ${JSON.stringify(r)}`).not.toContain(r.back.wire);
}

function expectOneSsrc(r) {
  expectAudioFollowsTheSwitch(r);
  expect(new Set([r.opus.wire, r.pcmu.wire, r.pcma.wire, r.back.wire]).size, JSON.stringify(r)).toBe(1);
}

test("a codec of another clock rate mid-stream: one SSRC, the default", async ({ page }) => {
  expectOneSsrc(await audioClockRateSwitch(page, WS, true));
});

test("a codec of another clock rate mid-stream, an SSRC per clock rate (with_ssrc_per_clock_rate(true)): the browser follows Rust to each new SSRC", async ({ page }) => {
  expectAnSsrcPerClockRate(await audioClockRateSwitch(page, `${WS}/?ssrc_per_clock_rate=1`, true));
});

test("a codec of another clock rate mid-stream, the browser offering: one SSRC, the default", async ({ page }) => {
  expectOneSsrc(await audioClockRateSwitch(page, WS, false));
});

test("a codec of another clock rate mid-stream, the browser offering, an SSRC per clock rate (with_ssrc_per_clock_rate(true)): it follows Rust to each new SSRC", async ({ page }) => {
  expectAnSsrcPerClockRate(await audioClockRateSwitch(page, `${WS}/?ssrc_per_clock_rate=1`, false));
});

// ---- the browser's SSRCs unsignalled: RTX found by its payload type (RFC 4588 5.3) ----

// The loss recovery above, with every a=ssrc and a=ssrc-group line removed from the offer Rust
// receives: Rust learns the browser's video SSRC from its first packet (MID), and its RTX SSRC
// only by the RTX payload type's apt in that single-stream section; RTX that arrives before
// any original (a browser's early padding probes) is dropped. NACK and RTX must still repair
// what netem drops.
test("loss recovery with the browser's SSRCs unsignalled: RTX is associated by its payload type", async ({ page }) => {
  await page.evaluate(async (ws) => {
    const s = await Interop.open(ws, { media: "reflect", video: "VP8" });
    window.S = s;
    const tr = s.pc.addTransceiver(Interop.canvasStream(640, 480).getVideoTracks()[0], { direction: "sendrecv" });
    Interop.prefer(tr, "video", "video/VP8");
    s.pc.ontrack = (e) => Interop.sink(new MediaStream([e.track]));
    await s.negotiate((sdp) => sdp.replace(/^a=ssrc(-group)?:[^\r\n]*\r?\n/gm, ""));
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
      const frames = (await Interop.inbound(S.pc, "video"))?.framesDecoded || 0;
      return { out, report, frames, rtx: Interop.mlines(S.pc.remoteDescription.sdp)[0].rtx };
    });
  } finally {
    restore();
  }
  const drops = netemDrops() - dropsBefore;
  await page.evaluate(() => S.close());
  expect(drops, "netem dropped nothing: the filter did not apply").toBeGreaterThan(0);
  expect(r.rtx, "the Rust answer negotiates no RTX for the video").toBe(true);
  expect(r.report.errors).toEqual([]);
  const video = r.report.coverage.filter((c) => c.key.startsWith("video:"));
  expect(video.length, JSON.stringify(r.report.coverage)).toBeGreaterThan(0);
  const v = video.reduce((a, b) => (b.span > a.span ? b : a));
  expect(v.span, JSON.stringify(v)).toBeGreaterThan(150);
  expect(v.missing / v.span, `still missing after NACK/RTX: ${JSON.stringify(v)}`).toBeLessThan(0.005);
  if (r.out?.retransmittedPacketsSent !== undefined) {
    expect(r.out.retransmittedPacketsSent, JSON.stringify(r.out)).toBeGreaterThan(0);
  }
  // The reflected video still decodes: no stream of Rust's receiver was taken over by RTX.
  expect(r.frames, JSON.stringify(r)).toBeGreaterThan(100);
});

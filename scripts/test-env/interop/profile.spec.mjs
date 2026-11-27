// The core scenarios with the Rust peer under the `Chrome` behaviour profile
// (docs/behaviour-profiles.md): examples/interop-peer builds its peer connection with
// `SettingEngineBuilder::with_behaviour_profile(BehaviourProfile::Chrome)` and
// `MediaEngine::for_profile` when the WebSocket URL carries `?profile=chrome`. Data channel,
// audio and video both ways, renegotiation, ICE restart and simulcast receive.
//
// Every skip goes through na.mjs with its kind and citation (gate.mjs fails an uncited one).
import { test, expect } from "@playwright/test";
import { naBrowser, naEnv } from "./na.mjs";
import { WS, setupPage } from "./common.mjs";

setupPage();

const CHROME = `${WS}/?profile=chrome`;

test("chrome profile: data channel ordered", async ({ page }) => {
  const r = await page.evaluate(async (ws) => {
    const s = await Interop.open(ws, {});
    const dc = s.pc.createDataChannel("interop", { ordered: true });
    await s.negotiate();
    await s.connected();
    const e = await Interop.echo(dc, 200);
    await e.wait(200, 20000);
    s.close();
    return { got: e.got, errors: s.errors };
  }, CHROME);
  expect(r.errors).toEqual([]);
  expect(r.got).toEqual(Array.from({ length: 200 }, (_, i) => `msg-${i}`));
});

test("chrome profile: audio and video both ways", async ({ page }) => {
  const r = await page.evaluate(async (ws) => {
    const s = await Interop.open(ws, { media: "reflect", video: "VP8", audio: true });
    const tr = s.pc.addTransceiver(Interop.canvasStream().getVideoTracks()[0], { direction: "sendrecv" });
    Interop.prefer(tr, "video", "video/VP8");
    s.pc.addTransceiver(Interop.audioStream().getAudioTracks()[0], { direction: "sendrecv" });
    s.pc.ontrack = (e) => Interop.sink(new MediaStream([e.track]));
    await s.negotiate();
    await s.connected();
    const video = await Interop.until(async () => {
      const v = await Interop.inbound(s.pc, "video");
      return v && v.framesDecoded > 15 && v;
    }, 25000, "15 decoded frames").catch(async (e) => ({ error: String(e), last: await Interop.inbound(s.pc, "video") }));
    const audio = await Interop.until(async () => {
      const a = await Interop.inbound(s.pc, "audio");
      return a && a.packetsReceived > 100 && a;
    }, 20000, "100 audio packets").catch(async (e) => ({ error: String(e), last: await Interop.inbound(s.pc, "audio") }));
    const report = await s.report();
    // What Rust received on a payload type the browser's offer does not have: one the answer
    // does not have either (RFC 3264 section 7), or a format the answer added (RFC 9429 section
    // 5.3.1) that the browser switched to (WebKit, seen in the loss-recovery cells, common.mjs
    // unlessOffFormat). Named rather than taken for video that stopped.
    const offPt = Interop.receivedOutside(report, s.pc.localDescription.sdp);
    const notInAnswer = Interop.receivedOutside(report, s.pc.remoteDescription.sdp);
    const answerVideo = Interop.codecLines(s.pc.remoteDescription.sdp, "video");
    const sending = (await Interop.codecView(s.pc)).sending;
    s.close();
    return {
      video, audio, errors: report.errors, offPt, notInAnswer, answerVideo, sending,
      wire: report.wireRtp?.received, engineIgnored: report.unnegotiatedPayloadTypeRtp,
    };
  }, CHROME);
  console.log(
    `[${test.info().project.name}] chrome profile payload types: answer ${JSON.stringify(r.answerVideo)}; received ${JSON.stringify(r.wire)}; ` +
      `the engine ignored ${r.engineIgnored} for an unnegotiated payload type; the browser sending ${JSON.stringify(r.sending)}`,
  );
  expect(
    r.offPt,
    `the browser sent media on a payload type its offer does not have (${r.notInAnswer.length ? "nor the answer, RFC 3264 section 7" : "a format the answer added, RFC 9429 section 5.3.1"}): ${JSON.stringify(r)}`,
  ).toEqual([]);
  expect(r.video.error, JSON.stringify(r)).toBeUndefined();
  expect(r.audio.error, JSON.stringify(r)).toBeUndefined();
  expect(r.video.mimeType.toLowerCase()).toBe("video/vp8");
  expect(r.audio.mimeType.toLowerCase()).toBe("audio/opus");
  expect(r.errors).toEqual([]);
});

test("chrome profile: renegotiation, Rust offers a new channel", async ({ page }) => {
  const r = await page.evaluate(async (ws) => {
    const s = await Interop.open(ws, {});
    s.pc.createDataChannel("first");
    await s.negotiate();
    await s.connected();
    const got = new Promise((res) => {
      s.pc.ondatachannel = (e) => {
        e.channel.onmessage = (m) => res([e.channel.label, m.data]);
      };
    });
    s.send({ type: "request-offer" });
    const result = await Promise.race([got, Interop.sleep(15000).then(() => "timeout")]);
    // The new channel opens over the SCTP association that already exists, so its message can
    // arrive before the offer that the WebSocket carries has reached the page: wait for it.
    await Interop.until(() => s.remoteOffers > 0 && s.pc.signalingState === "stable", 15000, "Rust's offer").catch(() => {});
    s.close();
    return { result, offers: s.remoteOffers, errors: s.errors };
  }, CHROME);
  expect(r.errors).toEqual([]);
  expect(r.offers).toBe(1);
  expect(r.result).toEqual(["from-rust", "hello-from-rust"]);
});

test("chrome profile: ICE restart keeps the data channel", async ({ page }) => {
  const r = await page.evaluate(async (ws) => {
    const s = await Interop.open(ws, {});
    const dc = s.pc.createDataChannel("restart");
    await s.negotiate();
    await s.connected();
    const ufrag = s.pc.localDescription.sdp.match(/a=ice-ufrag:(\S+)/)[1];
    s.pc.restartIce();
    await s.negotiate();
    const ufrag2 = s.pc.localDescription.sdp.match(/a=ice-ufrag:(\S+)/)[1];
    await Interop.sleep(2000);
    await s.connected();
    const e = await Interop.echo(dc, 20);
    await e.wait(20, 15000);
    s.close();
    return { changed: ufrag !== ufrag2, echoed: e.got.length, errors: s.errors };
  }, CHROME);
  expect(r.errors).toEqual([]);
  expect(r.changed).toBe(true);
  expect(r.echoed).toBe(20);
});

test("chrome profile: simulcast, three RIDs reach Rust", async ({ page }) => {
  const r = await page.evaluate(async (ws) => {
    const s = await Interop.open(ws, { media: "count" });
    const track = Interop.canvasStream(1280, 720).getVideoTracks()[0];
    const tr = s.pc.addTransceiver(track, {
      direction: "sendonly",
      sendEncodings: [
        { rid: "q", scaleResolutionDownBy: 4.0, maxBitrate: 100000 },
        { rid: "h", scaleResolutionDownBy: 2.0, maxBitrate: 200000 },
        { rid: "f", maxBitrate: 400000 },
      ],
    });
    Interop.prefer(tr, "video", "video/VP8");
    const params = tr.sender.getParameters();
    const acceptedRids = (params.encodings || []).map((e) => e.rid).filter(Boolean);
    try {
      params.degradationPreference = "maintain-resolution";
      await tr.sender.setParameters(params);
    } catch {}
    await s.negotiate();
    const offeredRids = [...s.pc.localDescription.sdp.matchAll(/^a=rid:(\S+) send/gm)].map((m) => m[1]);
    await s.connected();
    let report;
    await Interop.until(async () => {
      report = await s.report();
      const rids = new Set(Object.keys(report.rtp).filter((k) => report.rtp[k] > 20).map((k) => k.split(":")[1]));
      return ["q", "h", "f"].every((x) => rids.has(x));
    }, 25000, "packets on q, h and f").catch(() => {});
    const sent = {};
    (await s.pc.getStats()).forEach((x) => {
      if (x.type === "outbound-rtp" && x.kind === "video" && x.rid) {
        sent[x.rid] = { packets: x.packetsSent || 0, width: x.frameWidth, limit: x.qualityLimitationReason };
      }
    });
    s.close();
    return { report, sent, acceptedRids, offeredRids };
  }, CHROME);
  naBrowser(
    r.acceptedRids.length < 3,
    `the browser kept ${r.acceptedRids.length} of 3 send encodings`,
    `RTCRtpSender.getParameters().encodings after addTransceiver with three sendEncodings: ${JSON.stringify(r.acceptedRids)}`,
  );
  naBrowser(
    r.offeredRids.length < 3,
    `the browser's own offer declares ${r.offeredRids.length} send RIDs`,
    `its offer's a=rid lines (RFC 8853 section 5): ${JSON.stringify(r.offeredRids)}`,
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
    `outbound-rtp.qualityLimitationReason "cpu" (W3C webrtc-stats 7.3): ${JSON.stringify(r.sent)}`,
  );
  const rids = new Set(
    Object.keys(r.report.rtp)
      .filter((k) => r.report.rtp[k] > 20)
      .map((k) => k.split(":")[1]),
  );
  expect([...rids].sort(), JSON.stringify(r)).toEqual(["f", "h", "q"]);
});

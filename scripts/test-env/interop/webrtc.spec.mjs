// Browser <-> webrtc-rs-rtc interop. Each test opens a page on a local origin (served by
// Playwright, a secure context), loads peer.js and drives a session with
// examples/interop-peer at RTC_INTEROP_WS.
import { test, expect } from "@playwright/test";
import { readFileSync } from "node:fs";

const WS = process.env.RTC_INTEROP_WS || "ws://127.0.0.1:8080";
const PEER_JS = readFileSync(new URL("./peer.js", import.meta.url), "utf8");

test.beforeEach(async ({ page }) => {
  page.on("console", (m) => {
    if (m.type() === "error") console.log(`[${test.info().project.name}] console: ${m.text()}`);
  });
  await page.route("http://localhost/**", (route) =>
    route.fulfill({ contentType: "text/html", body: "<!doctype html><title>interop</title><body></body>" }),
  );
  await page.goto("http://localhost/index.html");
  await page.addScriptTag({ content: PEER_JS });
});

async function skipUnlessCodec(page, kind, mime, dir) {
  const ok = await page.evaluate(([k, m, d]) => Interop.hasCodec(k, m, d), [kind, mime, dir]);
  test.skip(!ok, `this browser has no ${mime} ${dir === "receiver" ? "decoder" : "encoder"}`);
}

// ---- data channels ----

for (const [name, init, count, size, exact] of [
  ["data channel ordered", { ordered: true }, 200, 0, true],
  ["data channel unordered", { ordered: false }, 200, 0, false],
  ["data channel unreliable (maxRetransmits 0)", { ordered: false, maxRetransmits: 0 }, 200, 0, false],
  ["data channel 64 KiB binary messages", { ordered: true }, 20, 65536, true],
]) {
  test(name, async ({ page }) => {
    const r = await page.evaluate(
      async ([ws, init, count, size]) => {
        const s = await Interop.open(ws, {});
        const dc = s.pc.createDataChannel("interop", init);
        await s.negotiate();
        await s.connected();
        const e = await Interop.echo(dc, count, size);
        await e.wait(count, 20000);
        const got = e.got.map((m) => (typeof m === "string" ? m : new DataView(m.buffer).getUint32(0)));
        const sizes = e.got.map((m) => (typeof m === "string" ? m.length : m.length));
        s.close();
        return { got, sizes };
      },
      [WS, init, count, size],
    );
    const want = Array.from({ length: count }, (_, i) => (size ? i : `msg-${i}`));
    if (exact) expect(r.got).toEqual(want);
    else expect([...r.got].sort()).toEqual([...want].sort());
    if (size) expect(new Set(r.sizes)).toEqual(new Set([size]));
  });
}

test("data channel negotiated (id 5)", async ({ page }) => {
  const got = await page.evaluate(async (ws) => {
    const s = await Interop.open(ws, { negotiated: [{ label: "neg", id: 5, ordered: true }] });
    const dc = s.pc.createDataChannel("neg", { negotiated: true, id: 5 });
    // A negotiated channel alone does not make the offer carry an SCTP section; an in-band
    // one does, so the association exists for the pre-negotiated stream.
    s.pc.createDataChannel("carrier");
    await s.negotiate();
    await s.connected();
    const e = await Interop.echo(dc, 50);
    await e.wait(50, 15000);
    s.close();
    return e.got;
  }, WS);
  expect(got).toEqual(Array.from({ length: 50 }, (_, i) => `msg-${i}`));
});

test("renegotiation: the browser adds a channel", async ({ page }) => {
  const r = await page.evaluate(async (ws) => {
    const s = await Interop.open(ws, {});
    const a = s.pc.createDataChannel("first");
    await s.negotiate();
    await s.connected();
    const e1 = await Interop.echo(a, 10);
    await e1.wait(10, 10000);
    const b = s.pc.createDataChannel("second");
    // A second channel needs no new offer once SCTP is up; renegotiate anyway (W3C allows
    // it), and the transport must survive the new offer/answer.
    await s.negotiate();
    const e2 = await Interop.echo(b, 10);
    await e2.wait(10, 10000);
    s.close();
    return [e1.got.length, e2.got.length, s.errors];
  }, WS);
  expect(r).toEqual([10, 10, []]);
});

test("renegotiation: Rust offers a new channel", async ({ page }) => {
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
    s.close();
    return { result, offers: s.remoteOffers, errors: s.errors };
  }, WS);
  expect(r.errors).toEqual([]);
  expect(r.offers).toBe(1);
  expect(r.result).toEqual(["from-rust", "hello-from-rust"]);
});

test("ICE restart keeps the data channel", async ({ page }) => {
  const r = await page.evaluate(async (ws) => {
    const s = await Interop.open(ws, {});
    const dc = s.pc.createDataChannel("restart");
    await s.negotiate();
    await s.connected();
    const before = (await Interop.transport(s.pc))?.selectedCandidatePairChanges;
    const ufrag = s.pc.localDescription.sdp.match(/a=ice-ufrag:(\S+)/)[1];
    s.pc.restartIce();
    await s.negotiate();
    const ufrag2 = s.pc.localDescription.sdp.match(/a=ice-ufrag:(\S+)/)[1];
    await Interop.sleep(2000);
    await s.connected();
    const e = await Interop.echo(dc, 20);
    await e.wait(20, 15000);
    s.close();
    return { changed: ufrag !== ufrag2, echoed: e.got.length, errors: s.errors, before };
  }, WS);
  expect(r.errors).toEqual([]);
  expect(r.changed).toBe(true);
  expect(r.echoed).toBe(20);
});

test("DTLS and SRTP are negotiated", async ({ page }) => {
  const t = await page.evaluate(async (ws) => {
    const s = await Interop.open(ws, { media: "reflect", video: "VP8" });
    const tr = s.pc.addTransceiver(Interop.canvasStream().getVideoTracks()[0], { direction: "sendrecv" });
    Interop.prefer(tr, "video", "video/VP8");
    await s.negotiate();
    await s.connected();
    await Interop.sleep(1000);
    const t = await Interop.transport(s.pc);
    s.close();
    return t;
  }, WS);
  expect(t.dtlsState).toBe("connected");
  // Chromium and Firefox report the negotiated suites; WebKit may not fill them in.
  if (t.dtlsCipher !== undefined) expect(t.dtlsCipher).toMatch(/AES_128_GCM|CHACHA20/);
  if (t.srtpCipher !== undefined) expect(t.srtpCipher).toMatch(/AES|AEAD/);
});

// ---- media: the browser sends, Rust reflects ----

for (const codec of ["VP8", "VP9", "H264"]) {
  test(`reflect video ${codec}`, async ({ page }) => {
    await skipUnlessCodec(page, "video", `video/${codec}`, "sender");
    const r = await page.evaluate(
      async ([ws, codec]) => {
        const s = await Interop.open(ws, { media: "reflect", video: codec });
        const tr = s.pc.addTransceiver(Interop.canvasStream().getVideoTracks()[0], { direction: "sendrecv" });
        Interop.prefer(tr, "video", `video/${codec}`);
        s.pc.ontrack = (e) => Interop.sink(new MediaStream([e.track]));
        await s.negotiate();
        await s.connected();
        const rtp = await Interop.until(async () => {
          const r = await Interop.inbound(s.pc, "video");
          return r && r.framesDecoded > 30 && r;
        }, 25000, "30 decoded frames").catch(async (e) => ({ error: String(e), last: await Interop.inbound(s.pc, "video") }));
        const report = await s.report();
        s.close();
        return { rtp, report };
      },
      [WS, codec],
    );
    expect(r.rtp.error, JSON.stringify(r)).toBeUndefined();
    expect(r.rtp.mimeType.toLowerCase()).toBe(`video/${codec}`.toLowerCase());
  });
}

test("reflect audio Opus", async ({ page }) => {
  const r = await page.evaluate(async (ws) => {
    const s = await Interop.open(ws, { media: "reflect", audio: true });
    s.pc.addTransceiver(Interop.audioStream().getAudioTracks()[0], { direction: "sendrecv" });
    s.pc.ontrack = (e) => Interop.sink(new MediaStream([e.track]));
    await s.negotiate();
    await s.connected();
    const rtp = await Interop.until(async () => {
      const r = await Interop.inbound(s.pc, "audio");
      return r && r.packetsReceived > 100 && r;
    }, 20000, "100 audio packets").catch(async (e) => ({ error: String(e), last: await Interop.inbound(s.pc, "audio") }));
    s.close();
    return rtp;
  }, WS);
  expect(r.error, JSON.stringify(r)).toBeUndefined();
  expect(r.mimeType.toLowerCase()).toBe("audio/opus");
});

// ---- media: Rust sends GStreamer-encoded files, the browser decodes ----

for (const [codec, kind, mime] of [
  ["VP8", "video", "video/VP8"],
  ["VP9", "video", "video/VP9"],
  ["H264", "video", "video/H264"],
  ["OPUS", "audio", "audio/opus"],
]) {
  test(`receive ${codec} from Rust (GStreamer fixture)`, async ({ page }) => {
    await skipUnlessCodec(page, kind, mime, "receiver");
    const r = await page.evaluate(
      async ([ws, codec, kind, mime]) => {
        const sc = kind === "video" ? { media: "send", video: codec } : { media: "send", audio: true };
        const s = await Interop.open(ws, sc);
        const tr = s.pc.addTransceiver(kind, { direction: "recvonly" });
        if (kind === "video") Interop.prefer(tr, "video", mime);
        s.pc.ontrack = (e) => Interop.sink(new MediaStream([e.track]));
        await s.negotiate();
        await s.connected();
        const rtp = await Interop.until(async () => {
          const r = await Interop.inbound(s.pc, kind);
          return r && (kind === "video" ? r.framesDecoded > 30 : r.packetsReceived > 100) && r;
        }, 25000, "decoded media").catch(async (e) => ({ error: String(e), last: await Interop.inbound(s.pc, kind) }));
        const report = await s.report();
        s.close();
        return { rtp, report };
      },
      [WS, codec, kind, mime],
    );
    expect(r.rtp.error, JSON.stringify(r)).toBeUndefined();
    expect(r.rtp.mimeType.toLowerCase()).toBe(mime.toLowerCase());
  });
}

// ---- simulcast ----

test("simulcast: three RIDs reach Rust", async ({ page }) => {
  const r = await page.evaluate(async (ws) => {
    const s = await Interop.open(ws, { media: "count" });
    const track = Interop.canvasStream().getVideoTracks()[0];
    // 320x240 is small; keep every layer above the encoders' minimum size.
    const tr = s.pc.addTransceiver(track, {
      direction: "sendonly",
      sendEncodings: [
        { rid: "q", scaleResolutionDownBy: 2.0, maxBitrate: 150000 },
        { rid: "h", scaleResolutionDownBy: 1.5, maxBitrate: 300000 },
        { rid: "f", maxBitrate: 600000 },
      ],
    });
    Interop.prefer(tr, "video", "video/VP8");
    await s.negotiate();
    await s.connected();
    let report;
    await Interop.until(async () => {
      report = await s.report();
      const rids = new Set(Object.keys(report.rtp).filter((k) => report.rtp[k] > 20).map((k) => k.split(":")[1]));
      return ["q", "h", "f"].every((x) => rids.has(x));
    }, 25000, "packets on q, h and f").catch(() => {});
    s.close();
    return report;
  }, WS);
  const rids = Object.keys(r.rtp).filter((k) => r.rtp[k] > 20).map((k) => k.split(":")[1]);
  expect(new Set(rids), JSON.stringify(r)).toEqual(new Set(["q", "h", "f"]));
});

// ---- encoded transforms (an SFrame-style end-to-end transform) ----

test("encoded transform: Rust forwards transformed VP8 untouched", async ({ page }) => {
  const r = await page.evaluate(async (ws) => {
    const insertable = !!RTCRtpSender.prototype.createEncodedStreams;
    if (!insertable && !window.RTCRtpScriptTransform) return { unsupported: true };
    const s = await Interop.open(ws, { media: "reflect", video: "VP8" }, { insertableStreams: insertable });
    const tr = s.pc.addTransceiver(Interop.canvasStream().getVideoTracks()[0], { direction: "sendrecv" });
    Interop.prefer(tr, "video", "video/VP8");
    const api = Interop.attachTransform(tr.sender);
    s.pc.ontrack = (e) => {
      Interop.attachTransform(e.receiver);
      Interop.sink(new MediaStream([e.track]));
    };
    await s.negotiate();
    await s.connected();
    const rtp = await Interop.until(async () => {
      const r = await Interop.inbound(s.pc, "video");
      return r && r.framesDecoded > 30 && r;
    }, 25000, "30 decoded frames through the transform").catch(async (e) => ({ error: String(e), last: await Interop.inbound(s.pc, "video") }));
    s.close();
    return { api, rtp };
  }, WS);
  test.skip(!!r.unsupported, "this browser has neither createEncodedStreams nor RTCRtpScriptTransform");
  expect(r.rtp.error, JSON.stringify(r)).toBeUndefined();
});

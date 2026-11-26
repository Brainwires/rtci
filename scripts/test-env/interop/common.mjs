// Shared by the spec files: the page every test runs in, the signalling address, the media
// fixtures, and per-session netem (a tc filter that sends one session's packets through the
// lossy band interop/run.sh sets up on open-a's eth0).
import { test, expect } from "@playwright/test";
import { readFileSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";

export const WS = process.env.RTC_INTEROP_WS || "ws://127.0.0.1:8080";
export const MEDIA = process.env.RTC_TESTENV_MEDIA || "/run/rtc-env/media";
export const TURN = {
  urls: `turn:${process.env.RTC_TESTENV_TURN_UDP || "203.0.113.10:3478"}?transport=udp`,
  username: process.env.RTC_TESTENV_TURN_USER || "test",
  credential: process.env.RTC_TESTENV_TURN_PASS || "test",
};
const PEER_JS = readFileSync(new URL("./peer.js", import.meta.url), "utf8");

// Writes every description the browser sent in a test (peer.js keeps them, as the browser
// wrote them) to RTC_INTEROP_SDP_DIR as `<project>--<test title>--<n>-<type>.sdp`, when set:
// real browser SDP for the engine's fixtures (tests/fixtures/browser-sdp/).
export function recordDescriptions() {
  const dir = process.env.RTC_INTEROP_SDP_DIR;
  if (!dir) return;
  test.afterEach(async ({ page }, info) => {
    let sent = [];
    try {
      sent = await page.evaluate(() => window.__interopDescriptions || []);
    } catch {
      return;
    }
    if (!sent.length) return;
    const slug = info.title.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 90);
    try {
      mkdirSync(dir, { recursive: true });
      sent.forEach((d, i) =>
        writeFileSync(`${dir}/${info.project.name}--${slug}--${i + 1}-${d.type}.sdp`, d.sdp),
      );
    } catch (e) {
      console.log(`[${info.project.name}] could not record the descriptions: ${e}`);
    }
  });
}

const ARTIFACTS = process.env.RTC_TESTENV_ARTIFACTS_DIR || "/artifacts";
const slugOf = (title) => title.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 90);

// Writes `descriptions` (a session's `descriptions`: [direction, type, sdp], every description
// it sent, received or applied, in order) to ARTIFACTS/failed-cell-sdp/ as
// `<project>--<test title>--<tag>--<n>-<direction>-<type>.sdp`.
function saveDescriptions(descriptions, tag) {
  const info = test.info();
  const dir = `${ARTIFACTS}/failed-cell-sdp`;
  try {
    mkdirSync(dir, { recursive: true });
    (descriptions || []).forEach(([direction, type, sdp], i) =>
      writeFileSync(`${dir}/${info.project.name}--${slugOf(info.title)}--${tag}--${i + 1}-${direction}-${type}.sdp`, sdp),
    );
  } catch (e) {
    console.log(`[${info.project.name}] could not save the descriptions: ${e}`);
  }
}

// A failed cell keeps the offer and answer of its session (`window.S`, where the test has one)
// in the uploaded artifacts.
function saveFailedDescriptions() {
  test.afterEach(async ({ page }, info) => {
    if (info.status === info.expectedStatus) return;
    let descriptions = null;
    try {
      descriptions = await page.evaluate(() => window.S?.descriptions || null);
    } catch {
      return;
    }
    if (descriptions?.length) saveDescriptions(descriptions, "failed");
  });
}

export function setupPage() {
  recordDescriptions();
  saveFailedDescriptions();
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
}

export const fixtureExists = (file) => existsSync(`${MEDIA}/${file}`);

// The UDP port of the Rust side's host candidate in its description.
export function rustUdpPort(sdp) {
  const m = sdp.match(/^a=candidate:\S+ \d+ udp \d+ \S+ (\d+) typ host/im);
  if (!m) throw new Error(`no UDP host candidate in the Rust description:\n${sdp}`);
  return Number(m[1]);
}

// Sends this test's packets to the Rust side's `port` through the netem band (run.sh: 1:4,
// "delay 20ms loss 5%") until the returned function is called. The filter's priority is the
// worker's slot, so parallel tests in other browsers keep their own.
export function impair(port) {
  const prio = String(100 + test.info().parallelIndex);
  const tc = (...args) => execFileSync("tc", args, { stdio: ["ignore", "pipe", "pipe"] }).toString();
  tc("filter", "add", "dev", "eth0", "parent", "1:", "protocol", "ip", "prio", prio, "u32",
    "match", "ip", "protocol", "17", "0xff", "match", "ip", "dport", String(port), "0xffff", "flowid", "1:4");
  return () => {
    try {
      tc("filter", "del", "dev", "eth0", "parent", "1:", "prio", prio);
    } catch {}
  };
}

// Sends what the Rust side sends from `port` through the same netem band on the Rust host's
// WAN interface (open-b's eth0, run.sh), until the returned function is called: loss on the
// path TO the browser, for packets the Rust side necessarily holds when the browser asks for
// them again. Priority per worker slot, apart from `impair`'s and peers.mjs's.
export function impairFromRust(port) {
  const prio = String(300 + test.info().parallelIndex);
  const tc = (...args) =>
    execFileSync("ip", ["netns", "exec", "open-b", "tc", ...args], { stdio: ["ignore", "pipe", "pipe"] }).toString();
  tc("filter", "add", "dev", "eth0", "parent", "1:", "protocol", "ip", "prio", prio, "u32",
    "match", "ip", "protocol", "17", "0xff", "match", "ip", "sport", String(port), "0xffff", "flowid", "1:4");
  return () => {
    try {
      tc("filter", "del", "dev", "eth0", "parent", "1:", "prio", prio);
    } catch {}
  };
}

// Packets the netem band on the Rust host has dropped so far (shared by every impaired test).
export function netemDropsFromRust() {
  const out = execFileSync("ip", ["netns", "exec", "open-b", "tc", "-s", "qdisc", "show", "dev", "eth0"]).toString();
  const m = out.match(/qdisc netem 40:[\s\S]*?dropped (\d+)/);
  return m ? Number(m[1]) : 0;
}

// Packets the netem band has dropped so far (shared by every impaired test running).
export function netemDrops() {
  const out = execFileSync("tc", ["-s", "qdisc", "show", "dev", "eth0"]).toString();
  const m = out.match(/qdisc netem 40:[\s\S]*?dropped (\d+)/);
  return m ? Number(m[1]) : 0;
}

// A browser that sends its media on a payload type the answer does not have.
//
// An offerer sends only formats of the answer (RFC 3264 section 6.1; RFC 8829 section 5.3.1),
// and the engine ignores a packet whose payload type its m= section did not negotiate (RFC 3550
// section 5.1), counted by `RTCPeerConnection::unnegotiated_payload_type_rtp_packets`. A
// browser that switches its sender to such a payload type mid-call (WebKit, seen 6 times in 240
// loss-recovery runs in the test image: about 35 VP8 packets on 96, then everything on 98) leaves
// a cell measuring Rust's handling of its media nothing to measure, and the cell's own checks
// would fail as "span 0". `run` is one attempt of the cell, with `r.wrongPt`
// (Interop.unnegotiatedReceived), `r.views` (Interop.codecView samples), `r.defaults`
// (Interop.defaultCodecLines, taken when wrongPt is not empty), `r.descriptions` and `r.report`;
// `again(page)` runs the cell once more.
//
// Every attempt logs its payload types. With none unnegotiated `run` is returned for the
// cell's own checks. Otherwise the case is logged with both descriptions' format lines, saved
// to the artifacts, and: for WebKit, a known browser defect, recorded as a `known-browser-defect`
// annotation and the cell run ONCE more, whose attempt goes through the same check; for any
// other browser, and for WebKit's second attempt, the cell fails here naming the payload type,
// not as a loss-recovery failure.
export async function unlessUnnegotiatedPayloadType(page, run, again) {
  const info = test.info();
  const browser = info.project.name;
  const describe = (run, attempt) => {
    const r = run.r;
    return {
      attempt,
      wrongPt: r.wrongPt,
      engineIgnored: r.report?.unnegotiatedPayloadTypeRtp,
      wire: r.report?.wireRtp?.received,
      offerVideo: run.codecLines.offer,
      answerVideo: run.codecLines.answer,
      browserTable: r.defaults,
      sending: (r.views || []).map((v) => ({ t: v.t, sending: v.sending, senderCodecs: v.senderCodecs, encodingCodecs: v.encodingCodecs })),
      codecStats: r.views?.[r.views.length - 1]?.codecStats,
    };
  };
  const check = async (run, attempt) => {
    run.codecLines = await page.evaluate(
      (ds) => {
        const last = (direction) => ((ds || []).filter((x) => x[0] === direction).pop() || [])[2];
        return { offer: Interop.codecLines(last("sent"), "video"), answer: Interop.codecLines(last("received"), "video") };
      },
      run.r.descriptions,
    );
    console.log(
      `[${browser}] payload types, attempt ${attempt}: answer ${JSON.stringify(run.codecLines.answer)}; ` +
        `received ${JSON.stringify(run.r.report?.wireRtp?.received)}; the engine ignored ${run.r.report?.unnegotiatedPayloadTypeRtp} ` +
        `for an unnegotiated payload type; the browser sending ${JSON.stringify((run.r.views || []).map((v) => v.sending?.codec))}`,
    );
    if (!run.r.wrongPt?.length) return null;
    const d = describe(run, attempt);
    console.log(`[${browser}] UNNEGOTIATED PAYLOAD TYPE ${JSON.stringify(d)}`);
    saveDescriptions(run.r.descriptions, `unnegotiated-pt-attempt-${attempt}`);
    const pts = run.r.wrongPt.map((w) => `${w.payloadType} (${w.packets} packets)`).join(", ");
    return (
      `the browser sent media on payload type ${pts}, which the answer does not have ` +
      `(RFC 3264 section 6.1); the engine ignored ${d.engineIgnored} packets for it (RFC 3550 section 5.1); ` +
      `answer: ${JSON.stringify(d.answerVideo)}; the browser's own table: ${JSON.stringify(d.browserTable)}; ` +
      `sending: ${JSON.stringify(d.sending.map((s) => s.sending?.codec))}`
    );
  };
  let message = await check(run, 1);
  if (!message) return run;
  if (browser === "webkit") {
    info.annotations.push({
      type: "known-browser-defect",
      description: `WebKit switched its sender to a payload type the answer does not have; the cell ran again. ${message}`,
    });
    await page.evaluate(() => window.S?.pc.getSenders().forEach((x) => x.track && x.track.stop()));
    run = await again(page);
    message = await check(run, 2);
    if (!message) return run;
  }
  expect(run.r.wrongPt, message).toEqual([]);
  return run;
}

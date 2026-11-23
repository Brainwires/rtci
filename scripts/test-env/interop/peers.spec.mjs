// The non-browser peers (scripts/test-env/peers/) against examples/interop-peer: one
// Playwright project per peer, so each cell is `<scenario> [<peer>]` in the matrix. A cell
// hands its peer a plan (peers/README.md), the peer runs it and reports what happened, and the
// checks below decide. Most scenarios run in both directions: "(peer offers)" and "(Rust
// offers)".
//
// A scenario the peer's stack cannot express is na-peer, never skipped silently: either its
// peer.json lists the capability under `lacks` (with the reason and a citation), or the peer
// reports `na` at run time with its own citation.
import { test, expect } from "@playwright/test";
import { naPeer } from "./na.mjs";
import { runPeer, peerInfo } from "./peers.mjs";

const WS = process.env.RTC_INTEROP_WS || "ws://203.0.113.51:8080";
const MDNS_WS = process.env.RTC_INTEROP_MDNS_WS || "ws://10.99.0.51:8080";
const PEER_IP = process.env.RTC_INTEROP_PEER_IP || "203.0.113.50";
const MDNS_PEER_IP = process.env.RTC_INTEROP_MDNS_PEER_IP || "10.99.0.50";
const MEDIA = process.env.RTC_TESTENV_MEDIA || "/run/rtc-env/media";
const TURN_HOST = (process.env.RTC_TESTENV_TURN_UDP || "203.0.113.10:3478").split(":")[0];
const TURN_TLS = process.env.RTC_TESTENV_TURN_TLS || "203.0.113.10:5349";
const TURN_AUTH = {
  username: process.env.RTC_TESTENV_TURN_USER || "test",
  credential: process.env.RTC_TESTENV_TURN_PASS || "test",
};
const CA = process.env.RTC_TESTENV_TURN_CA || "/run/rtc-env/ca.crt";

const peerName = () => test.info().project.name;

// The cell's plan with the defaults filled in.
function plan(p) {
  return {
    ws: WS,
    scenario: {},
    media: MEDIA,
    timeout_ms: 60000,
    ...p,
    config: { trickle: true, iceServers: [], iceTransportPolicy: "all", caFile: CA, ...(p.config || {}) },
  };
}

// na-peer for each capability the cell needs that the peer's peer.json lists under `lacks`.
function needs(caps) {
  const lacks = peerInfo(peerName()).lacks || {};
  for (const c of caps) {
    const l = lacks[c];
    if (l) naPeer(true, l.reason, l.cite);
  }
}

// Runs the plan and turns a peer's run-time `na` into the cell's na-peer; returns the result.
async function run(title, p, caps = []) {
  needs(caps);
  const r = await runPeer(peerName(), plan(p), title, test.info().parallelIndex);
  if (r.na) naPeer(true, r.na.reason, r.na.cite);
  return r;
}

// What a failure message carries: the peer's error, its steps, Rust's errors and the
// transport lines of every description (enough to read a failing cell from the report).
function ctx(r, extra = {}) {
  return JSON.stringify({
    error: r.error,
    steps: (r.steps || []).map((s) => `${s.op}:${s.ok ? "ok" : "FAILED"}${s.error ? ` ${s.error}` : ""}`),
    state: r.connectionState,
    rustErrors: r.rustErrors,
    rust: r.rust && { state: r.rust.state, errors: r.rust.errors, rtp: r.rust.rtp, rtcp: r.rust.rtcp },
    descriptions: transportLines(r.descriptions || []),
    log: r.log,
    ...extra,
  }).slice(0, 6000);
}

function expectOk(r, extra) {
  expect(r.ok, ctx(r, extra)).toBe(true);
  expect(r.rustErrors || [], ctx(r, extra)).toEqual([]);
  expect(r.rust?.errors || [], ctx(r, extra)).toEqual([]);
}

// The transport lines of each description: per m= section its kind, port, mid, ufrag, setup,
// candidate count and direction (peer.js transportLines, for failure reports).
function transportLines(descriptions) {
  return descriptions.map(([dir, type, sdp]) => {
    const [session, ...media] = (sdp || "").split(/\r?\nm=/);
    const groups = [...session.matchAll(/^a=group:BUNDLE[^\r\n]*/gm)].map((g) => g[0]);
    const sections = media.map((m) => {
      const pick = (re) => (m.match(re) || [])[1];
      return [
        m.split(/\r?\n/)[0].split(" ").slice(0, 2).join(" "),
        `mid=${pick(/^a=mid:(\S+)/m)}`,
        `ufrag=${pick(/^a=ice-ufrag:(\S+)/m) || (session.match(/^a=ice-ufrag:(\S+)/m) || [])[1]}`,
        `setup=${pick(/^a=setup:(\S+)/m)}`,
        `candidates=${(m.match(/^a=candidate:/gm) || []).length}`,
        pick(/^a=(sendrecv|sendonly|recvonly|inactive)\r?$/m) || "",
      ].join(" ");
    });
    return `${dir} ${type}: ${groups.join(" | ") || "no group"} || ${sections.join(" || ")}`;
  });
}

// The m-lines of a description: kind, port, direction, mid.
function mlines(sdp) {
  return (sdp || "").split(/\r?\n(?=m=)/).slice(1).map((sec) => ({
    kind: sec.match(/^m=(\S+)/)[1],
    port: Number(sec.match(/^m=\S+ (\d+)/)[1]),
    dir: (sec.match(/^a=(sendrecv|sendonly|recvonly|inactive)\r?$/m) || [, "sendrecv"])[1],
    mid: (sec.match(/^a=mid:(\S+)/m) || [, null])[1],
  }));
}

const lastDescription = (r, dir, type) =>
  [...(r.descriptions || [])].reverse().find((d) => d[0] === dir && d[1] === type)?.[2] || "";
const ufragOf = (sdp) => (sdp.match(/^a=ice-ufrag:(\S+)/m) || [])[1];
const mms = (sdp) => {
  const m = sdp.match(/^a=max-message-size:(\d+)/m);
  return m ? Number(m[1]) : 65536; // RFC 8841 6: absent means 64 KiB
};
// Rust's packets from this peer, of one kind (its report's "kind:rid:mime" keys).
const rustRtp = (r, kind) =>
  Object.entries(r.rust?.rtp || {}).filter(([k]) => k.startsWith(`${kind}:`)).reduce((a, [, n]) => a + n, 0);
const rustMimes = (r, kind) =>
  Object.keys(r.rust?.rtp || {}).filter((k) => k.startsWith(`${kind}:`)).map((k) => k.split(":").slice(2).join(":").toLowerCase());
// What a cell negotiated, for the train's log (docs/interop.md is written from these lines).
function logNegotiated(r) {
  const t = (r.rust?.stats?.transports || []).find((x) => x.dtlsState === "connected") || {};
  console.log(
    `[${peerName()}] ${test.info().title}: peer dtls=${JSON.stringify(r.dtls)} sctp=${JSON.stringify(r.sctp)} ` +
      `rust tlsVersion=${t.tlsVersion} dtlsCipher=${t.dtlsCipher} srtpCipher=${t.srtpCipher} dtlsRole=${t.dtlsRole} ` +
      `pair=${JSON.stringify(r.selectedPair)} rtcp=${JSON.stringify(r.rtcp)} rustRtcp=${JSON.stringify(r.rust?.rtcp)}`,
  );
}

// ---- data channels ----

// [name, init, count, size, exact order]
const CHANNELS = [
  ["data channel ordered", { ordered: true }, 200, 0, true],
  ["data channel unordered", { ordered: false }, 200, 0, false],
  ["data channel unreliable (maxRetransmits 0)", { ordered: false, maxRetransmits: 0 }, 200, 0, false],
  ["data channel partial reliability (maxPacketLifeTime 3000 ms)", { ordered: false, maxPacketLifeTime: 3000 }, 200, 0, false],
  ["data channel 64 KiB binary messages", { ordered: true }, 20, 65536, true],
  ["data channel 256 KiB message", { ordered: true }, 1, 262144, true],
];

function checkEcho(r, label, count, size, exact) {
  const got = r.datachannels?.[label]?.got || [];
  const want = Array.from({ length: count }, (_, i) => (size ? i : `msg-${i}`));
  if (exact) expect(got, ctx(r)).toEqual(want);
  else expect([...got].sort(), ctx(r)).toEqual([...want].sort());
  if (size) expect(new Set(r.datachannels[label].sizes), ctx(r)).toEqual(new Set([size]));
}

for (const [name, init, count, size, exact] of CHANNELS) {
  const caps = [
    ...(init.maxPacketLifeTime !== undefined || init.maxRetransmits !== undefined ? ["partialReliability"] : []),
    ...(size > 65536 ? ["largeMessages"] : []),
  ];
  const big = size > 65536;
  test(`${name} (peer offers)`, async () => {
    const r = await run(test.info().title, {
      steps: [
        { op: "dc", label: "interop", ...init },
        { op: "offer" },
        { op: "connected" },
        { op: "echo", label: "interop", count, size, ms: 30000 },
      ],
    }, caps);
    if (big) bigMessageNa(r);
    expectOk(r);
    checkEcho(r, "interop", count, size, exact);
    if (big) expect(mms(lastDescription(r, "received", "answer")), "Rust states less than 256 KiB").toBeGreaterThanOrEqual(size);
  });
  test(`${name} (Rust offers)`, async () => {
    const r = await run(test.info().title, {
      steps: [
        { op: "request-offer" },
        { op: "connected" },
        { op: "await-channel", label: "from-rust", ms: 15000 },
        { op: "dc", label: "interop", ...init },
        { op: "echo", label: "interop", count, size, ms: 30000 },
      ],
    }, caps);
    if (big) bigMessageNa(r);
    expectOk(r);
    expect(r.remoteChannels?.["from-rust"], ctx(r)).toBe("hello-from-rust");
    checkEcho(r, "interop", count, size, exact);
  });
}

// A peer whose own description states less than 256 KiB cannot take the message (RFC 8841 6).
function bigMessageNa(r) {
  const own = lastDescription(r, "sent", "offer") || lastDescription(r, "sent", "answer");
  naPeer(
    own && mms(own) < 262144,
    `this peer states a max-message-size of ${mms(own)}`,
    "its own description's a=max-message-size (RFC 8841 section 6)",
  );
}

for (const dir of ["peer offers", "Rust offers"]) {
  test(`data channel negotiated (id 5) (${dir})`, async () => {
    const scenario = { negotiated: [{ label: "neg", id: 5, ordered: true }] };
    const steps =
      dir === "peer offers"
        ? [
            { op: "dc", label: "neg", negotiated: 5, ordered: true },
            // A negotiated channel alone makes no SCTP section; an in-band one does.
            { op: "dc", label: "carrier" },
            { op: "offer" },
            { op: "connected" },
            { op: "echo", label: "neg", count: 50, ms: 15000 },
          ]
        : [
            { op: "dc", label: "neg", negotiated: 5, ordered: true },
            { op: "request-offer" },
            { op: "connected" },
            { op: "echo", label: "neg", count: 50, ms: 15000 },
          ];
    const r = await run(test.info().title, { scenario, steps }, ["negotiatedChannels"]);
    expectOk(r);
    checkEcho(r, "neg", 50, 0, true);
  });
}

test("renegotiation: the peer adds a channel", async () => {
  const r = await run(test.info().title, {
    steps: [
      { op: "dc", label: "first" },
      { op: "offer" },
      { op: "connected" },
      { op: "echo", label: "first", count: 10 },
      { op: "dc", label: "second" },
      // No new offer is needed once SCTP is up; renegotiate anyway: the transport must
      // survive it.
      { op: "offer" },
      { op: "echo", label: "second", count: 10 },
    ],
  }, ["renegotiation"]);
  expectOk(r);
  checkEcho(r, "first", 10, 0, true);
  checkEcho(r, "second", 10, 0, true);
});

test("renegotiation: Rust offers a new channel", async () => {
  const r = await run(test.info().title, {
    steps: [
      { op: "dc", label: "first" },
      { op: "offer" },
      { op: "connected" },
      { op: "request-offer" },
      { op: "await-channel", label: "from-rust", ms: 15000 },
    ],
  }, ["renegotiation"]);
  expectOk(r);
  expect(r.remoteOffers, ctx(r)).toBe(1);
  expect(r.remoteChannels?.["from-rust"], ctx(r)).toBe("hello-from-rust");
});

// ---- media both ways ----

const MIME = { opus: "audio/opus", vp8: "video/vp8", vp9: "video/vp9", h264: "video/h264" };

for (const [kind, codec] of [["audio", "opus"], ["video", "vp8"], ["video", "vp9"], ["video", "h264"]]) {
  const label = `${kind === "audio" ? "audio Opus" : `video ${codec.toUpperCase()}`}`;
  const caps = [`codec:${codec}`];
  const n = kind === "audio" ? 100 : 60;
  test(`${label} both ways (peer offers, Rust reflects)`, async () => {
    const scenario = kind === "audio" ? { media: "reflect", audio: true } : { media: "reflect", video: codec.toUpperCase() };
    const r = await run(test.info().title, {
      scenario,
      steps: [
        { op: "track", kind, codec },
        { op: "offer" },
        { op: "connected" },
        { op: "await-rust-rtp", kind, packets: n, ms: 20000 },
        { op: "await-rtp", kind, packets: n, ms: 20000 },
        { op: "report" },
      ],
    }, caps);
    expectOk(r);
    expect(rustRtp(r, kind), ctx(r)).toBeGreaterThanOrEqual(n);
    expect(rustMimes(r, kind), ctx(r)).toContain(MIME[codec]);
    expect(r.rtp?.[kind]?.packets || 0, ctx(r)).toBeGreaterThanOrEqual(n);
    expect((r.rtp?.[kind]?.codec || "").toLowerCase(), ctx(r)).toBe(MIME[codec]);
    logNegotiated(r);
  });
  test(`${label} both ways (Rust offers and streams its fixture)`, async () => {
    const r = await run(test.info().title, {
      steps: [
        { op: "track", kind, codec },
        { op: "request-offer", tracks: [codec.toUpperCase()] },
        { op: "connected" },
        { op: "await-rtp", kind, packets: n, ms: 20000 },
        { op: "await-rust-rtp", kind, packets: n, ms: 20000 },
        { op: "report" },
      ],
    }, caps);
    expectOk(r);
    expect(r.rtp?.[kind]?.packets || 0, ctx(r)).toBeGreaterThanOrEqual(n);
    expect((r.rtp?.[kind]?.codec || "").toLowerCase(), ctx(r)).toBe(MIME[codec]);
    expect(rustRtp(r, kind), ctx(r)).toBeGreaterThanOrEqual(n);
    expect(rustMimes(r, kind), ctx(r)).toContain(MIME[codec]);
  });
}

// ---- RTCP (RFC 3550 6.4, RFC 4585 6.3, RFC 5104 4.3.1, transport-wide CC) ----

test("RTCP: SR and RR both ways, PLI and FIR from the peer, transport-cc feedback from Rust", async () => {
  const r = await run(test.info().title, {
    scenario: { media: "reflect", video: "VP8", audio: true },
    steps: [
      { op: "track", kind: "audio", codec: "opus" },
      { op: "track", kind: "video", codec: "vp8" },
      { op: "offer" },
      { op: "connected" },
      { op: "await-rtp", kind: "video", packets: 100, ms: 20000 },
      { op: "rtcp", types: ["pli", "fir"] },
      // RTCP reports go every second or so (RFC 3550 6.2; the stacks' report intervals).
      { op: "wait", ms: 6000 },
      { op: "report" },
    ],
  }, ["rtcpFeedback"]);
  expectOk(r);
  logNegotiated(r);
  // SR and RR are the engine's own: its RTCP session takes them in and they never reach the
  // application (tests/idle_endpoints.rs), so what Rust received shows in its stats: a sender
  // report makes a remote-outbound-rtp (reportsSent counts them), a report block about one of
  // Rust's streams a remote-inbound-rtp (W3C webrtc-stats 7.5, 7.6). Feedback (PLI, FIR) does
  // reach the application, and the sender's stats count it (pliCount, firCount).
  const rust = r.rust?.rtcp || {};
  const stats = r.rust?.stats || {};
  const srs = (stats.remoteOutbound || []).reduce((a, x) => a + (x.reportsSent || 0), 0);
  const blocks = (stats.remoteInbound || []).length;
  const out = (stats.outbound || []).find((o) => o.kind === "video")?.w3c || {};
  expect(r.rtcp?.sr || 0, `the peer received no SR from Rust: ${ctx(r)}`).toBeGreaterThan(0);
  // A sender puts its reception report blocks in its SRs and sends a bare RR only for the
  // SSRCs that send nothing (RFC 3550 6.4): Rust sends media in this cell, so what the peer must
  // get is report blocks about its streams, in SRs or RRs.
  const peerBlocks = r.reportBlocks ?? null;
  if (peerBlocks !== null) expect(peerBlocks, `the peer received no reception report block from Rust: ${ctx(r)}`).toBeGreaterThan(0);
  else expect(r.rtcp?.rr || 0, `the peer received no RR from Rust: ${ctx(r)}`).toBeGreaterThan(0);
  const secs = (r.steps || []).reduce((a, s) => a + (s.ms || 0), 0) / 1000;
  console.log(`[${peerName()}] RTCP cell: ${secs.toFixed(1)} s; Rust sending SSRCs ${(stats.outbound || []).length}; the peer counted ${JSON.stringify(r.rtcp)}, ${peerBlocks} report blocks`);
  expect(srs, `Rust took in no SR from the peer (remote-outbound-rtp): ${ctx(r, { stats })}`).toBeGreaterThan(0);
  expect(blocks, `Rust took in no report block about its streams (remote-inbound-rtp): ${ctx(r, { stats })}`).toBeGreaterThan(0);
  expect(r.rtcpSent?.pli || 0, ctx(r)).toBeGreaterThan(0);
  expect(Math.max(rust.pli || 0, out.pliCount || 0), `Rust received none of the peer's PLIs: ${ctx(r)}`).toBeGreaterThan(0);
  if ((r.rtcpSent?.fir || 0) > 0) {
    expect(Math.max(rust.fir || 0, out.firCount || 0), `Rust received none of the peer's FIRs: ${ctx(r)}`).toBeGreaterThan(0);
  }
  // Rust sends transport-cc feedback when both the feedback and the header extension are
  // negotiated and the peer's packets carry the extension.
  const answer = lastDescription(r, "received", "answer");
  const twcc = /a=rtcp-fb:\d+ transport-cc/.test(answer) && /transport-wide-cc/.test(answer);
  if (twcc && r.twccSent) expect(r.rtcp?.twcc || 0, `no transport-cc feedback from Rust: ${ctx(r)}`).toBeGreaterThan(0);
});

// ---- loss recovery (RFC 4585 6.2.1, RFC 4588) ----

test("loss recovery: NACK and RTX repair the peer's video under netem (peer offers)", async () => {
  const r = await run(test.info().title, {
    scenario: { media: "reflect", video: "VP8" },
    steps: [
      { op: "track", kind: "video", codec: "vp8" },
      { op: "offer" },
      { op: "connected" },
      { op: "wait", ms: 1000 },
      { op: "impair", direction: "to-rust", ms: 12000 },
      { op: "wait", ms: 1000 },
      { op: "report" },
    ],
  }, ["nackResponder"]);
  expectOk(r);
  expect(r.netemDrops, "netem dropped nothing: the filter did not apply").toBeGreaterThan(0);
  const video = (r.rust?.coverage || []).filter((c) => c.key.startsWith("video:"));
  expect(video.length, ctx(r)).toBeGreaterThan(0);
  const v = video.reduce((a, b) => (b.span > a.span ? b : a));
  expect(v.span, JSON.stringify(v)).toBeGreaterThan(150);
  expect(v.missing / v.span, `still missing after NACK/RTX: ${JSON.stringify(v)} ${ctx(r)}`).toBeLessThan(0.005);
  expect(r.rtcp?.nack || 0, `the peer received no NACK from Rust: ${ctx(r)}`).toBeGreaterThan(0);
});

test("loss recovery: Rust repairs its video to the peer under netem (Rust offers)", async () => {
  const r = await run(test.info().title, {
    steps: [
      { op: "request-offer", tracks: ["VP8"] },
      { op: "connected" },
      { op: "impair", direction: "to-peer", ms: 8000 },
      { op: "wait", ms: 1000 },
      { op: "report" },
    ],
  }, ["nackSender"]);
  expectOk(r);
  expect(r.netemDrops, "netem dropped nothing: the filter did not apply").toBeGreaterThan(0);
  const out = (r.rust?.stats?.outbound || []).find((o) => o.kind === "video")?.w3c || {};
  expect(out.nackCount || 0, `Rust saw no NACK from the peer: ${JSON.stringify(out)} ${ctx(r)}`).toBeGreaterThan(0);
  expect(out.retransmittedPacketsSent || 0, `Rust retransmitted nothing: ${JSON.stringify(out)}`).toBeGreaterThan(0);
  const cov = (r.coverage || []).filter((c) => c.kind === "video" && c.span > 0);
  if (cov.length) {
    const c = cov.reduce((a, b) => (b.span > a.span ? b : a));
    expect(c.missing / c.span, `still missing at the peer after repair: ${JSON.stringify(c)}`).toBeLessThan(0.01);
  }
});

// ---- trickle and non-trickle ICE (RFC 8838, RFC 9429 4.1.17) ----

for (const dir of ["peer offers", "Rust offers"]) {
  test(`non-trickle: every candidate in the description (${dir})`, async () => {
    const first = dir === "peer offers" ? [{ op: "dc", label: "nt" }, { op: "offer" }] : [{ op: "request-offer" }];
    const label = dir === "peer offers" ? "nt" : "from-rust";
    const r = await run(test.info().title, {
      config: { trickle: false },
      steps: [
        ...first,
        { op: "connected" },
        ...(dir === "peer offers" ? [{ op: "echo", label, count: 10 }] : [{ op: "await-channel", label, ms: 15000 }]),
      ],
    });
    expectOk(r);
    expect(r.trickled, ctx(r)).toBe(0);
    const own = lastDescription(r, "sent", dir === "peer offers" ? "offer" : "answer");
    expect((own.match(/^a=candidate:/gm) || []).length, ctx(r)).toBeGreaterThan(0);
  });
}

test("trickle: candidates sent as they are gathered (peer offers)", async () => {
  const r = await run(test.info().title, {
    config: { trickle: true },
    steps: [{ op: "dc", label: "t" }, { op: "offer" }, { op: "connected" }, { op: "echo", label: "t", count: 10 }],
  }, ["trickle"]);
  expectOk(r);
  expect(r.trickled, ctx(r)).toBeGreaterThan(0);
  checkEcho(r, "t", 10, 0, true);
});

// ---- ICE restart (RFC 8445 9, RFC 9429 4.1.10.1) ----

test("ICE restart by the peer keeps the data channel", async () => {
  const r = await run(test.info().title, {
    steps: [
      { op: "dc", label: "restart" },
      { op: "offer" },
      { op: "connected" },
      { op: "echo", label: "restart", count: 5 },
      { op: "offer", iceRestart: true },
      { op: "connected" },
      { op: "echo", label: "restart", count: 20, ms: 20000 },
    ],
  }, ["iceRestart"]);
  expectOk(r);
  const offers = (r.descriptions || []).filter((d) => d[0] === "sent" && d[1] === "offer").map((d) => ufragOf(d[2]));
  expect(offers.length, ctx(r)).toBe(2);
  expect(offers[0], ctx(r)).not.toBe(offers[1]);
  const answers = (r.descriptions || []).filter((d) => d[0] === "received" && d[1] === "answer").map((d) => ufragOf(d[2]));
  expect(answers[0], "Rust must answer a restart with new credentials (RFC 8445 9)").not.toBe(answers[1]);
  expect(r.datachannels?.restart?.got?.length, ctx(r)).toBe(25);
});

test("ICE restart by Rust keeps the data channel", async () => {
  const r = await run(test.info().title, {
    steps: [
      { op: "dc", label: "restart" },
      { op: "offer" },
      { op: "connected" },
      { op: "echo", label: "restart", count: 5 },
      { op: "request-offer", iceRestart: true },
      { op: "connected" },
      { op: "echo", label: "restart", count: 20, ms: 20000 },
    ],
  }, ["iceRestart"]);
  expectOk(r);
  const answer = lastDescription(r, "received", "answer");
  const offer = lastDescription(r, "received", "offer");
  expect(ufragOf(offer), ctx(r)).not.toBe(ufragOf(answer));
  const own = (r.descriptions || []).filter((d) => d[0] === "sent").map((d) => ufragOf(d[2]));
  expect(own[0], "the peer must answer Rust's restart with new credentials").not.toBe(own[own.length - 1]);
  expect(r.datachannels?.restart?.got?.length, ctx(r)).toBe(25);
});

// ---- relay-only through coturn (RFC 8656; RFC 6062 3.1 for TCP, RFC 8656 3.1 for TLS) ----

for (const [transport, url, cap] of [
  ["UDP", `turn:${TURN_HOST}:3478?transport=udp`, "turnUdp"],
  ["TCP", `turn:${TURN_HOST}:3478?transport=tcp`, "turnTcp"],
  ["TLS", `turns:${TURN_TLS}?transport=tcp`, "turnTls"],
]) {
  test(`relay only through coturn over ${transport} (peer offers)`, async () => {
    const r = await run(test.info().title, {
      config: { iceServers: [{ urls: [url], ...TURN_AUTH }], iceTransportPolicy: "relay" },
      steps: [{ op: "dc", label: "relay" }, { op: "offer" }, { op: "connected" }, { op: "echo", label: "relay", count: 30 }],
    }, [cap]);
    expectOk(r);
    expect(r.localCandidates.length, ctx(r)).toBeGreaterThan(0);
    expect(r.localCandidates.every((c) => / typ relay/.test(c)), JSON.stringify(r.localCandidates)).toBe(true);
    checkEcho(r, "relay", 30, 0, true);
    expect(r.selectedPair?.local?.candidateType, ctx(r)).toBe("relay");
    const rp = r.selectedPair?.local?.relayProtocol;
    if (rp) expect(rp.toLowerCase(), ctx(r)).toBe(transport.toLowerCase());
  });
}

// ---- ICE-TCP (RFC 6544) ----

test("ICE-TCP: the peer's active candidate reaches Rust's passive one", async () => {
  const r = await run(test.info().title, {
    scenario: { ice_tcp: true, udp: false },
    config: { tcp: true },
    steps: [{ op: "dc", label: "tcp" }, { op: "offer" }, { op: "connected" }, { op: "echo", label: "tcp", count: 30, size: 32768, ms: 20000 }],
  }, ["iceTcpActive"]);
  expectOk(r);
  checkEcho(r, "tcp", 30, 32768, true);
  expect((r.selectedPair?.local?.protocol || "").toLowerCase(), ctx(r)).toBe("tcp");
});

test("ICE-TCP: built into the engine with UDP blocked, the peer reaches an engine-gathered TCP candidate", async () => {
  const r = await run(test.info().title, {
    scenario: { engine_tcp: true, udp_blocked: true },
    config: { tcp: true },
    steps: [{ op: "dc", label: "engine-tcp" }, { op: "offer" }, { op: "connected" }, { op: "echo", label: "engine-tcp", count: 30, size: 32768, ms: 20000 }],
  }, ["iceTcp"]);
  expectOk(r);
  checkEcho(r, "engine-tcp", 30, 32768, true);
  expect((r.selectedPair?.local?.protocol || "").toLowerCase(), ctx(r)).toBe("tcp");
});

// ---- mDNS candidates (draft-ietf-mmusic-mdns-ice-candidates), on the private LAN ----

test("mDNS-hidden peer candidates resolve on the Rust side", async () => {
  const r = await run(test.info().title, {
    ws: MDNS_WS,
    ns: "lan-a",
    config: { mdns: true },
    steps: [{ op: "dc", label: "mdns" }, { op: "offer" }, { op: "connected" }, { op: "echo", label: "mdns", count: 20 }, { op: "wait", ms: 3000 }, { op: "report" }],
  }, ["mdns"]);
  expectOk(r);
  const hosts = r.localCandidates.filter((c) => / typ host/.test(c));
  expect(hosts.length, ctx(r)).toBeGreaterThan(0);
  expect(hosts.every((c) => /\.local /.test(c)), JSON.stringify(hosts)).toBe(true);
  checkEcho(r, "mdns", 20, 0, true);
  // As in mdns.spec.mjs: a `.local` pair succeeded, or one on the port of a succeeded pair to
  // the peer's own address (the name resolved to it).
  const pairs = r.rust?.stats?.candidatePairs || [];
  const working = pairs.filter((p) => p.remoteAddress === MDNS_PEER_IP && p.state === "succeeded").map((p) => p.remotePort);
  const resolved = pairs.some(
    (p) => p.remoteType === "host" && /\.local$/.test(p.remoteAddress || "") && (p.state === "succeeded" || working.includes(p.remotePort)),
  );
  expect(resolved, `Rust's candidate pairs: ${JSON.stringify(pairs)}`).toBe(true);
});

// ---- DTLS (RFC 9147 preferred, RFC 6347 fallback; RFC 5764 SRTP profile) ----

for (const dir of ["peer offers", "Rust offers"]) {
  test(`DTLS and SRTP: both sides agree on version, cipher suite and SRTP profile (${dir})`, async () => {
    const steps =
      dir === "peer offers"
        ? [{ op: "track", kind: "audio", codec: "opus" }, { op: "dc", label: "dtls" }, { op: "offer" }, { op: "connected" }]
        : [{ op: "track", kind: "audio", codec: "opus" }, { op: "request-offer", tracks: ["OPUS"] }, { op: "connected" }];
    const r = await run(test.info().title, {
      scenario: dir === "peer offers" ? { media: "reflect", audio: true } : {},
      steps: [...steps, { op: "await-rtp", kind: "audio", packets: 20, ms: 15000 }, { op: "report" }],
    });
    expectOk(r);
    logNegotiated(r);
    const t = (r.rust?.stats?.transports || []).find((x) => x.dtlsState === "connected");
    expect(t, ctx(r)).toBeTruthy();
    expect(["FEFD", "FEFC"], ctx(r)).toContain(t.tlsVersion);
    // The peer's view where its stack exposes it: the same version (the W3C tlsVersion form,
    // "FEFD" / "FEFC"), suite and SRTP profile.
    const norm = (s) => String(s || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
    const same = (a, b) => norm(a).includes(norm(b)) || norm(b).includes(norm(a));
    if (r.dtls?.version) expect(norm(r.dtls.version), ctx(r, { rust: t })).toBe(norm(t.tlsVersion));
    if (r.dtls?.cipher && t.dtlsCipher) expect(same(r.dtls.cipher, t.dtlsCipher), ctx(r, { rust: t })).toBe(true);
    if (r.dtls?.srtpProfile && t.srtpCipher) expect(same(r.dtls.srtpProfile, t.srtpCipher), ctx(r, { rust: t })).toBe(true);
  });
}

// DTLS 1.3 where the peer's stack has it, set to prefer it (with 1.2 fallback where the stack
// can): the engine offers both versions in one ClientHello and takes 1.3 from a ClientHello
// that offers it (RFC 9147 5.3, RFC 8446 4.2.1), whichever side is the client.
for (const dir of ["peer offers", "Rust offers"]) {
  test(`DTLS 1.3: a peer that prefers it negotiates DTLS 1.3 with Rust (${dir})`, async () => {
    const steps =
      dir === "peer offers"
        ? [{ op: "dc", label: "dtls13" }, { op: "offer" }, { op: "connected" }, { op: "echo", label: "dtls13", count: 10 }]
        : [{ op: "request-offer" }, { op: "connected" }, { op: "await-channel", label: "from-rust", ms: 15000 }];
    const r = await run(test.info().title, { config: { dtls13: true }, steps: [...steps, { op: "report" }] }, ["dtls13"]);
    expectOk(r);
    logNegotiated(r);
    const t = (r.rust?.stats?.transports || []).find((x) => x.dtlsState === "connected");
    expect(t?.tlsVersion, ctx(r, { rust: t })).toBe("FEFC");
    if (r.dtls?.version) expect(r.dtls.version.toUpperCase(), ctx(r, { rust: t })).toBe("FEFC");
  });
}

// ---- renegotiation adding and removing a track (RFC 9429 5.2.2, 5.3.1) ----

test("renegotiation: the peer adds a video track, then removes it, audio keeps flowing", async () => {
  const r = await run(test.info().title, {
    scenario: { media: "reflect", video: "VP8", audio: true },
    steps: [
      { op: "track", kind: "audio", codec: "opus" },
      { op: "offer" },
      { op: "connected" },
      { op: "await-rtp", kind: "audio", packets: 50, ms: 15000 },
      { op: "track", kind: "video", codec: "vp8" },
      { op: "offer" },
      { op: "await-rtp", kind: "video", packets: 50, ms: 20000 },
      { op: "remove-track", kind: "video" },
      { op: "offer" },
      { op: "await-rtp", kind: "audio", more: 50, ms: 15000 },
      { op: "report" },
    ],
  }, ["renegotiation"]);
  expectOk(r);
  const offers = (r.descriptions || []).filter((d) => d[0] === "sent" && d[1] === "offer").map((d) => mlines(d[2]));
  const answers = (r.descriptions || []).filter((d) => d[0] === "received" && d[1] === "answer").map((d) => mlines(d[2]));
  expect(offers.length, ctx(r)).toBe(3);
  expect(offers[1].map((m) => m.kind), ctx(r)).toEqual(["audio", "video"]);
  // An answer has the offer's m-lines, in order and of the same kinds (RFC 9429 5.3.1).
  answers.forEach((a, i) => expect(a.map((m) => m.kind), ctx(r)).toEqual(offers[i].map((m) => m.kind)));
  // After removeTrack the peer no longer sends video: its section is recvonly / inactive (or
  // rejected), and Rust's answer does not have Rust receive on it.
  const v = offers[2].find((m) => m.kind === "video");
  expect(["recvonly", "inactive"].includes(v.dir) || v.port === 0, ctx(r)).toBe(true);
  const va = answers[2].find((m) => m.kind === "video");
  expect(["sendonly", "inactive"].includes(va.dir) || va.port === 0, ctx(r)).toBe(true);
  expect(rustRtp(r, "video"), ctx(r)).toBeGreaterThan(0);
});

// ---- rollback and glare (RFC 9429 4.1.8.2, 5.7) ----

test("rollback: an abandoned local offer leaves the session usable", async () => {
  const r = await run(test.info().title, {
    steps: [
      { op: "dc", label: "first" },
      { op: "offer" },
      { op: "connected" },
      { op: "transceiver", kind: "audio", direction: "recvonly" },
      { op: "rollback" },
      { op: "offer" },
      { op: "echo", label: "first", count: 10 },
    ],
  }, ["rollback"]);
  expectOk(r);
  expect(r.steps.find((s) => s.op === "rollback")?.signalingState, ctx(r)).toBe("stable");
  expect(mlines(lastDescription(r, "received", "answer")).map((m) => m.kind), ctx(r)).toEqual(["application", "audio"]);
  checkEcho(r, "first", 10, 0, true);
});

test("glare: Rust rolls its offer back, answers, and offers again", async () => {
  const r = await run(test.info().title, {
    steps: [
      { op: "dc", label: "first" },
      { op: "offer" },
      { op: "connected" },
      { op: "transceiver", kind: "audio", direction: "recvonly" },
      { op: "glare", ms: 20000 },
      { op: "await-channel", label: "from-rust", ms: 20000 },
      { op: "report" },
    ],
  }, ["glare"]);
  expectOk(r);
  expect(r.ignoredOffers, "the peer (impolite) must have ignored Rust's colliding offer").toBeGreaterThan(0);
  expect(r.rust?.rollbacks || 0, "Rust (polite) must have rolled its offer back").toBeGreaterThan(0);
  expect(r.remoteOffers, ctx(r)).toBeGreaterThan(1);
  expect(r.remoteChannels?.["from-rust"], ctx(r)).toBe("hello-from-rust");
});

// ---- simulcast: Rust receives three RIDs (RFC 8853, RFC 8852) ----

test("simulcast: three RIDs from the peer reach Rust", async () => {
  const r = await run(test.info().title, {
    scenario: { media: "count" },
    steps: [
      { op: "track", kind: "video", codec: "vp8", simulcast: ["q", "h", "f"] },
      { op: "offer" },
      { op: "connected" },
      { op: "wait", ms: 8000 },
      { op: "report" },
    ],
  }, ["simulcastSend"]);
  expectOk(r);
  for (const rid of ["q", "h", "f"]) {
    const n = Object.entries(r.rust?.rtp || {}).filter(([k]) => k.startsWith(`video:${rid}:`)).reduce((a, [, c]) => a + c, 0);
    expect(n, `no packets on rid ${rid}: ${ctx(r, { peerOutbound: r.outbound, peerFirstHeaders: r.firstHeaders, rustDiscarded: r.rust?.discardedSsrcs, rustTransports: r.rust?.stats?.transports })}`).toBeGreaterThan(20);
  }
});

// The same three layers with no MID or RID extension on the wire, identified only by the SSRCs
// the offer declares for the section (`a=ssrc`, `a=ssrc-group:FID`): RFC 9143 9.2 associates
// a declared SSRC with its m= section. The engine receives each as a stream of the section
// without a rid (`conf/demux-1-declared-ssrc-in-rid-section`; it was an expected failure for
// Pion in train 10 round 4, when the engine discarded them).
test("simulcast without MID or RID on the wire: the layers' declared SSRCs reach Rust's section", async () => {
  const r = await run(test.info().title, {
    scenario: { media: "count" },
    steps: [
      { op: "track", kind: "video", codec: "vp8", simulcast: ["q", "h", "f"], ridExtensions: false },
      { op: "offer" },
      { op: "connected" },
      { op: "wait", ms: 8000 },
      { op: "report" },
    ],
  }, ["simulcastSend", "simulcastWithoutRid"]);
  expectOk(r);
  const declared = [...lastDescription(r, "sent", "offer").matchAll(/^a=ssrc-group:FID (\d+) \d+/gm)].map((m) => Number(m[1]));
  expect(declared.length, ctx(r)).toBe(3);
  expect(r.rust?.discardedSsrcs || [], `Rust discarded the declared layers: ${ctx(r, { peerFirstHeaders: r.firstHeaders })}`).toEqual([]);
  const inbound = (r.rust?.stats?.inbound || []).filter((i) => i.kind === "video").map((i) => i.ssrc);
  for (const ssrc of declared) expect(inbound, ctx(r)).toContain(ssrc);
});

// ---- several transports (RFC 9429 4.1.1, 5.2.1, 5.3.1; RFC 9143 7) ----

test("balanced: Rust's offer with a transport per media type, the peer bundles it", async () => {
  const r = await run(test.info().title, {
    steps: [
      { op: "track", kind: "audio", codec: "opus" },
      { op: "track", kind: "video", codec: "vp8" },
      { op: "request-offer", tracks: ["VP8", "OPUS"] },
      { op: "connected" },
      { op: "await-rtp", kind: "video", packets: 60, ms: 20000 },
      { op: "await-rtp", kind: "audio", packets: 50, ms: 15000 },
      { op: "await-rust-rtp", kind: "audio", packets: 50, ms: 15000 },
      { op: "report" },
    ],
  }, ["codec:vp8"]);
  expectOk(r);
  const offer = lastDescription(r, "received", "offer");
  // The engine's default: the transports share the session's one set of ICE credentials
  // (SettingEngineBuilder::with_unique_transport_credentials), as the browsers write them.
  expect(new Set([...offer.matchAll(/^a=ice-ufrag:(\S+)/gm)].map((m) => m[1])).size, ctx(r)).toBe(1);
  expect(rustRtp(r, "audio"), ctx(r)).toBeGreaterThanOrEqual(50);
});

test("balanced, answered without BUNDLE: a transport per media type", async () => {
  const r = await run(test.info().title, {
    steps: [
      { op: "request-offer", tracks: ["VP8", "OPUS"], munge: "strip-bundle" },
      { op: "connected" },
      { op: "await-rtp", kind: "video", packets: 60, ms: 20000 },
      { op: "await-rtp", kind: "audio", packets: 50, ms: 15000 },
      { op: "report" },
    ],
  }, ["unbundled", "answerUnbundled", "codec:vp8"]);
  expectOk(r);
  expect(/^a=group:BUNDLE/m.test(lastDescription(r, "sent", "answer")), ctx(r)).toBe(false);
  expect(r.rust?.transportsConnected, ctx(r)).toBe(2);
});

test("unbundled: the peer offers a transport per section, without a BUNDLE group", async () => {
  const r = await run(test.info().title, {
    scenario: { media: "reflect", video: "VP8" },
    config: { bundlePolicy: "max-compat" },
    steps: [
      { op: "track", kind: "video", codec: "vp8" },
      { op: "dc", label: "unbundled" },
      { op: "offer", munge: "strip-bundle" },
      { op: "connected" },
      { op: "echo", label: "unbundled", count: 1, size: 1024 },
      { op: "await-rtp", kind: "video", packets: 60, ms: 20000 },
      { op: "report" },
    ],
  }, ["unbundled", "codec:vp8"]);
  expectOk(r);
  const answer = lastDescription(r, "received", "answer");
  expect(/^a=group:BUNDLE/m.test(answer), "Rust answers an offer without a BUNDLE group without one").toBe(false);
  expect(r.rust?.transportsConnected, ctx(r)).toBe(2);
});

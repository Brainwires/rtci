// The browser's default host candidates: hidden behind an mDNS name (draft-ietf-mmusic-mdns-
// ice-candidates, a random UUID ".local"). Runs in the "-mdns" projects of
// playwright.config.mjs, which leave each browser's default in place (the other projects turn
// the hiding off). interop/run.sh runs these projects on the private mDNS LAN (the browser in
// lan-a, 10.99.0.50; a second interop-peer in lan-b, 10.99.0.51): the Rust side resolves the
// name over multicast there (interop-peer's mDNS socket, MulticastDnsMode::QueryOnly) and, as
// it should, believes an answer only from an on-link sender naming its own address, which a
// public (TEST-NET) WAN host is not.
import { test, expect } from "@playwright/test";
import { naBrowser, naEnv } from "./na.mjs";
import { WS, setupPage } from "./common.mjs";

// The browser host's address on the mDNS LAN (interop/run.sh).
const BROWSER_IP = process.env.RTC_INTEROP_BROWSER_IP || "10.99.0.50";

setupPage();

test("mDNS-hidden browser candidates resolve on the Rust side", async ({ page }) => {
  const r = await page.evaluate(async ([ws, ip]) => {
    const s = await Interop.open(ws, {});
    const dc = s.pc.createDataChannel("mdns");
    await s.negotiate();
    await Interop.until(() => s.localCandidates.length > 0 || s.pc.iceGatheringState === "complete", 10000, "a candidate")
      .catch(() => {});
    const hosts = s.localCandidates.filter((c) => / typ host/.test(c));
    if (!hosts.some((c) => /\.local /.test(c))) {
      s.close();
      return { notHidden: true, hosts };
    }
    await s.connected();
    const e = await Interop.echo(dc, 20);
    await e.wait(20, 15000);
    // The name resolves over multicast beside the connectivity checks (which can connect first
    // through a peer-reflexive candidate), so wait a while for the pair it makes.
    let report = await s.report();
    const deadline = Date.now() + 10000;
    while (!resolved(report.stats.candidatePairs) && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 250));
      report = await s.report();
    }
    s.close();
    return {
      hosts,
      echoed: e.got.length,
      remote: report.stats.remoteCandidates,
      pairs: report.stats.candidatePairs,
    };
    // See resolvedName below (the same rule, needed inside the page too).
    function resolved(pairs) {
      const working = pairs.filter((p) => p.remoteAddress === ip && p.state === "succeeded").map((p) => p.remotePort);
      return pairs.some(
        (p) => p.remoteType === "host" && /\.local$/.test(p.remoteAddress || "") &&
          (p.state === "succeeded" || working.includes(p.remotePort)),
      );
    }
  }, [WS, BROWSER_IP]);
  naBrowser(
    r.notHidden,
    "this browser's default host candidates carry its address, not an mDNS name",
    `its own icecandidate events with default settings: ${JSON.stringify(r.hosts)}`,
  );
  // WebKit's Linux ports publish their mDNS names through the Avahi daemon over the system
  // D-Bus; the test image runs neither, so nothing answers for WebKit's name. Its candidate is
  // still in Rust's report (an `RTCIceCandidateStats` exists for every submitted mDNS
  // candidate, draft-ietf-mmusic-mdns-ice-candidates section 3.3.1), but it has no pair: a
  // pair is made only once the name resolved.
  naEnv(
    test.info().project.name.startsWith("webkit") && !r.pairs.some((p) => /\.local$/.test(p.remoteAddress || "")),
    "the test image runs no Avahi daemon, which WebKitGTK / WPE register their mDNS candidate names with",
    "WebKit Source/WebKit/NetworkProcess/glib/NetworkMDNSRegisterGLib.cpp (org.freedesktop.Avahi " +
      "EntryGroup.AddAddress on the system bus); the image (mcr.microsoft.com/playwright, " +
      "scripts/test-env/Dockerfile) installs no avahi-daemon or system dbus",
  );
  expect(r.echoed).toBe(20);
  // The name resolved. The agent pairs a `.local` candidate only once its name resolved (its stats
  // address stays the name; the resolved address is not exposed), so a pair on it proves the
  // answer was believed. It is checked only if ICE has not completed yet: the browser's checks
  // usually connect first through the peer-reflexive candidate they teach Rust (BROWSER_IP,
  // lan-a), the controlling browser nominates that pair, and once ICE processing has completed the
  // pairs formed after it are not checked (RFC 8445 §8.1.2). So either the `.local` pair succeeded, or it is on the very
  // port of a succeeded pair to BROWSER_IP: the name resolved to the browser's address.
  expect(
    resolvedName(r.pairs),
    `Rust's candidate pairs: ${JSON.stringify(r.pairs)}; remote candidates: ${JSON.stringify(r.remote)} ` +
      `(browser ${BROWSER_IP})`,
  ).toBe(true);
});

// A `.local` host pair that succeeded, or that shares its port with a succeeded pair to the
// browser's own address (the peer-reflexive one the browser's checks made).
function resolvedName(pairs) {
  const working = pairs
    .filter((p) => p.remoteAddress === BROWSER_IP && p.state === "succeeded")
    .map((p) => p.remotePort);
  return pairs.some(
    (p) => p.remoteType === "host" && /\.local$/.test(p.remoteAddress || "") &&
      (p.state === "succeeded" || working.includes(p.remotePort)),
  );
}

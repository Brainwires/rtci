// The browser's default host candidates: hidden behind an mDNS name (draft-ietf-mmusic-mdns-
// ice-candidates, a random UUID ".local"). Runs in the "-mdns" projects of
// playwright.config.mjs, which leave each browser's default in place (the other projects turn
// the hiding off). interop/run.sh runs these projects on the private mDNS LAN (the browser in
// lan-a, 10.99.0.50; a second interop-peer in lan-b, 10.99.0.51): the Rust side resolves the
// name over multicast there (interop-peer's mDNS socket, MulticastDnsMode::QueryOnly) and, as
// it should, believes an answer only from an on-link sender naming its own address, which a
// public (TEST-NET) WAN host is not.
import { test, expect } from "@playwright/test";
import { naBrowser } from "./na.mjs";
import { WS, setupPage } from "./common.mjs";

// The browser host's address on the mDNS LAN (interop/run.sh).
const BROWSER_IP = process.env.RTC_INTEROP_BROWSER_IP || "10.99.0.50";

setupPage();

test("mDNS-hidden browser candidates resolve on the Rust side", async ({ page }) => {
  const r = await page.evaluate(async (ws) => {
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
    while (!report.stats.candidatePairs.some(resolvedPair) && Date.now() < deadline) {
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
    // A pair whose remote is one of the browser's `.local` host candidates: the agent pairs one
    // only after its name resolved (its stats address stays the name; the resolved address is
    // not exposed).
    function resolvedPair(p) {
      return p.remoteType === "host" && /\.local$/.test(p.remoteAddress || "") && p.state === "succeeded";
    }
  }, WS);
  naBrowser(
    r.notHidden,
    "this browser's default host candidates carry its address, not an mDNS name",
    `its own icecandidate events with default settings: ${JSON.stringify(r.hosts)}`,
  );
  expect(r.echoed).toBe(20);
  // The name resolved: a connectivity check succeeded on a pair whose remote is the browser's
  // `.local` host candidate, not only on the peer-reflexive one (BROWSER_IP, lan-a) the checks
  // teach Rust anyway.
  expect(
    r.pairs.some(
      (p) => p.remoteType === "host" && /\.local$/.test(p.remoteAddress || "") && p.state === "succeeded",
    ),
    `Rust's candidate pairs: ${JSON.stringify(r.pairs)}; remote candidates: ${JSON.stringify(r.remote)} ` +
      `(browser ${BROWSER_IP})`,
  ).toBe(true);
});

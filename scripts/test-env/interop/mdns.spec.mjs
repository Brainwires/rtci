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
    const report = await s.report();
    s.close();
    return { hosts, echoed: e.got.length, remote: report.stats.remoteCandidates };
  }, WS);
  naBrowser(
    r.notHidden,
    "this browser's default host candidates carry its address, not an mDNS name",
    `its own icecandidate events with default settings: ${JSON.stringify(r.hosts)}`,
  );
  expect(r.echoed).toBe(20);
  // The name resolved: Rust holds a host candidate with the browser's address (lan-a), not only
  // the peer-reflexive one its checks would teach it anyway.
  expect(
    r.remote.some((c) => c.type === "host" && c.address === BROWSER_IP),
    `Rust's remote candidates: ${JSON.stringify(r.remote)}`,
  ).toBe(true);
});

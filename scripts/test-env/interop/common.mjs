// Shared by the spec files: the page every test runs in, the signalling address, the media
// fixtures, and per-session netem (a tc filter that sends one session's packets through the
// lossy band interop/run.sh sets up on open-a's eth0).
import { test } from "@playwright/test";
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

export function setupPage() {
  recordDescriptions();
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

// Packets the netem band has dropped so far (shared by every impaired test running).
export function netemDrops() {
  const out = execFileSync("tc", ["-s", "qdisc", "show", "dev", "eth0"]).toString();
  const m = out.match(/qdisc netem 40:[\s\S]*?dropped (\d+)/);
  return m ? Number(m[1]) : 0;
}

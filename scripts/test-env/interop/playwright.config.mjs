// Headless Chromium, Firefox and WebKit as the remote peer of examples/interop-peer.
// Host candidates are not hidden behind mDNS names, so the ICE pair is host/host on the
// environment's WAN (the Rust side learns peer-reflexive candidates either way).
import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: ".",
  testMatch: /.*\.spec\.mjs/,
  timeout: 60_000,
  workers: 3,
  fullyParallel: false,
  retries: 0,
  reporter: [["list"], ["json", { outputFile: process.env.RTC_INTEROP_JSON || "results.json" }]],
  use: { headless: true },
  projects: [
    {
      name: "chromium",
      use: {
        browserName: "chromium",
        launchOptions: {
          args: [
            "--disable-features=WebRtcHideLocalIpsWithMdns",
            "--autoplay-policy=no-user-gesture-required",
            "--use-fake-ui-for-media-stream",
          ],
        },
      },
    },
    {
      name: "firefox",
      use: {
        browserName: "firefox",
        launchOptions: {
          firefoxUserPrefs: {
            "media.peerconnection.ice.obfuscate_host_addresses": false,
            "media.autoplay.default": 0,
            "media.autoplay.block-webaudio": false,
            "media.navigator.permission.disabled": true,
          },
        },
      },
    },
    { name: "webkit", use: { browserName: "webkit" } },
  ],
});

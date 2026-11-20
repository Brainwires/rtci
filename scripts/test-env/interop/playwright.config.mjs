// Headless Chromium, Firefox and WebKit as the remote peer of examples/interop-peer.
// In the main projects host candidates are not hidden behind mDNS names, so the ICE pair is
// host/host on the environment's WAN (the Rust side learns peer-reflexive candidates either
// way). The "-mdns" projects keep each browser's default (hidden) and run only mdns.spec.mjs.
import { defineConfig } from "@playwright/test";

// Firefox's media decoder log (PlatformDecoderModule / MediaDataDecoder: why a decoder refuses
// a frame) and libwebrtc's warnings (webrtc_trace: the receiver's frame reference finder drops a
// frame it cannot place, e.g. a VP9 key frame without a usable scalability structure, with a
// warning), one file per process, beside the other artifacts.
const ARTIFACTS = process.env.RTC_TESTENV_ARTIFACTS_DIR || "/artifacts";
const FIREFOX_ENV = {
  ...process.env,
  MOZ_LOG: process.env.RTC_INTEROP_MOZ_LOG || "PlatformDecoderModule:5,MediaDataDecoder:5,webrtc_trace:3",
  MOZ_LOG_FILE: `${ARTIFACTS}/firefox-moz.log`,
};

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
      testIgnore: /mdns\.spec\.mjs/,
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
      testIgnore: /mdns\.spec\.mjs/,
      use: {
        browserName: "firefox",
        launchOptions: {
          env: FIREFOX_ENV,
          firefoxUserPrefs: {
            "media.peerconnection.ice.obfuscate_host_addresses": false,
            "media.autoplay.default": 0,
            "media.autoplay.block-webaudio": false,
            "media.navigator.permission.disabled": true,
          },
        },
      },
    },
    { name: "webkit", testIgnore: /mdns\.spec\.mjs/, use: { browserName: "webkit" } },
    {
      name: "chromium-mdns",
      testMatch: /mdns\.spec\.mjs/,
      use: {
        browserName: "chromium",
        launchOptions: {
          // The page (http://localhost, served by a Playwright route) reaches the peer on the
          // private mDNS LAN (10.99.0.51); Chromium's Local Network Access checks block that
          // WebSocket (net::ERR_BLOCKED_BY_LOCAL_NETWORK_ACCESS_CHECKS) behind a permission a
          // headless run never grants. mDNS hiding (WebRtcHideLocalIpsWithMdns) stays on.
          args: [
            "--autoplay-policy=no-user-gesture-required",
            "--disable-features=LocalNetworkAccessChecks,BlockInsecurePrivateNetworkRequests,PrivateNetworkAccessSendPreflights,PrivateNetworkAccessRespectPreflightResults",
          ],
        },
      },
    },
    { name: "firefox-mdns", testMatch: /mdns\.spec\.mjs/, use: { browserName: "firefox" } },
    { name: "webkit-mdns", testMatch: /mdns\.spec\.mjs/, use: { browserName: "webkit" } },
  ],
});

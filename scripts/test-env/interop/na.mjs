// The two kinds of "not applicable" a browser interop cell may be (plans: C3). Every skip in
// the specs goes through these, so the reason and its citation are in the test itself and the
// gate (gate.mjs) can tell a cited n/a from a skip that hides a failure.
//
//   na-browser: the browser lacks the feature. The citation is the browser's own capability
//               API read at run time (RTCRtpSender.getCapabilities, a missing constructor, its
//               own offer) or a release note.
//   na-env:     the headless build in the test image lacks it, though the browser has it. The
//               citation says what the image is missing and where that is documented.
//
// The skip description is "na-<kind>: <reason> [<citation>]"; matrix.mjs parses it back.
import { test } from "@playwright/test";

export { NA_PATTERN } from "./na-pattern.mjs";

function skip(kind, condition, reason, cite) {
  if (!reason || !cite) throw new Error(`na-${kind} needs a reason and a citation`);
  test.skip(!!condition, `na-${kind}: ${reason} [${cite}]`);
}

export const naBrowser = (condition, reason, cite) => skip("browser", condition, reason, cite);
export const naEnv = (condition, reason, cite) => skip("env", condition, reason, cite);

// Codecs the browser has but the headless build in the image does not, by project name. Each
// entry is checked against the capability API at run time too: it only applies when the codec
// is really missing.
const ENV_CODEC_GAPS = {
  firefox: {
    "video/h264":
      "Firefox does H.264 through Cisco's OpenH264 plugin, which it downloads after install; " +
      "Playwright's Firefox in the offline test image never fetches it " +
      "(https://support.mozilla.org/kb/openh264-plugin-firefox, " +
      "https://wiki.mozilla.org/GeckoMediaPlugins)",
  },
};

// Skips unless the browser can send (dir "sender") or receive ("receiver") `mime`, by its own
// RTCRtpSender / RTCRtpReceiver.getCapabilities(kind).
export async function skipUnlessCodec(page, kind, mime, dir) {
  const ok = await page.evaluate(([k, m, d]) => Interop.hasCodec(k, m, d), [kind, mime, dir]);
  if (ok) return;
  const project = test.info().project.name.replace(/-.*$/, "");
  const what = `no ${mime} ${dir === "receiver" ? "decoder" : "encoder"}`;
  const envGap = ENV_CODEC_GAPS[project]?.[mime.toLowerCase()];
  if (envGap) naEnv(true, `the test image's ${project} has ${what}`, envGap);
  naBrowser(
    true,
    `this browser has ${what}`,
    `RTCRtp${dir === "receiver" ? "Receiver" : "Sender"}.getCapabilities("${kind}") lists no ${mime}`,
  );
}

// The C3 gate: reads interop-summary.json (matrix.mjs writes it) and exits non-zero unless
// every cell of the matrix is a pass or a cited n/a, and every browser and peer ran.
//
//   node gate.mjs /artifacts/interop-summary.json
//
// RTC_INTEROP_BROWSERS (default "chromium,firefox,webkit") and RTC_INTEROP_PEERS (default
// none; interop/run.sh names every peer under scripts/test-env/peers/) name the projects that
// must each have run at least one test. A cell fails the gate when it failed, timed out, is missing (the
// browser ran the spec file but not that test), or was skipped without a "na-browser:" /
// "na-env:" reason and citation (na.mjs).
import { readFileSync } from "node:fs";

const summary = JSON.parse(readFileSync(process.argv[2], "utf8"));
const browsers = [
  ...(process.env.RTC_INTEROP_BROWSERS || "chromium,firefox,webkit").split(","),
  ...(process.env.RTC_INTEROP_PEERS || "").split(","),
].filter(Boolean);
const problems = [];
const cells = summary.cells || [];
if (cells.length === 0) problems.push("the summary has no cells: the matrix did not run");
for (const b of browsers) {
  if (!cells.some((c) => c.browser === b)) problems.push(`${b}: ran no test`);
}
// xfail: a known gap, an expected failure with its cited verdict (matrix.mjs).
const ok = new Set(["pass", "na-browser", "na-env", "na-peer", "xfail"]);
for (const c of cells) {
  if (!ok.has(c.status)) problems.push(`${c.test} [${c.browser}]: ${c.status}${c.detail ? ` (${c.detail})` : ""}`);
}
const count = (s) => cells.filter((c) => c.status === s).length;
console.log(
  `interop gate: ${count("pass")} pass, ${count("na-browser")} na-browser, ${count("na-peer")} na-peer, ` +
    `${count("na-env")} na-env (not tested), ${count("xfail")} known gaps, ` +
    `${cells.length - count("pass") - count("na-browser") - count("na-peer") - count("na-env") - count("xfail")} failing`,
);
for (const c of cells.filter((c) => c.status === "xfail")) {
  console.log(`  known gap: ${c.test} [${c.browser}]: ${c.reason} [${c.cite}]`);
}
for (const c of cells.filter((c) => c.status === "na-env")) {
  console.log(`  not tested: ${c.test} [${c.browser}]: ${c.reason} [${c.cite}]`);
}
if (problems.length) {
  console.log("interop gate FAILED:");
  for (const p of problems) console.log(`  ${p}`);
  process.exit(1);
}
console.log("interop gate passed");

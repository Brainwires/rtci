// Turns Playwright's JSON report into the interop matrix: Markdown on stdout (one row per test,
// one column per browser or peer; an n/a shows its kind and reason, a failure the first line of its
// error) and, when a second path is given, interop-summary.json for gate.mjs:
//
//   node matrix.mjs results.json [interop-summary.json]
//
// Summary cells: { test, file, browser, status, reason?, cite?, detail? } with status "pass",
// "fail", "na-browser", "na-env", "na-peer", "na-uncited" (skipped without a cited na.mjs reason) or
// "missing" (the browser ran tests from that file but not this one).
import { readFileSync, writeFileSync } from "node:fs";
import { NA_PATTERN } from "./na-pattern.mjs";

const report = JSON.parse(readFileSync(process.argv[2], "utf8"));
const cells = [];
const walk = (suite, file) => {
  for (const spec of suite.specs || []) {
    for (const t of spec.tests || []) {
      const res = t.results[t.results.length - 1] || {};
      const cell = { test: spec.title, file: spec.file || file, browser: t.projectName };
      if (t.status === "skipped" || res.status === "skipped") {
        const notes = [...(t.annotations || []), ...(res.annotations || [])];
        const why = notes.find((a) => a.type === "skip")?.description || "";
        const m = why.match(NA_PATTERN);
        if (m) Object.assign(cell, { status: `na-${m[1]}`, reason: m[2], cite: m[3] });
        else Object.assign(cell, { status: "na-uncited", detail: why || "skipped without a reason" });
      } else if (res.status === "passed" && (t.status === "expected" || t.status === undefined)) {
        cell.status = "pass";
      } else {
        const first = (res.error?.message || res.status || t.status || "").split("\n")[0];
        Object.assign(cell, { status: "fail", detail: first.slice(0, 300) });
      }
      cells.push(cell);
    }
  }
  for (const s of suite.suites || []) walk(s, s.file || file);
};
for (const s of report.suites || []) walk(s, s.file || s.title);

// A browser that ran a file but has no cell for one of its tests: missing.
const browsersByFile = new Map();
const testsByFile = new Map();
for (const c of cells) {
  if (!browsersByFile.has(c.file)) browsersByFile.set(c.file, new Set());
  if (!testsByFile.has(c.file)) testsByFile.set(c.file, new Set());
  browsersByFile.get(c.file).add(c.browser);
  testsByFile.get(c.file).add(c.test);
}
for (const [file, tests] of testsByFile) {
  for (const test of tests) {
    for (const browser of browsersByFile.get(file)) {
      if (!cells.some((c) => c.file === file && c.test === test && c.browser === browser)) {
        cells.push({ test, file, browser, status: "missing" });
      }
    }
  }
}

if (process.argv[3]) {
  const counts = {};
  for (const c of cells) counts[c.status] = (counts[c.status] || 0) + 1;
  writeFileSync(process.argv[3], JSON.stringify({ counts, cells }, null, 2));
}

// One table per set of columns: the browser specs' rows have a column per browser, the peer
// cells (peers.spec.mjs) a column per peer.
const text = (c) =>
  (c.status === "pass"
    ? "pass"
    : c.status.startsWith("na-") && c.status !== "na-uncited"
      ? `${c.status} (${c.reason})`
      : `${c.status.toUpperCase()}: ${c.detail || ""}`
  ).replace(/\|/g, "/").replace(/\n/g, " ").slice(0, 160);
const groups = new Map();
for (const c of cells) {
  const g = /peers\.spec\.mjs$/.test(c.file || "") ? "peers" : "browsers";
  if (!groups.has(g)) groups.set(g, []);
  groups.get(g).push(c);
}
for (const [g, group] of groups) {
  const cols = [...new Set(group.map((c) => c.browser))];
  const rows = new Map();
  for (const c of group) {
    if (!rows.has(c.test)) rows.set(c.test, {});
    rows.get(c.test)[c.browser] = text(c);
  }
  if (groups.size > 1) console.log(`\n### ${g === "peers" ? "Peers" : "Browsers"}\n`);
  console.log(`| test | ${cols.join(" | ")} |`);
  console.log(`|---|${cols.map(() => "---").join("|")}|`);
  for (const [title, r] of rows) console.log(`| ${title} | ${cols.map((c) => r[c] || "-").join(" | ")} |`);
}
const n = (pred) => cells.filter(pred).length;
const cited = ["pass", "na-browser", "na-env", "na-peer"];
console.log(
  `\n${n((c) => c.status === "pass")} pass, ${n((c) => !cited.includes(c.status))} fail, ` +
    `${n((c) => c.status === "na-browser")} not applicable (browser), ${n((c) => c.status === "na-peer")} not applicable (peer), ` +
    `${n((c) => c.status === "na-env")} not tested (environment)`,
);

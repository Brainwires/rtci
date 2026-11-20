// Turns Playwright's JSON report into the interop matrix: Markdown on stdout (one row per test,
// one column per browser; an n/a shows its kind and reason, a failure the first line of its
// error) and, when a second path is given, interop-summary.json for gate.mjs:
//
//   node matrix.mjs results.json [interop-summary.json]
//
// Summary cells: { test, file, browser, status, reason?, cite?, detail? } with status "pass",
// "fail", "na-browser", "na-env", "na-uncited" (skipped without a cited na.mjs reason) or
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

const cols = [...new Set(cells.map((c) => c.browser))];
const rows = new Map();
for (const c of cells) {
  if (!rows.has(c.test)) rows.set(c.test, {});
  const text =
    c.status === "pass"
      ? "pass"
      : c.status.startsWith("na-") && c.status !== "na-uncited"
        ? `${c.status} (${c.reason})`
        : `${c.status.toUpperCase()}: ${c.detail || ""}`;
  rows.get(c.test)[c.browser] = text.replace(/\|/g, "/").replace(/\n/g, " ").slice(0, 160);
}
console.log(`| test | ${cols.join(" | ")} |`);
console.log(`|---|${cols.map(() => "---").join("|")}|`);
for (const [title, r] of rows) console.log(`| ${title} | ${cols.map((c) => r[c] || "-").join(" | ")} |`);
const n = (pred) => cells.filter(pred).length;
console.log(
  `\n${n((c) => c.status === "pass")} pass, ${n((c) => !["pass", "na-browser", "na-env"].includes(c.status))} fail, ` +
    `${n((c) => c.status === "na-browser")} not applicable (browser), ${n((c) => c.status === "na-env")} not tested (environment)`,
);

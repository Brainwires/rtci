// Turns Playwright's JSON report into a Markdown matrix: one row per test, one column per
// browser; a skip shows its reason, a failure the first line of its error.
import { readFileSync } from "node:fs";

const report = JSON.parse(readFileSync(process.argv[2], "utf8"));
const rows = new Map();
const projects = new Set();
const walk = (suite) => {
  for (const spec of suite.specs || []) {
    for (const t of spec.tests || []) {
      projects.add(t.projectName);
      const res = t.results[t.results.length - 1] || {};
      let cell;
      if (t.status === "skipped" || res.status === "skipped") {
        const why = (t.annotations || []).find((a) => a.type === "skip")?.description || "skipped";
        cell = `n/a (${why})`;
      } else if (res.status === "passed") cell = "pass";
      else cell = `FAIL: ${(res.error?.message || res.status || "").split("\n")[0].replace(/\|/g, "/").slice(0, 120)}`;
      if (!rows.has(spec.title)) rows.set(spec.title, {});
      rows.get(spec.title)[t.projectName] = cell;
    }
  }
  for (const s of suite.suites || []) walk(s);
};
for (const s of report.suites || []) walk(s);
const cols = [...projects];
console.log(`| test | ${cols.join(" | ")} |`);
console.log(`|---|${cols.map(() => "---").join("|")}|`);
for (const [title, cells] of rows) console.log(`| ${title} | ${cols.map((c) => cells[c] || "-").join(" | ")} |`);
const all = [...rows.values()].flatMap((r) => Object.values(r));
console.log(`\n${all.filter((c) => c === "pass").length} pass, ${all.filter((c) => c.startsWith("FAIL")).length} fail, ${all.filter((c) => c.startsWith("n/a")).length} not applicable`);

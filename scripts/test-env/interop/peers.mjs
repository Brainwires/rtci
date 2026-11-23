// The non-browser peers of the interop matrix (scripts/test-env/peers/<name>/): which exist,
// how to start one, and the control channel a cell uses while it runs. A peer is a program
// that speaks the browser page's WebSocket signalling with examples/interop-peer and runs one
// plan (a list of steps) per invocation; scripts/test-env/peers/README.md is its contract.
//
//   const r = await runPeer("pion", plan)  // -> the peer's result object
//
// The peer reads the plan from the file named by its first argument, writes its log to
// stderr, and writes JSON lines to stdout: `{"event": ...}` lines ask the runner for
// something mid-run (netem on a path, see `impair`) and get one line back on stdin; the last
// line is `{"result": {...}}`.
import { spawn, execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

// The peers' sources, beside interop/ in the checkout (run.sh copies the specs to the image's
// runner directory, so the path comes from the environment there).
export const PEERS_DIR =
  process.env.RTC_INTEROP_PEERS_DIR || fileURLToPath(new URL("../peers/", import.meta.url));
// Where run.sh put each built peer: <dir>/<name>-peer.
export const PEER_BIN = process.env.RTC_INTEROP_PEER_BIN || "/run/rtc-env/peers";
const ARTIFACTS = process.env.RTC_TESTENV_ARTIFACTS_DIR || "/artifacts";

// Every peer with a peer.json: { name, version, licence, upstream, lacks: { capability:
// { reason, cite } } }.
export function peerList() {
  if (!existsSync(PEERS_DIR)) return [];
  return readdirSync(PEERS_DIR, { withFileTypes: true })
    .filter((d) => d.isDirectory() && existsSync(join(PEERS_DIR, d.name, "peer.json")))
    .map((d) => JSON.parse(readFileSync(join(PEERS_DIR, d.name, "peer.json"), "utf8")))
    .sort((a, b) => a.name.localeCompare(b.name));
}

export function peerInfo(name) {
  const p = peerList().find((x) => x.name === name);
  if (!p) throw new Error(`no peer ${name} under ${PEERS_DIR}`);
  return p;
}

const slug = (s) => s.replace(/[^A-Za-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 120);

// tc on one namespace's eth0: the lossy band (1:4) interop/run.sh adds on open-a and open-b.
function tc(ns, ...args) {
  const cmd = ns ? ["netns", "exec", ns, "tc", ...args] : null;
  return cmd
    ? execFileSync("ip", cmd, { stdio: ["ignore", "pipe", "pipe"] }).toString()
    : execFileSync("tc", args, { stdio: ["ignore", "pipe", "pipe"] }).toString();
}

function netemDropped(ns) {
  const out = tc(ns, "-s", "qdisc", "show", "dev", "eth0");
  const m = out.match(/qdisc netem 40:[\s\S]*?dropped (\d+)/);
  return m ? Number(m[1]) : 0;
}

// What an "impair" event asks for: the packets of one session on one path go through netem.
//   to-rust: the peer's packets to Rust's UDP port, on the peer's side (open-a egress);
//   to-peer: Rust's packets from that port, on Rust's side (open-b egress).
// The filter priority is unique per running cell (`slot`), so parallel cells keep their own.
function impair(ev, slot) {
  const port = Number(ev.rustPort);
  if (!port) throw new Error(`impair without the Rust side's port: ${JSON.stringify(ev)}`);
  const [ns, field] = ev.direction === "to-peer" ? ["open-b", "sport"] : [null, "dport"];
  const prio = String(200 + slot);
  const before = netemDropped(ns);
  tc(ns, "filter", "add", "dev", "eth0", "parent", "1:", "protocol", "ip", "prio", prio, "u32",
    "match", "ip", "protocol", "17", "0xff", "match", "ip", field, String(port), "0xffff", "flowid", "1:4");
  return () => {
    try {
      tc(ns, "filter", "del", "dev", "eth0", "parent", "1:", "prio", prio);
    } catch {}
    return netemDropped(ns) - before;
  };
}

// Runs `plan` with peer `name` (`slot`: the Playwright worker's parallelIndex, which keeps
// each running cell's tc filter apart); resolves to its result (with `log`, the path of its stderr,
// and `netemDrops`, what netem dropped while the cell asked for loss). A peer that exits
// without a result, or outlives `plan.timeout_ms` plus a grace, rejects with its log's tail.
export function runPeer(name, plan, title, slot = 0) {
  const bin = join(PEER_BIN, `${name}-peer`);
  if (!existsSync(bin)) return Promise.reject(new Error(`peer ${name} was not built (${bin} is missing)`));
  const dir = join(ARTIFACTS, "peers", name);
  mkdirSync(dir, { recursive: true });
  const base = join(dir, slug(title || "cell"));
  writeFileSync(`${base}.plan.json`, JSON.stringify(plan, null, 2));
  const args = [`${base}.plan.json`];
  const child = plan.ns
    ? spawn("ip", ["netns", "exec", plan.ns, bin, ...args], { stdio: ["pipe", "pipe", "pipe"] })
    : spawn(bin, args, { stdio: ["pipe", "pipe", "pipe"] });
  const log = [];
  child.stderr.on("data", (d) => log.push(d));
  let result = null;
  let drops = 0;
  let restore = null;
  let buf = "";
  const reply = (v) => {
    try {
      child.stdin.write(`${JSON.stringify(v)}\n`);
    } catch {}
  };
  child.stdout.on("data", (d) => {
    buf += d.toString();
    let i;
    while ((i = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, i).trim();
      buf = buf.slice(i + 1);
      if (!line) continue;
      let m;
      try {
        m = JSON.parse(line);
      } catch {
        log.push(Buffer.from(`[stdout] ${line}\n`));
        continue;
      }
      if (m.result) result = m.result;
      else if (m.event === "impair") {
        try {
          restore = impair(m, slot);
          reply({ ok: true });
        } catch (e) {
          reply({ ok: false, error: String(e) });
        }
      } else if (m.event === "unimpair") {
        if (restore) drops += restore();
        restore = null;
        reply({ ok: true, dropped: drops });
      } else reply({ ok: false, error: `unknown event ${m.event}` });
    }
  });
  const limit = (plan.timeout_ms || 60000) + 15000;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => child.kill("SIGKILL"), limit);
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      if (restore) drops += restore();
      const text = Buffer.concat(log).toString();
      writeFileSync(`${base}.log`, text);
      if (result) writeFileSync(`${base}.result.json`, JSON.stringify(result, null, 2));
      if (!result) {
        const tail = text.split("\n").slice(-25).join("\n");
        reject(new Error(`peer ${name} exited (${signal || code}) without a result; log tail:\n${tail}`));
        return;
      }
      resolve({ ...result, log: `${base}.log`, netemDrops: drops });
    });
  });
}

// ancestry.js — every exec on the system, with its full parent chain.
// Demos the new in-memory process tree maintained by the ES extension:
//   getProc(pid)         → {pid, ppid, name, exe, started_at_ms}
//   getAncestry(pid)     → [{...}, {...}, ...]  walking up to launchd
//   getAncestryNames(pid)→ ["zsh", "ssh", "sshd", "launchd"]
//
// Both are synchronous in-memory walks — safe to call from any probe.
//
// Run:
//   sudo tractor program examples/ancestry.js                  # everything
//   sudo tractor program examples/ancestry.js --watch curl     # alert on curl ancestors
//
// Flags:
//   --watch NAME    highlight execs whose ancestry includes NAME
//   --rows N        max rows shown (default: terminal height - 4)

function parseArgs(av) {
  const o = { watch: null, rows: null };
  let i = 0;
  while (i < av.length) {
    const a = av[i];
    if (a === "--watch" && i + 1 < av.length)     o.watch = av[++i];
    else if (a === "--rows" && i + 1 < av.length) o.rows = parseInt(av[++i], 10);
    i++;
  }
  return o;
}
const OPTS = parseArgs(args);

const recent = [];                  // ring of {ts, pid, chain}
let watchHits = 0;

probe("es:notify:exec", c => {
  const chain = getAncestryNames(c.pid);
  const hit = OPTS.watch && chain.includes(OPTS.watch);
  // --watch FILTERS — only matching execs land in the ring.
  if (OPTS.watch && !hit) return;
  if (hit) watchHits++;
  recent.push({ ts: Date.now(), pid: c.pid, chain, hit });
  if (recent.length > 5000) recent.splice(0, recent.length - 5000);
});

function pad(s, w, right) {
  s = String(s);
  if (s.length >= w) return s.slice(0, w);
  return right ? s.padStart(w) : s.padEnd(w);
}
function fmtTs(ms) {
  const d = new Date(ms);
  return `${String(d.getHours()).padStart(2, "0")}:`
       + `${String(d.getMinutes()).padStart(2, "0")}:`
       + `${String(d.getSeconds()).padStart(2, "0")}.`
       + `${String(d.getMilliseconds()).padStart(3, "0")}`;
}

const BOLD_ON  = "\x1b[1m";
const BOLD_OFF = "\x1b[22m";

probe("timer:250ms", () => {
  const cols = terminalCols();
  const rows = OPTS.rows || Math.max(10, terminalRows() - 4);
  const lines = [];
  const tag = OPTS.watch ? `   --watch ${OPTS.watch}   hits ${watchHits}` : "";
  lines.push(`ancestry   tree=${_processTreeSize()}   shown=${recent.length}${tag}`);
  lines.push(pad("TIME", 12) + " " + pad("PID", 6, true) + " ANCESTRY (current ← parent ← …)");
  lines.push("─".repeat(Math.min(cols, 60)));
  const slice = recent.slice(-rows);
  for (const e of slice) {
    const chainStr = e.chain.join(" ← ");
    const head = pad(fmtTs(e.ts), 12) + " " + pad(e.pid, 6, true) + " ";
    const room = Math.max(1, cols - head.length);
    let body = chainStr.length > room ? chainStr.slice(0, room - 1) + "…" : chainStr;
    if (e.hit) body = BOLD_ON + body + BOLD_OFF;
    lines.push(head + body);
  }
  render("ancestry", lines.join("\n"));
});

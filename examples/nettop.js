// nettop.js — per-process network throughput. Like `nettop` / Activity
// Monitor → Network, but composable in 100 lines of JS.
//
// Aggregates ne:flow:bytes deltas by pid, renders a top-N table every
// second with per-second rate + session totals + open flow count.
//
// Run:  sudo tractor program examples/nettop.js [topN]
//   topN defaults to 15.

const N = parseInt(args[0] || "15", 10);

const procs = new Map();       // pid → { name }
const flows = new Map();       // flowID → { pid, host, port, lastOut, lastIn }
const tally = new Map();       // pid → { winOut, winIn, sesOut, sesIn, flowCount }

function getPid(pid) {
  let t = tally.get(pid);
  if (!t) { t = { winOut: 0, winIn: 0, sesOut: 0, sesIn: 0, flowCount: 0 };
            tally.set(pid, t); }
  return t;
}

function bestName(p) {
  if (p && p.process) {
    const i = p.process.lastIndexOf("/");
    return i >= 0 ? p.process.slice(i + 1) : p.process;
  }
  return (p && p.comm) || null;
}

function human(b) {
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return (i === 0 ? b.toFixed(0) : b.toFixed(1)) + u[i];
}

function pad(s, w, right = false) {
  s = String(s);
  if (s.length >= w) return s.slice(0, w);
  return right ? s.padStart(w) : s.padEnd(w);
}

// Look up a proc name lazily via the host's in-memory process tree.
// Cached locally so repeated lookups are O(1).
function nameFor(pid) {
  let cached = procs.get(pid);
  if (cached) return cached.name;
  const info = getProc(pid);
  const name = (info && info.name) || ("pid:" + pid);
  procs.set(pid, { name });
  return name;
}

// Network event handlers.
probe("ne:flow:new", c => {
  flows.set(c.flowID, {
    pid: c.pid, host: c.host, port: c.port,
    lastOut: 0, lastIn: 0,
  });
  getPid(c.pid).flowCount += 1;
});

probe("ne:flow:bytes", c => {
  let f = flows.get(c.flowID);
  if (!f) {
    // Flow we never saw open — pre-existed the script (e.g. Safari's
    // long-lived connections). Synthesize a record from the bytes
    // event's pid/host/port and count it from this point forward.
    f = { pid: c.pid, host: c.host, port: c.port, lastOut: 0, lastIn: 0 };
    flows.set(c.flowID, f);
    getPid(c.pid).flowCount += 1;
  }
  const dOut = Math.max(0, (c.bytesOut || 0) - f.lastOut);
  const dIn  = Math.max(0, (c.bytesIn  || 0) - f.lastIn);
  f.lastOut = c.bytesOut || 0;
  f.lastIn  = c.bytesIn  || 0;
  const t = getPid(f.pid);
  t.winOut += dOut; t.winIn += dIn;
  t.sesOut += dOut; t.sesIn += dIn;
});

probe("ne:flow:close", c => {
  let f = flows.get(c.flowID);
  if (!f) {
    // Never saw open or any bytes. Still attribute final totals by pid.
    f = { pid: c.pid, host: c.host, port: c.port, lastOut: 0, lastIn: 0 };
    getPid(c.pid).flowCount += 1;
  }
  const dOut = Math.max(0, (c.bytesOut || 0) - f.lastOut);
  const dIn  = Math.max(0, (c.bytesIn  || 0) - f.lastIn);
  const t = getPid(f.pid);
  t.winOut += dOut; t.winIn += dIn;
  t.sesOut += dOut; t.sesIn += dIn;
  t.flowCount = Math.max(0, t.flowCount - 1);
  flows.delete(c.flowID);
});

// Render tick.
probe("timer:1s", () => {

  // Snapshot tallies + reset window.
  const rows = [];
  let totalWinOut = 0, totalWinIn = 0, totalSesOut = 0, totalSesIn = 0;
  for (const [pid, t] of tally) {
    if (t.winOut === 0 && t.winIn === 0 && t.sesOut === 0 && t.sesIn === 0) continue;
    rows.push({
      pid, name: nameFor(pid),
      winOut: t.winOut, winIn: t.winIn,
      sesOut: t.sesOut, sesIn: t.sesIn,
      flows: t.flowCount,
    });
    totalWinOut += t.winOut; totalWinIn += t.winIn;
    totalSesOut += t.sesOut; totalSesIn += t.sesIn;
    t.winOut = 0; t.winIn = 0;
  }
  rows.sort((a, b) => (b.winOut + b.winIn) - (a.winOut + a.winIn));
  const top = rows.slice(0, N);

  // Layout. Fixed cols: 2 + 6 + 1 + 1 + 11 + 1 + 11 + 1 + 11 + 1 + 11 + 1 + 5 = 63
  // ("  " + PID(6) + " " + NAME + " " + OUT/s(11) + " " + IN/s(11) +
  //  " " + TOTAL↑(11) + " " + TOTAL↓(11) + " " + FLOWS(5))
  const totalCols = terminalCols();
  const nameWidth = Math.max(8, totalCols - 63);

  let out = "";
  out += `↑ ${human(totalWinOut)}/s   ↓ ${human(totalWinIn)}/s    `
       + `session: ↑${human(totalSesOut)} ↓${human(totalSesIn)}    `
       + `${flows.size} open flows\n\n`;
  out += "  " + pad("PID", 6, true) + " " + pad("NAME", nameWidth)
       + " " + pad("OUT/s", 11, true) + " " + pad("IN/s", 11, true)
       + " " + pad("TOTAL ↑", 11, true) + " " + pad("TOTAL ↓", 11, true)
       + " " + pad("FLOWS", 5, true) + "\n";
  out += "  " + "─".repeat(6) + " " + "─".repeat(nameWidth)
       + " " + "─".repeat(11) + " " + "─".repeat(11)
       + " " + "─".repeat(11) + " " + "─".repeat(11)
       + " " + "─".repeat(5) + "\n";
  for (const r of top) {
    out += "  " + pad(r.pid, 6, true) + " " + pad(r.name, nameWidth)
         + " " + pad(human(r.winOut), 11, true) + " " + pad(human(r.winIn), 11, true)
         + " " + pad(human(r.sesOut), 11, true) + " " + pad(human(r.sesIn), 11, true)
         + " " + pad(r.flows, 5, true) + "\n";
  }

  render("nettop", out);
});

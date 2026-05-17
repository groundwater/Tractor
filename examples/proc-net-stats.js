// proc-net-stats.js — every 1s, list the processes that did any network
// IO in the last second, with per-second bytes plus session totals.
//
// Submit:  sudo tractor program examples/proc-net-stats.js

const procs   = new Map();   // pid → {process, ppid, argv}
const window  = new Map();   // pid → {out, in} — bytes added this 1s window
const totals  = new Map();   // pid → {out, in} — session-cumulative bytes
const flowCum = new Map();   // flowID → {out, in} — last-seen cumulative per flow

// 1) Init: snapshot the host's in-memory process tree (sync, no syscalls).
for (const p of listProcs()) {
  procs.set(p.pid, { process: p.exe, comm: p.name, ppid: p.ppid });
}

// 2) Keep map current for processes that exec/exit while we're running.
probe("es:auth:exec", function (c) {
  procs.set(c.pid, { process: c.process, ppid: c.ppid, argv: c.argv });
});
probe("es:notify:exit", function (c) {
  procs.delete(c.pid);
});

// 3) Use flow-open as a fallback source of process info for pids we
//    couldn't resolve at init time (or that started after init but before
//    we saw any AUTH_EXEC for them, which can happen briefly).
probe("ne:flow:new", function (c) {
  if (!procs.has(c.pid) && c.process) {
    procs.set(c.pid, { process: c.process, ppid: null });
  }
});

// 4) Accumulate bytes. `ne:flow:bytes` fires periodically *during* a flow
//    with cumulative-since-flow-start totals — we diff against the prior
//    observation to get the delta and roll into pid windows/totals. This
//    gives smooth per-second rates for long-lived connections, not just
//    spikes at close.
function applyDelta(c) {
  const cumOut = Number(c.bytesOut || 0);
  const cumIn  = Number(c.bytesIn  || 0);
  const prev = flowCum.get(c.flowID) || { out: 0, in: 0 };
  const dOut = Math.max(0, cumOut - prev.out);
  const dIn  = Math.max(0, cumIn  - prev.in);
  flowCum.set(c.flowID, { out: cumOut, in: cumIn });

  const w = window.get(c.pid) || { out: 0, in: 0 };
  w.out += dOut; w.in += dIn;
  window.set(c.pid, w);
  const t = totals.get(c.pid) || { out: 0, in: 0 };
  t.out += dOut; t.in += dIn;
  totals.set(c.pid, t);
}

probe("ne:flow:bytes", applyDelta);

probe("ne:flow:close", function (c) {
  applyDelta(c);
  flowCum.delete(c.flowID);
});

function human(b) {
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return (i === 0 ? b.toFixed(0) : b.toFixed(1)) + u[i];
}

function basename(p) {
  if (!p) return null;
  const i = p.lastIndexOf("/");
  return i >= 0 ? p.slice(i + 1) : p;
}

function nameFor(pid) {
  const meta = procs.get(pid);
  if (meta) {
    return basename(meta.process) || meta.comm || ("pid:" + pid);
  }
  return "pid:" + pid;
}

// 5) Periodic flush.
probe("timer:1s", function () {
  if (window.size === 0) return;

  const rows = [];
  for (const pid of window.keys()) {
    const w = window.get(pid);
    const t = totals.get(pid) || { out: 0, in: 0 };
    rows.push({
      pid: pid,
      name: nameFor(pid),
      wOut: w.out, wIn: w.in,
      tOut: t.out, tIn: t.in,
    });
  }
  rows.sort(function (a, b) { return (b.wOut + b.wIn) - (a.wOut + a.wIn); });

  let line = rows.length + " active proc" + (rows.length === 1 ? "" : "s");
  for (let i = 0; i < rows.length; i++) {
    const r = rows[i];
    line += "\n  " + r.name + " [" + r.pid + "] " +
            "↑" + human(r.wOut) + " ↓" + human(r.wIn) +
            "   (session: ↑" + human(r.tOut) + " ↓" + human(r.tIn) + ")";
  }

  emit("stats", { line: line });
  window.clear();
});

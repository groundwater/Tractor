// engine-stats.js — live JS-engine self-profiler.
//
// Per-program-per-probe dispatch counts and p50/p99/max latency in
// nanoseconds, plus per-probe kernel-deadline-miss counters.
//
// Run:  sudo tractor program examples/engine-stats.js
//
// Best used loaded alongside other programs (top.js, nettop.js, etc.)
// so the stats actually show interesting numbers.

function fmtNs(ns) {
  if (ns < 1_000) return ns + "ns";
  if (ns < 1_000_000) return (ns / 1_000).toFixed(1) + "µs";
  if (ns < 1_000_000_000) return (ns / 1_000_000).toFixed(2) + "ms";
  return (ns / 1_000_000_000).toFixed(2) + "s";
}

function pad(s, w, right) {
  s = String(s);
  if (s.length >= w) return s.slice(0, w);
  return right ? s.padStart(w) : s.padEnd(w);
}

probe("timer:1s", () => {
  const s = engineStats();
  const cols = terminalCols();

  const lines = [];
  const uptime = (s.uptime_ms / 1000).toFixed(0);
  lines.push(`engine   uptime ${uptime}s   programs: ${s.programs.length}`);
  lines.push("");

  // Per-probe table per program.
  for (const p of s.programs) {
    lines.push(`▼ ${p.name}`);
    const probeNames = Object.keys(p.dispatches).sort();
    if (probeNames.length === 0) {
      lines.push("    (no probe dispatches yet)");
      lines.push("");
      continue;
    }
    lines.push("    "
      + pad("PROBE", 22)
      + " " + pad("CALLS", 10, true)
      + " " + pad("p50", 10, true)
      + " " + pad("p99", 10, true)
      + " " + pad("MAX", 10, true));
    lines.push("    " + "─".repeat(22)
      + " " + "─".repeat(10)
      + " " + "─".repeat(10)
      + " " + "─".repeat(10)
      + " " + "─".repeat(10));
    for (const name of probeNames) {
      const l = p.latency_ns[name] || {};
      lines.push("    "
        + pad(name, 22)
        + " " + pad(p.dispatches[name], 10, true)
        + " " + pad(fmtNs(l.p50 || 0), 10, true)
        + " " + pad(fmtNs(l.p99 || 0), 10, true)
        + " " + pad(fmtNs(l.max || 0), 10, true));
    }
    lines.push("");
  }

  // Deadline misses, if any.
  const misses = Object.keys(s.deadline_misses);
  if (misses.length > 0) {
    lines.push("▼ AUTH deadline misses (kernel auto-allowed)");
    for (const probe of misses.sort()) {
      lines.push(`    ${pad(probe, 22)} ${s.deadline_misses[probe]}`);
    }
  } else {
    lines.push("▼ AUTH deadline misses: none");
  }

  // Truncate to terminal width per-line.
  const out = lines.map(l => l.length > cols ? l.slice(0, cols - 1) + "…" : l).join("\n");
  render("engine-stats", out);
});

// top.js — render-style live process monitor. Uses `render(panel, text)`
// instead of `emit` so the CLI repaints the terminal in place every
// tick rather than scrolling.
//
// Run:  sudo tractor program examples/top.js
// (Best viewed in a real terminal; over a pipe / non-TTY it falls back
//  to line-by-line output.)

const prev = new Map();   // pid → { cpuNs, tickNs }
const cores = ncpu();

function human(b) {
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return (i === 0 ? b.toFixed(0) : b.toFixed(1)) + u[i];
}

// Pick the best name for a process. `comm` is kernel-truncated to 16
// chars; `process` is the full executable path. Prefer basename(process),
// fall back to comm, then to pid.
function bestName(p) {
  if (p.process) {
    const i = p.process.lastIndexOf("/");
    return i >= 0 ? p.process.slice(i + 1) : p.process;
  }
  return p.comm || ("pid:" + p.pid);
}

probe("timer:1s", () => {
  // Sample every pid. One proc_pidinfo per pid; tree-membership is free.
  // We need stats for every pid to compute CPU%, but each call is cheap
  // (a single syscall, no path resolution, no comm sysctl) — orders of
  // magnitude lighter than the old kitchen-sink requestProcessInfo.
  const nowNs = Date.now() * 1e6;
  const samples = [];
  const live = new Set();

  for (const pid of listPids()) {
    const s = getProcStats(pid);
    if (!s) continue;
    live.add(pid);
    const cpu = (s.cpu_user_ns || 0) + (s.cpu_system_ns || 0);
    const last = prev.get(pid);
    if (last) {
      const dCpu  = cpu - last.cpuNs;
      const dWall = nowNs - last.tickNs;
      if (dWall > 0) {
        const meta = getProc(pid);
        samples.push({
          name: meta ? meta.name : (s.comm || ("pid:" + pid)),
          pid,
          pct: (dCpu / dWall) * 100,
          rss: s.rss_bytes || 0,
          threads: s.threads || 0,
        });
      }
    }
    prev.set(pid, { cpuNs: cpu, tickNs: nowNs });
  }
  for (const pid of prev.keys()) if (!live.has(pid)) prev.delete(pid);

  samples.sort((a, b) => b.pct - a.pct);
  const top = samples.slice(0, 15);
  const load = loadAverage();

  const totalCols = terminalCols();
  const nameWidth = Math.max(8, totalCols - 32);

  let out = "";
  out += `load ${load[0].toFixed(2)} / ${load[1].toFixed(2)} / ${load[2].toFixed(2)}    cores ${cores}    procs ${live.size}\n\n`;
  out += "  PID    %CPU   THR  RSS       NAME\n";
  out += "  ─────  ─────  ───  ────────  " + "─".repeat(nameWidth) + "\n";
  for (const t of top) {
    const name = t.name.length > nameWidth ? t.name.slice(0, nameWidth) : t.name;
    out += "  "
      + String(t.pid).padStart(5) + "  "
      + (t.pct.toFixed(1) + "%").padStart(6) + " "
      + String(t.threads).padStart(4) + "  "
      + human(t.rss).padStart(8) + "  "
      + name + "\n";
  }

  render("top", out);
});

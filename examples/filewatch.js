// filewatch.js — live tail of filesystem mutations across the whole
// system. Like `fs_usage`, but you can filter by path glob, by process
// name, or both, and you get a fixed-panel top-style view that shows
// either the latest events (tail) or a sorted leaderboard.
//
// Run:
//   sudo tractor program examples/filewatch.js                         # everything
//   sudo tractor program examples/filewatch.js --path '~/Desktop/**'
//   sudo tractor program examples/filewatch.js --proc git              # only git
//   sudo tractor program examples/filewatch.js --proc node --path '**/node_modules/**'
//   sudo tractor program examples/filewatch.js --mode top              # leaderboard
//
// Flags:
//   --path GLOB     only show paths matching GLOB (supports *, **, ?)
//   --proc NAME     substring match against process name
//   --mode tail|top tail = scrolling latest (default); top = sorted by write count
//   --rows N        max rows in panel (default: terminal height - 4)
//
// Channels used: es:notify:write, es:notify:unlink, es:notify:rename

function parseArgs(av) {
  const o = { path: null, proc: null, mode: "tail", rows: null };
  let i = 0;
  while (i < av.length) {
    const a = av[i];
    if (a === "--path" && i + 1 < av.length)       o.path = av[++i];
    else if (a === "--proc" && i + 1 < av.length)  o.proc = av[++i];
    else if (a === "--mode" && i + 1 < av.length)  o.mode = av[++i];
    else if (a === "--rows" && i + 1 < av.length)  o.rows = parseInt(av[++i], 10);
    i++;
  }
  return o;
}
const OPTS = parseArgs(args);

// Expand a leading ~ in a glob and turn glob syntax into a regex.
//   *   → any chars except /
//   **  → any chars including /
//   ?   → single char except /
function globToRegex(glob) {
  // Expand ~ to user home if we can guess it (HOME isn't a JS global here,
  // but most invocations of `tractor program` run via sudo and tildes are
  // typed against the *invoking* user's home, so we can't reliably expand.
  // Leave ~ literal — users can pass an absolute path if they need to.
  let re = "^";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === "*") {
      if (glob[i + 1] === "*") { re += ".*"; i++; }
      else re += "[^/]*";
    } else if (c === "?") {
      re += "[^/]";
    } else if ("\\.+()|[]{}^$".indexOf(c) >= 0) {
      re += "\\" + c;
    } else {
      re += c;
    }
  }
  return new RegExp(re + "$");
}

const pathRe = OPTS.path ? globToRegex(OPTS.path) : null;

function procName(fullPath) {
  if (!fullPath) return "?";
  const i = fullPath.lastIndexOf("/");
  return i >= 0 ? fullPath.slice(i + 1) : fullPath;
}

function matches(proc, path) {
  if (OPTS.proc && procName(proc).indexOf(OPTS.proc) < 0) return false;
  if (pathRe && !pathRe.test(path)) return false;
  return true;
}

// Ring buffer of recent events for tail mode.
const TAIL_CAP = 2000;
const tail = [];

// Per-(proc, path) counters for top mode.
const counts = new Map();    // "op\0proc\0path" → {op, proc, path, count, lastTs}
let totalEvents = 0;
let droppedByFilter = 0;

function record(op, c, path, secondaryPath) {
  totalEvents++;
  if (!matches(c.process, path)) { droppedByFilter++; return; }

  const entry = {
    ts: Date.now(),
    op,
    pid: c.pid,
    proc: procName(c.process),
    path,
    extra: secondaryPath || null,   // for rename: destination
  };

  if (OPTS.mode === "top") {
    const key = `${op}\0${entry.proc}\0${path}`;
    const slot = counts.get(key);
    if (slot) { slot.count++; slot.lastTs = entry.ts; }
    else      { counts.set(key, { op, proc: entry.proc, path, count: 1, lastTs: entry.ts }); }
  } else {
    tail.push(entry);
    if (tail.length > TAIL_CAP) tail.splice(0, tail.length - TAIL_CAP);
  }
}

probe("es:notify:write",  c => record("W", c, c.path));
probe("es:notify:unlink", c => record("U", c, c.path));
probe("es:notify:rename", c => {
  // Record under both source and dest so either path-filter matches.
  record("R", c, c.from, c.to);
});

function pad(s, w, right) {
  s = String(s);
  if (s.length >= w) return s.slice(0, w);
  return right ? s.padStart(w) : s.padEnd(w);
}
function fmtTs(ms) {
  const d = new Date(ms);
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  const ml = String(d.getMilliseconds()).padStart(3, "0");
  return `${hh}:${mm}:${ss}.${ml}`;
}

probe("timer:250ms", () => {
  const cols = terminalCols();
  const rows = OPTS.rows || Math.max(10, terminalRows() - 4);
  const lines = [];

  const filterTag = [
    OPTS.proc ? `proc~="${OPTS.proc}"` : null,
    OPTS.path ? `path="${OPTS.path}"` : null,
  ].filter(Boolean).join("  ");

  lines.push(`filewatch [${OPTS.mode}]   seen ${totalEvents}   filtered out ${droppedByFilter}   ${filterTag || "(no filters)"}`);
  lines.push("");

  if (OPTS.mode === "top") {
    // Sort by count desc, then by recency.
    const rowsArr = [...counts.values()]
      .sort((a, b) => b.count - a.count || b.lastTs - a.lastTs)
      .slice(0, rows);
    lines.push(pad("OP", 3) + " " + pad("COUNT", 7, true) + " "
             + pad("LAST", 12) + " " + pad("PROC", 18) + " PATH");
    lines.push("─".repeat(Math.min(cols, 60)));
    for (const r of rowsArr) {
      const head = pad(r.op, 3) + " " + pad(r.count, 7, true) + " "
                 + pad(fmtTs(r.lastTs), 12) + " " + pad(r.proc, 18) + " ";
      const room = Math.max(1, cols - head.length);
      const p = r.path.length > room ? "…" + r.path.slice(-(room - 1)) : r.path;
      lines.push(head + p);
    }
  } else {
    // Tail mode: latest N events at the bottom.
    const slice = tail.slice(-rows);
    lines.push(pad("TIME", 12) + " " + pad("OP", 3) + " "
             + pad("PID", 6, true) + " " + pad("PROC", 18) + " PATH");
    lines.push("─".repeat(Math.min(cols, 60)));
    for (const e of slice) {
      const head = pad(fmtTs(e.ts), 12) + " " + pad(e.op, 3) + " "
                 + pad(e.pid, 6, true) + " " + pad(e.proc, 18) + " ";
      let body = e.path;
      if (e.op === "R" && e.extra) body += " → " + e.extra;
      const room = Math.max(1, cols - head.length);
      if (body.length > room) body = "…" + body.slice(-(room - 1));
      lines.push(head + body);
    }
  }

  render("filewatch", lines.join("\n"));
});

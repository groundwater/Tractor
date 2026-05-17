// pstree.js — live process tree, event-driven so even sub-second
// processes appear. Dead processes linger briefly with an [exited]
// marker before pruning, so you can see them flash by. Each row also
// shows the process's argv (when known — only for procs that exec'd
// after the script loaded).
//
// Run:
//   sudo tractor program examples/pstree.js                    # whole tree
//   sudo tractor program examples/pstree.js claude             # subtree of any proc named "claude"
//   sudo tractor program examples/pstree.js --linger 5000 npm  # dead-linger 5s, filter npm
//   sudo tractor program examples/pstree.js --depth 4          # cap depth to 4
//
// Flags:
//   --linger MS    how long dead procs stay visible (default 2000)
//   --depth N      max tree depth (default unlimited)
//   <name>         first non-flag arg = name filter (substring of process name)

function parseArgs(av) {
  const o = { linger: 2000, depth: 99, filter: null };
  let i = 0;
  while (i < av.length) {
    const a = av[i];
    if ((a === "--linger" || a === "-l") && i + 1 < av.length) {
      o.linger = parseInt(av[++i], 10);
    } else if ((a === "--depth" || a === "-d") && i + 1 < av.length) {
      o.depth = parseInt(av[++i], 10);
    } else if (!a.startsWith("-") && o.filter === null) {
      o.filter = a;
    }
    i++;
  }
  return o;
}

const OPTS = parseArgs(args);
const DEAD_LINGER_MS = OPTS.linger;

const procs = new Map();   // pid → { name, ppid, argv, deadAt, children }

function bestName(p) {
  // p shape varies: ES exec ctx has `process` + `comm` + `argv`;
  // listProcs entries have `name` + `exe`. Try in that order.
  if (p && p.name) return p.name;
  if (p && p.process) {
    const i = p.process.lastIndexOf("/");
    return i >= 0 ? p.process.slice(i + 1) : p.process;
  }
  if (p && p.exe) {
    const i = p.exe.lastIndexOf("/");
    return i >= 0 ? p.exe.slice(i + 1) : p.exe;
  }
  if (p && p.comm) return p.comm;
  if (p && p.argv && p.argv[0]) {
    const i = p.argv[0].lastIndexOf("/");
    return i >= 0 ? p.argv[0].slice(i + 1) : p.argv[0];
  }
  return "?";
}

function addProc(pid, ppid, name, argv) {
  const existing = procs.get(pid);
  if (existing) {
    existing.name = name;
    existing.ppid = ppid;
    existing.deadAt = null;
    if (argv) existing.argv = argv;
  } else {
    procs.set(pid, { name, ppid, argv: argv || null, deadAt: null, children: new Set() });
    const parent = procs.get(ppid);
    if (parent) parent.children.add(pid);
  }
}

// Init: snapshot the host's process tree (in-memory, no syscalls).
for (const p of listProcs()) {
  procs.set(p.pid, { name: bestName(p), ppid: p.ppid, argv: null, deadAt: null, children: new Set() });
}
for (const [pid, p] of procs) {
  if (p.ppid != null && p.ppid !== pid) {
    const parent = procs.get(p.ppid);
    if (parent) parent.children.add(pid);
  }
}

probe("es:notify:exec", c => {
  addProc(c.pid, c.ppid, bestName(c), c.argv);
});

probe("es:notify:exit", c => {
  const p = procs.get(c.pid);
  if (p) p.deadAt = Date.now();
});

// Reconciliation: every 30s, diff against the daemon's live-pid set
// (in-memory dict, no syscalls). Anything we have that's not in the
// daemon's tree must have exited without our es:notify:exit firing.
probe("timer:30s", () => {
  const live = new Set(listPids());
  const now = Date.now();
  for (const [pid, p] of procs) {
    if (!live.has(pid) && p.deadAt == null) p.deadAt = now;
  }
});

function prune(now) {
  const toRemove = [];
  for (const [pid, p] of procs) {
    if (p.deadAt != null && (now - p.deadAt) > DEAD_LINGER_MS) toRemove.push(pid);
  }
  for (const pid of toRemove) {
    const p = procs.get(pid);
    if (p && p.ppid != null) {
      const parent = procs.get(p.ppid);
      if (parent) parent.children.delete(pid);
    }
    procs.delete(pid);
  }
}

const DIM_ON  = "\x1b[2m";
const DIM_OFF = "\x1b[22m";

// Tree rendering. Each row: <prefix><connector><pid> <name> <argv>
// truncated to fit terminal width.
function renderSubtree(pid, prefix, isLast, lines, depth, maxDepth, cols) {
  const p = procs.get(pid);
  if (!p) return;
  const connector = isLast ? "└── " : "├── ";
  const childPrefix = isLast ? "    " : "│   ";
  const isDead = p.deadAt != null;

  let label = `${String(pid).padStart(6)} ${p.name}`;
  if (p.argv && p.argv.length > 1) {
    label += "  " + p.argv.slice(1).join(" ");
  }
  if (isDead) label += "  [exited]";

  // Truncate row to terminal width.
  const totalVisible = prefix.length + connector.length + label.length;
  if (totalVisible > cols) {
    const allowed = Math.max(1, cols - prefix.length - connector.length - 1);
    label = label.slice(0, allowed) + "…";
  }

  const open  = isDead ? DIM_ON  : "";
  const close = isDead ? DIM_OFF : "";
  lines.push(`${prefix}${connector}${open}${label}${close}`);

  if (depth >= maxDepth) {
    if (p.children.size > 0) {
      lines.push(`${prefix}${childPrefix}…(${p.children.size} hidden, depth limit)`);
    }
    return;
  }
  const children = [...p.children].sort((a, b) => a - b);
  for (let i = 0; i < children.length; i++) {
    renderSubtree(children[i], prefix + childPrefix, i === children.length - 1,
                  lines, depth + 1, maxDepth, cols);
  }
}

probe("timer:250ms", () => {
  const now = Date.now();
  prune(now);

  const cols = terminalCols();
  let roots = [];
  let liveCount = 0, deadCount = 0;
  const matches = new Set();        // pids whose name matches OPTS.filter
  for (const [pid, p] of procs) {
    if (p.deadAt) deadCount++; else liveCount++;
    if (OPTS.filter && p.name && p.name.indexOf(OPTS.filter) >= 0) matches.add(pid);
  }
  if (OPTS.filter) {
    // Only the topmost matching ancestor becomes a root — otherwise
    // child matches get rendered twice (once nested under their matching
    // parent, once as a separate root).
    for (const pid of matches) {
      let cur = procs.get(pid);
      let hasMatchingAncestor = false;
      while (cur && cur.ppid != null && cur.ppid !== pid) {
        if (matches.has(cur.ppid)) { hasMatchingAncestor = true; break; }
        cur = procs.get(cur.ppid);
        if (!cur) break;
      }
      if (!hasMatchingAncestor) roots.push(pid);
    }
  } else {
    for (const [pid, p] of procs) {
      if (p.ppid == null || !procs.has(p.ppid) || p.ppid === pid) roots.push(pid);
    }
  }
  roots.sort((a, b) => a - b);

  const lines = [];
  const filterTag = OPTS.filter ? `   filter="${OPTS.filter}"` : "";
  lines.push(`pstree   ${liveCount} live + ${deadCount} dying (kept ${DEAD_LINGER_MS}ms)   ${roots.length} root${roots.length === 1 ? "" : "s"}${filterTag}\n`);
  if (OPTS.filter && roots.length === 0) {
    lines.push(`  (no processes match "${OPTS.filter}" right now)`);
  }
  for (let i = 0; i < roots.length; i++) {
    renderSubtree(roots[i], "", i === roots.length - 1, lines, 0, OPTS.depth, cols);
  }

  const maxLines = Math.max(10, terminalRows() - 3);
  let out;
  if (lines.length > maxLines) {
    out = lines.slice(0, maxLines - 1).join("\n") + `\n  …(${lines.length - maxLines + 1} more lines off-screen)`;
  } else {
    out = lines.join("\n");
  }

  render("pstree", out);
});

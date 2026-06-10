// curl-pipe-bash.js — detect the classic `curl URL | bash` install
// pattern (and friends: wget|bash, fetch|sh, etc.). At shell-exec time,
// inspect the new process's stdin pipe handle, then scan every live
// proc's stdout for the matching peer handle to identify the writer.
//
// Run:
//   sudo tractor program examples/curl-pipe-bash.js
//
// Then in another terminal:
//   curl -sL https://example.com/install.sh | bash
//
// Flags:
//   --any-source     alert on ANY exec whose stdin is a pipe (broad).
//   --rows N         max rows shown.
//
// Composed from engine primitives:
//   getFdPipe(pid, fd)  → {handle, peerhandle} | null
//   listPids()          → [pid, ...] (live pids in the ES daemon's tree)
//   getProc(pid)        → {pid, ppid, name, exe, ...} | null

const SHELL_NAMES   = new Set(["bash", "sh", "zsh", "dash", "ksh", "fish"]);
const FETCH_NAMES   = new Set(["curl", "wget", "fetch", "httpie", "http"]);

function parseArgs(av) {
  const o = { anySource: false, deny: false, rows: null };
  let i = 0;
  while (i < av.length) {
    const a = av[i];
    if (a === "--any-source") o.anySource = true;
    else if (a === "--deny") o.deny = true;
    else if (a === "--rows" && i + 1 < av.length) o.rows = parseInt(av[++i], 10);
    i++;
  }
  return o;
}
const OPTS = parseArgs(args);

function basename(p) {
  if (!p) return "";
  const i = p.lastIndexOf("/");
  return i >= 0 ? p.slice(i + 1) : p;
}

const hits = [];     // {ts, shellPid, shellName, srcPid, srcName, srcExe, suspicious}
let totalExecs = 0;
let shellExecs = 0;
let pipedShellExecs = 0;
let withSourceCount = 0;
let cacheHitCount = 0;
let liveScanHitCount = 0;
let lastShell = "(none yet)";
const noSourceTrail = [];   // {ts, shell, pid, inode, peer, treeSize}

// Cache of `pipe_inode → {pid, name, exe, ts}` recorded at every
// AUTH_EXEC for procs whose fd 1 is a pipe. Lets us identify the writer
// even after it exits — important for fast producers like curl, which
// can finish & exit before the consumer's AUTH_EXEC arrives.
const pipeWriters = new Map();
const WRITER_TTL_MS = 30_000;

// Key writers by every identifier the kernel hands us — handle (always
// nonzero for a real pipe), peerhandle (consumer's handle, the natural
// lookup key when we see the consumer later), and inode (anonymous
// pipes are often 0 on macOS, but we record it anyway as a fallback).
function rememberIfPipeWriter(c) {
  const out = getFdPipe(c.pid, 1);
  if (!out) return;
  const entry = {
    pid: c.pid,
    name: basename(c.process),
    exe: c.process,
    ts: Date.now(),
  };
  if (out.handle)     pipeWriters.set("h:" + out.handle, entry);
  if (out.peerhandle) pipeWriters.set("p:" + out.peerhandle, entry);
  if (out.inode)      pipeWriters.set("i:" + out.inode, entry);
}

// Best-effort identification of the proc that has stdout on the other
// end of `pid`'s stdin pipe. Tries our writer cache first (works for
// already-exited producers); falls back to a live sysctl scan (works
// for currently-alive producers that we never saw via AUTH_EXEC).
function findStdinSource(pid, stdinInfo) {
  const mine = stdinInfo || getFdPipe(pid, 0);
  if (!mine) return null;
  // 1) Cache lookup — try all three identifiers, prefer peerhandle
  // (= producer's handle, recorded as "h:<writerHandle>") since that's
  // the most reliable on macOS where anonymous pipes have no inode.
  const cached =
       (mine.peerhandle && pipeWriters.get("h:" + mine.peerhandle))
    || (mine.handle     && pipeWriters.get("p:" + mine.handle))
    || (mine.inode      && pipeWriters.get("i:" + mine.inode));
  if (cached) { cacheHitCount++; return cached; }
  // 2) Live scan — match handle/peerhandle or inode across live pids.
  const wantHandle = mine.peerhandle;
  const wantInode  = mine.inode;
  for (const candidate of listPids()) {
    if (candidate === pid) continue;
    const other = getFdPipe(candidate, 1);
    if (!other) continue;
    if ((wantHandle && other.handle === wantHandle) ||
        (wantInode  && other.inode  === wantInode)) {
      liveScanHitCount++;
      return getProc(candidate) || { pid: candidate, name: "?", exe: "" };
    }
  }
  return null;
}

// Trim the writer cache periodically.
probe("timer:5s", () => {
  const cutoff = Date.now() - WRITER_TTL_MS;
  for (const [inode, w] of pipeWriters) {
    if (w.ts < cutoff) pipeWriters.delete(inode);
  }
});

// AUTH probes block the exec in the kernel until we return — call
// `deny()` to refuse, otherwise the exec proceeds. NOTIFY is observe-
// only (cheaper, no kernel wait) so we only switch to AUTH when --deny
// is requested.
probe(OPTS.deny ? "es:auth:exec" : "es:notify:exec", c => {
  totalExecs++;
  // Record this proc as a potential pipe writer BEFORE filtering on
  // shell — fetchers (curl/wget) need to be cached so we can identify
  // them when the consumer (bash) is auth'd next.
  rememberIfPipeWriter(c);
  const shellName = basename(c.process);
  if (!SHELL_NAMES.has(shellName)) return;
  shellExecs++;
  lastShell = `${shellName}(${c.pid}) @ ${new Date().toLocaleTimeString()}`;

  const mine = getFdPipe(c.pid, 0);
  if (!mine) return;             // stdin isn't a pipe (interactive shell)
  pipedShellExecs++;

  const src = findStdinSource(c.pid);
  if (!src) {
    // Pipe but no upstream found — record so we can see what went wrong.
    noSourceTrail.push({
      ts: Date.now(), shell: shellName, pid: c.pid,
      handle: mine.handle, peer: mine.peerhandle, inode: mine.inode,
      treeSize: listPids().length,
    });
    if (noSourceTrail.length > 50) noSourceTrail.splice(0, noSourceTrail.length - 50);
    emit("debug", { line: `${shellName}(${c.pid}) PIPE-no-source  inode=${mine.inode} peer=${mine.peerhandle} tree=${listPids().length}` });
    return;
  }
  withSourceCount++;

  const srcName = src.name || "?";
  const suspicious = FETCH_NAMES.has(srcName);

  if (!OPTS.anySource && !suspicious) return;

  hits.push({
    ts: Date.now(),
    shellPid: c.pid,
    shellName,
    srcPid: src.pid,
    srcName,
    srcExe: src.exe || "",
    suspicious,
  });
  if (hits.length > 1000) hits.splice(0, hits.length - 1000);

  if (suspicious) {
    if (OPTS.deny) {
      c.deny();   // ctx-scoped — only valid in es:auth:* probes
      emit("alert", { line: `BLOCKED ${srcName}(${src.pid}) | ${shellName}(${c.pid})  ${src.exe || ""}` });
    } else {
      emit("alert", { line: `${srcName}(${src.pid}) | ${shellName}(${c.pid})  ${src.exe || ""}` });
    }
  }
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
       + `${String(d.getSeconds()).padStart(2, "0")}`;
}

const BOLD_ON  = "\x1b[1m";
const BOLD_OFF = "\x1b[22m";

probe("timer:500ms", () => {
  const cols = terminalCols();
  const rows = OPTS.rows || Math.max(10, terminalRows() - 4);
  const lines = [];
  const mode = OPTS.deny ? "AUTH/deny" : "NOTIFY/observe";
  lines.push(`curl-pipe-bash [${mode}]  total-execs=${totalExecs}  shell-execs=${shellExecs}  `
           + `piped=${pipedShellExecs}  with-source=${withSourceCount} (cache=${cacheHitCount} live=${liveScanHitCount})  `
           + `alerts=${hits.filter(h => h.suspicious).length}  `
           + `writers-cached=${pipeWriters.size}`
           + (OPTS.anySource ? "   [showing ANY piped exec]" : ""));
  lines.push(`last-shell: ${lastShell}`);
  if (noSourceTrail.length > 0) {
    const last = noSourceTrail[noSourceTrail.length - 1];
    lines.push(`last-no-source: ${last.shell}(${last.pid}) inode=${last.inode} peer=${last.peer} tree=${last.treeSize}`);
  }
  lines.push(pad("TIME", 10) + " " + pad("SHELL", 22)
           + " " + pad("←  SOURCE", 30) + " SOURCE-EXE");
  lines.push("─".repeat(Math.min(cols, 60)));
  for (const h of hits.slice(-rows)) {
    const shell = `${h.shellName}(${h.shellPid})`;
    const src   = `${h.srcName}(${h.srcPid})`;
    const head  = pad(fmtTs(h.ts), 10) + " "
                + pad(shell, 22) + " "
                + pad("←  " + src, 30) + " ";
    const room = Math.max(1, cols - head.length);
    let body = h.srcExe;
    if (body.length > room) body = "…" + body.slice(-(room - 1));
    let row = head + body;
    if (h.suspicious) row = BOLD_ON + row + BOLD_OFF;
    lines.push(row);
  }
  render("curl-pipe-bash", lines.join("\n"));
});

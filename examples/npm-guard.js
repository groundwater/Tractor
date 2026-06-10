// npm-guard.js — observe-only. When `npm install` (or i/ci/add) runs
// anywhere on the system, log every subprocess it spawns and every file
// write/delete/rename it performs. Nothing is blocked.

const tracked = new Set();
const INSTALL_VERBS = new Set(["install", "i", "ci", "add"]);

function looksLikeNpmInstall(process, argv) {
  if (!argv || argv.length < 2) return false;
  var hasNpm = (process && process.indexOf("npm") >= 0);
  if (!hasNpm) {
    for (var i = 0; i < argv.length; i++) {
      if (String(argv[i]).indexOf("npm") >= 0) { hasNpm = true; break; }
    }
  }
  if (!hasNpm) return false;
  for (var j = 1; j < argv.length; j++) {
    if (INSTALL_VERBS.has(String(argv[j]).toLowerCase())) return true;
  }
  return false;
}

probe("es:auth:exec", function (ctx) {
  // Log any subprocess spawned beneath an npm-install root.
  if (tracked.has(ctx.ppid)) {
    emit("subprocess", { pid: ctx.pid, ppid: ctx.ppid, process: ctx.process, argv: ctx.argv });
    tracked.add(ctx.pid);  // keep watching this whole subtree
    return;
  }
  // Detect a fresh npm-install root.
  if (looksLikeNpmInstall(ctx.process, ctx.argv)) {
    tracked.add(ctx.pid);
    emit("npm-install-detected", { pid: ctx.pid, process: ctx.process, argv: ctx.argv });
  }
});

probe("es:notify:write", function (ctx) {
  if (!tracked.has(ctx.pid)) return;
  emit("fileop", { type: "write", pid: ctx.pid, path: ctx.path });
});

probe("es:notify:unlink", function (ctx) {
  if (!tracked.has(ctx.pid)) return;
  emit("fileop", { type: "delete", pid: ctx.pid, path: ctx.path });
});

probe("es:notify:rename", function (ctx) {
  if (!tracked.has(ctx.pid)) return;
  emit("fileop", { type: "rename", pid: ctx.pid, from: ctx.from, to: ctx.to });
});

probe("es:notify:exit", function (ctx) {
  tracked.delete(ctx.pid);
});

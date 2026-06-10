// network-block.js — single JS engine seeing BOTH exec and network events.
//
// When `curl` runs anywhere on the system:
//   • mark its pid (and any descendants') for network observation
//   • deny every outbound TCP flow it tries to open to a host in BLOCKED
//   • emit every flow attempt (allowed or denied) so the GUI streams it
//
// Submit with:  sudo tractor program examples/network-block.js
//
// Demonstrates the unified-engine point: one Set, one mental model, two
// event sources (ES exec + NE flow). The XPC plumbing between sysexts is
// invisible to the program.

const tracked = new Set();
const BLOCKED_SUFFIXES = ["doubleclick.net", "googletagmanager.com", "example.com"];

function basename(p) {
  if (!p) return "";
  const i = p.lastIndexOf("/");
  return (i >= 0 ? p.slice(i + 1) : p).toLowerCase();
}

probe("es:auth:exec", function (ctx) {
  if (tracked.has(ctx.ppid)) {
    tracked.add(ctx.pid);
    return;
  }
  if (basename(ctx.process) === "curl") {
    tracked.add(ctx.pid);
    emit("curl-detected", { pid: ctx.pid, argv: ctx.argv });
  }
});

probe("ne:flow:new", function (ctx) {
  // ctx.{pid, process, host, port, direction}
  if (!tracked.has(ctx.pid)) {
    // We only meddle with flows from tracked processes.
    return;
  }

  const blocked = BLOCKED_SUFFIXES.some(function (s) {
    return typeof ctx.host === "string" && ctx.host.endsWith(s);
  });

  if (blocked) {
    ctx.deny();
    emit("flow-blocked", { pid: ctx.pid, host: ctx.host, port: ctx.port });
  } else {
    emit("flow-allowed", { pid: ctx.pid, host: ctx.host, port: ctx.port });
  }
});

probe("es:notify:exit", function (ctx) {
  tracked.delete(ctx.pid);
});

// flow-log.js — observe every outbound TCP flow, annotated with the
// process that opened it. Pivots through a pid → process metadata Map.
//
// Submit:  sudo tractor program examples/flow-log.js

const procs = new Map();

// 1) Init: seed the map with everything that's already running so flows
//    from long-lived processes (Safari, Slack, etc.) have a process name.
//    Sync: pulls from the host's in-memory process tree, no syscalls.
for (const p of listProcs()) {
  procs.set(p.pid, { process: p.exe, comm: p.name, ppid: p.ppid });
}

// 2) Keep the map current as processes come and go.
probe("es:auth:exec", function (c) {
  procs.set(c.pid, { process: c.process, ppid: c.ppid, argv: c.argv });
});
probe("es:notify:exit", function (c) {
  procs.delete(c.pid);
});

// 3) Log flow opens.
probe("ne:flow:new", function (c) {
  const m = procs.get(c.pid) || {};
  emit("flow-open", {
    pid: c.pid,
    process: m.process || c.process || null,
    argv: m.argv || null,
    host: c.host,
    port: c.port,
    direction: c.direction,
  });
});

// 4) Log flow closes with byte totals.
probe("ne:flow:close", function (c) {
  const m = procs.get(c.pid) || {};
  emit("flow-close", {
    pid: c.pid,
    process: m.process || null,
    host: c.host,
    port: c.port,
    bytesOut: c.bytesOut,
    bytesIn: c.bytesIn,
  });
});

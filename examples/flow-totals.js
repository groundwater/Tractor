// flow-totals.js — running totals of network IO, emitted every second.
//
// Accumulates bytes from ne:flow:close events and formats a human-readable
// summary on a 1s tick.
//
// Submit:  sudo tractor program examples/flow-totals.js

let totalOut = 0;
let totalIn = 0;
let lastOut = 0;
let lastIn  = 0;
let flowCount = 0;

function human(bytes) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (bytes >= 1024 && i < units.length - 1) { bytes /= 1024; i++; }
  return bytes.toFixed(i === 0 ? 0 : 2) + units[i];
}

probe("ne:flow:close", function (c) {
  totalOut += c.bytesOut || 0;
  totalIn  += c.bytesIn  || 0;
  flowCount += 1;
});

probe("timer:1s", function () {
  const deltaOut = totalOut - lastOut;
  const deltaIn  = totalIn  - lastIn;
  lastOut = totalOut;
  lastIn  = totalIn;

  emit("totals", {
    line: "↑ " + human(deltaOut) + "/s   ↓ " + human(deltaIn) + "/s   " +
          "(session: ↑" + human(totalOut) + " ↓" + human(totalIn) + ", " +
          flowCount + " flows)",
    deltaOut: deltaOut,
    deltaIn:  deltaIn,
    totalOut: totalOut,
    totalIn:  totalIn,
    flowCount: flowCount,
  });
});

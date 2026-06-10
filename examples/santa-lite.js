// santa-lite.js — exec allowlist by Apple team ID. Deny any user-binary
// exec whose team_id isn't in the allowlist. Platform binaries (the OS
// itself) are always allowed.
//
// Run:
//   sudo tractor program examples/santa-lite.js ABC123 T84D6A4Q1J
//
// The team IDs come in via the `args` global (string array).

const allowedTeams = new Set(args);

fputs(`santa-lite armed: ${allowedTeams.size} team(s) allowed: ${[...allowedTeams].join(", ")}`);

function fputs(line) {
  emit("info", { line });
}

probe("es:auth:exec", function (c) {
  // Always allow platform binaries (Apple's own).
  if (c.is_platform_binary) return;

  // Allow if the team_id is in the allowlist.
  if (c.team_id && allowedTeams.has(c.team_id)) return;

  // Otherwise deny and log.
  c.deny();
  emit("denied", {
    line: `DENY ${c.process}  team=${c.team_id || "unsigned"}  signing=${c.signing_id || "-"}`,
    pid: c.pid,
    process: c.process,
    argv: c.argv,
    team_id: c.team_id,
    signing_id: c.signing_id,
  });
});

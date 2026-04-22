# Tractor

<p align="center">
  <img src="icon/Tractor_1024.png" width="192" alt="Tractor icon" />
</p>

**Know what your AI agents are up to.**

Tractor is a real-time process monitor for AI coding agents on macOS. It uses the Endpoint Security framework to trace an agent's process tree, file activity, and observed network connections, then presents the activity in an interactive ncurses TUI or as JSON lines.

## Why?

AI coding agents spawn dozens of subprocesses, write to files across your filesystem, and make network requests — all in seconds. Tractor gives you visibility into this activity with low overhead.

- **Process tree** — see subprocesses an agent spawns, nested by parent-child relationship
- **File tracking** — watch which files are being written in real-time
- **Network connections** — see observed connections, with per-connection byte counters when available
- **CPU profiling** — sample any process to see where it's spending time
- **Wait diagnosis** — find out why a process is blocked

## Install

```bash
git clone https://github.com/groundwater/Tractor.git
cd Tractor
make debug
```

Requires Xcode, [XcodeGen](https://github.com/yonaskolb/XcodeGen), and macOS 15+.

The debug binary is produced under `.build/Debug/Tractor`.

### Development Security Setup

Tractor uses Apple's Endpoint Security framework. For local development with an unsigned or ad-hoc signed build, the most practical setup is a macOS VM with SIP disabled.

**For development and testing, we recommend running Tractor inside a VM with SIP disabled.** This keeps your host machine secure while giving Tractor full access.

Using [GhostVM](https://github.com/groundwater/GhostVM) or any macOS VM:

```bash
# In the VM, boot into Recovery Mode (hold power button on Apple Silicon)
# Open Terminal from the Utilities menu, then:
csrutil disable

# Reboot, then run Tractor:
sudo .build/Debug/Tractor trace --trace Terminal
```

> **Note:** Disabling SIP on your primary machine is not recommended for daily use. SIP protects your system from unauthorized modifications. Use a VM for development and testing.

On a production machine, the Endpoint Security entitlement is a restricted entitlement that must be authorized by a provisioning profile. For distribution, use an app-like bundle or system extension host so the profile can be embedded, sign with Developer ID and hardened runtime, notarize the distribution artifact, and grant Full Disk Access in System Settings.

## Usage

```bash
# Trace any process by name (substring match)
sudo .build/Debug/Tractor trace --trace claude

# Trace Terminal and all its child processes
sudo .build/Debug/Tractor trace --trace Terminal

# Trace a specific PID and its descendants
sudo .build/Debug/Tractor trace --pid 1234

# JSON output for scripting
sudo .build/Debug/Tractor trace --trace claude --json
```

### Keyboard

| Key | Action |
|-----|--------|
| `↑`/`↓` | Navigate process list |
| `→`/`←` | Expand/collapse (Finder-style) |
| `Enter` | Toggle disclosure |
| `Esc` | Clear selection |
| `Space` | Pause/resume display |
| `h` | Toggle tree/flat view |
| `?` | Toggle hints |
| `q` | Quit |

#### Menus

| Key | Menu |
|-----|------|
| `f` | **File** — Track, Export placeholder |
| `e` | **Edit** — Clear; Filter, Find, Copy placeholders |
| `p` | **Process** — Info, Files, Network, Sample, Wait, Kill, Pause |
| `m` | **Sample** — Resample, Delete, Export placeholder |
| `t` | **Network** — Reverse DNS and SNI status |
| `y` | **FileSystem** — Read/write display toggles |
| `v` | **View** — Show Exited, Expand/Collapse All, Columns placeholder |

#### Process Actions

| Key | Action |
|-----|--------|
| `i` | Toggle process info (path, args, env, resources) |
| `d` | Toggle file I/O panel |
| `n` | Toggle network connections panel |
| `s` | Sample CPU profile (3 seconds, bottom-up call tree) |
| `w` | Diagnose wait — show what threads are blocked on |
| `k` | Kill — pick a signal from the modal |
| `z` | Pause/resume process (SIGSTOP/SIGCONT) |
| `l` | Clear exited processes |

## Architecture

Tractor is built on several macOS subsystems:

- **Endpoint Security** (`AUTH_EXEC`, `NOTIFY_OPEN`, `NOTIFY_WRITE`, `NOTIFY_CLOSE`, `NOTIFY_UNLINK`, `NOTIFY_RENAME`, `NOTIFY_EXIT`) — process lifecycle and file operations
- **NetworkStatistics.framework** (private, via `dlopen`) — per-connection byte counters without spawning subprocesses
- **libpcap** — SNI extraction from TLS ClientHello packets for hostname resolution
- **proc_pidinfo / proc_pid_rusage** — disk I/O totals, CWD, open file descriptors
- **sample** — CPU profiling with inverted call tree parsing

### How It Works

1. Tractor registers an ES client with `AUTH_EXEC` to observe and promptly allow new process creation. This helps capture short-lived child processes.
2. The process tree is built from parent-child relationships. New agent instances are auto-discovered by matching executable names.
3. File writes are tracked via `NOTIFY_WRITE`, `NOTIFY_CLOSE` (modified), and `NOTIFY_RENAME` (for atomic saves).
4. Network connections are enumerated via the private `NetworkStatistics.framework`, giving per-connection TX/RX byte counters.
5. Hostname resolution uses a combination of reverse DNS and a packet sniffer that extracts SNI from TLS ClientHello messages.

## JSON Output

The `--json` flag outputs newline-delimited JSON events to stdout:

```json
{"type":"exec","pid":1234,"ppid":1813,"process":"/usr/bin/grep","timestamp":"2026-04-22T08:00:00.000Z","user":501,"details":{"argv":"grep -r foo"}}
{"type":"write","pid":1813,"ppid":1753,"process":"claude","timestamp":"2026-04-22T08:00:01.000Z","user":501,"details":{"path":"/Users/you/project/src/main.ts"}}
{"type":"exit","pid":1234,"ppid":1813,"process":"/usr/bin/grep","timestamp":"2026-04-22T08:00:02.000Z","user":501,"details":{}}
```

## Roadmap

- [ ] **TLS interception** — decrypt and display API request/response content using DYLD injection or Network Extension
- [ ] **JS stack frames** — resolve V8/Bun JIT frames via Node.js inspector protocol (`SIGUSR1` activation)
- [ ] **Crash detection** — parse `.ips` crash reports, show crash dump inline with faulting thread backtrace
- [ ] **Flamegraph export** — generate SVG flamegraphs from sample data, open in browser
- [ ] **Session recording/replay** — save all ES events to a file, replay the TUI from a recording
- [ ] **Cost estimation** — estimate API costs from network traffic byte counts
- [ ] **Multi-agent comparison** — trace two agents side-by-side, compare resource usage
- [ ] **Column configuration** — show/hide and reorder columns via View menu
- [ ] **Filter/search** — filter process list by name, PID, or status
- [ ] **Network Extension** — proper system extension for per-connection byte counters without private API
- [ ] **Alerting** — configurable alerts for unexpected file writes, network connections, or process spawns

## License

GNU Affero General Public License v3.0

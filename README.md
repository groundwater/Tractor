# Tractor

<p align="center">
  <img src="icon/Tractor_1024.png" width="192" alt="Tractor icon" />
</p>

**Know what your AI agents are up to.**

Tractor is a real-time process monitor for AI coding agents on macOS. It traces an agent's process tree, file activity, and network connections — then presents everything in an interactive terminal UI. Optionally intercept TLS traffic to inspect the actual HTTP requests your agent is making.

<p align="center">
  <img src="screenshots/hero-process-tree.png" width="720" alt="Tractor tracing Claude Code — process tree with network connections and subprocess activity" />
</p>

## Why?

AI coding agents spawn dozens of subprocesses, write to files across your filesystem, and make network requests — all in seconds. Tractor gives you visibility into this activity with low overhead.

## Features

### Process Tree

Live hierarchical view of all traced processes with PID, runtime, file operation count, CPU status, memory usage, and full command line. Processes are auto-discovered by name, PID, or executable path — children are captured automatically.

### Process Info

Inspect any process to see its full path, working directory, arguments, environment variables, and resource usage (CPU time, RSS memory, open file descriptors, disk I/O).

<p align="center">
  <img src="screenshots/detail-view.png" width="720" alt="Process info panel showing path, args, env, file writes, and network connections" />
</p>

### File Tracking

Real-time observation of file writes, renames, and deletes per process. Files are shown with write count, size, and path relative to the process working directory. The panel auto-expands on activity and auto-collapses after 5 seconds of inactivity.

### Network Connections

Per-connection TX/RX byte counters with hostname resolution (reverse DNS and SNI extraction). Connections are grouped by process with lifetime aggregate totals.

<p align="center">
  <img src="screenshots/network-connections.png" width="720" alt="Network connections panel showing per-connection TX/RX bytes and hostnames" />
</p>

### TLS Interception

Optional transparent TLS proxy decrypts HTTPS traffic from traced processes. See the actual HTTP requests and responses your agent is making — method, URL, headers, and body. Supports chunked transfer encoding and gzip/deflate decompression.

<p align="center">
  <img src="screenshots/http-protocol-frames.png" width="720" alt="HTTP protocol frames showing request/response summary lines with chunked transfer decoding" />
</p>

Drill into any frame to inspect full headers and decoded body:

<p align="center">
  <img src="screenshots/traffic-request.png" width="720" alt="Traffic inspector showing HTTP request headers" />
</p>

<p align="center">
  <img src="screenshots/traffic-response.png" width="720" alt="Traffic inspector showing decoded HTTP response with gzip decompression" />
</p>

### CPU Sampling

Capture CPU profiles with configurable duration, threshold, and depth. Results are displayed as a bottom-up call tree with auto-expansion of hot functions.

<p align="center">
  <img src="screenshots/cpu-sample.png" width="720" alt="CPU sample results with bottom-up call tree and sample configuration modal" />
</p>

### Wait Diagnosis

Diagnose why a process is blocked by sampling its threads and categorizing blocking functions — I/O wait, TLS, network, disk, lock contention, memory allocation, or sleep.

### Signal Delivery

Send signals (SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGKILL) or pause/resume (SIGSTOP/SIGCONT) any traced process.

<p align="center">
  <img src="screenshots/send-signal.png" width="320" alt="Send Signal modal with SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGKILL" />
</p>

### JSON Output

Stream newline-delimited JSON events to stdout for scripting and analysis:

```bash
sudo tractor trace --name claude --json
```

### SQLite Logging

Persist all events and HTTP traffic to a SQLite database for post-hoc analysis:

```bash
sudo tractor trace --name claude --mitm --log
```

## Quick Start

```bash
git clone https://github.com/groundwater/Tractor.git
cd Tractor
make debug
sudo .build/Debug/Tractor trace --name Terminal
```

> [!WARNING]
> Tractor uses Apple's Endpoint Security framework, which requires SIP to be disabled for unsigned builds. See [Development Setup](#development-setup) for details.

Requires Xcode, [XcodeGen](https://github.com/yonaskolb/XcodeGen), and macOS 15+.

### MITM Setup

To enable TLS interception:

```bash
make install && make activate
sudo tractor trust-ca
sudo tractor trace --name claude --mitm
```

> [!NOTE]
> Without `--net` or `--mitm`, Tractor does not activate the network extension. Basic process and file tracking works standalone.

## Development Setup

Tractor uses Apple's Endpoint Security framework, which requires special entitlements. For local development with an unsigned build, the most practical setup is a macOS VM with SIP disabled.

<details>
<summary>VM setup instructions</summary>

Using [GhostVM](https://github.com/groundwater/GhostVM) or any macOS VM:

```bash
# In the VM, boot into Recovery Mode (hold power button on Apple Silicon)
# Open Terminal from the Utilities menu, then:
csrutil disable

# Reboot, then run Tractor:
sudo .build/Debug/Tractor trace --name Terminal
```

> **Note:** Disabling SIP on your primary machine is not recommended. Use a VM for development.

</details>

<details>
<summary>Production distribution</summary>

The Endpoint Security entitlement is restricted and must be authorized by a provisioning profile. For distribution: use an app-like bundle or system extension host so the profile can be embedded, sign with Developer ID and hardened runtime, notarize the artifact, and grant Full Disk Access in System Settings.

</details>

### Build Targets

| Make target | Description |
|-------------|-------------|
| `make debug` | Build unsigned Debug binary (requires SIP disabled) |
| `make release` | Build signed Release .app bundle with embedded system extension |
| `make install` | Install Release .app to `/Applications/Tractor.app` |
| `make activate` | Activate the network system extension |
| `make clean` | Remove build directory |

## License

GNU Affero General Public License v3.0

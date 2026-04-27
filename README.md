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

**Process tree** — live hierarchical view of all traced processes with PID, runtime, CPU, memory, and full command line. Auto-discovers new agent instances and captures their entire subtree.

**Process inspection** — full path, working directory, arguments, environment variables, and resource usage.

<p align="center">
  <img src="screenshots/detail-view.png" width="720" alt="Process info panel showing path, args, env, file writes, and network connections" />
</p>

**File tracking** — real-time observation of file writes, renames, and deletes per process.

**Network connections** — per-connection TX/RX byte counters with hostname resolution.

<p align="center">
  <img src="screenshots/network-connections.png" width="720" alt="Network connections panel showing per-connection TX/RX bytes and hostnames" />
</p>

**TLS interception** — transparent MITM proxy decrypts HTTPS traffic. See HTTP requests and responses with full headers and body. Supports chunked transfer encoding and gzip/deflate decompression.

<p align="center">
  <img src="screenshots/http-protocol-frames.png" width="720" alt="HTTP protocol frames showing request/response summary lines" />
</p>

<p align="center">
  <img src="screenshots/traffic-request.png" width="720" alt="Traffic inspector showing HTTP request headers" />
</p>

<p align="center">
  <img src="screenshots/traffic-response.png" width="720" alt="Traffic inspector showing decoded HTTP response with gzip decompression" />
</p>

**CPU sampling** — capture CPU profiles displayed as a bottom-up call tree.

<p align="center">
  <img src="screenshots/cpu-sample.png" width="720" alt="CPU sample results with bottom-up call tree" />
</p>

**Wait diagnosis** — find out why a process is blocked (I/O, locks, network, sleep).

**Signal delivery** — send signals or pause/resume any traced process.

**JSON output** — stream events as newline-delimited JSON for scripting.

**SQLite logging** — persist all events and HTTP traffic to a database.

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

### TLS Interception Setup

```bash
make install && make activate
sudo tractor trust-ca
sudo tractor trace --name claude --mitm
```

## Development Setup

Tractor requires special entitlements for Endpoint Security. For local development, use a macOS VM with SIP disabled.

<details>
<summary>VM setup</summary>

Using [GhostVM](https://github.com/groundwater/GhostVM) or any macOS VM, boot into Recovery Mode and run `csrutil disable`.

</details>

<details>
<summary>Production distribution</summary>

Requires a provisioning profile with the Endpoint Security entitlement, Developer ID signing, hardened runtime, notarization, and Full Disk Access.

</details>

### Build Targets

| Target | Description |
|--------|-------------|
| `make debug` | Unsigned Debug binary (requires SIP disabled) |
| `make release` | Release .app bundle with embedded system extension |
| `make install` | Install to `/Applications/Tractor.app` |
| `make activate` | Activate the network system extension |

## License

GNU Affero General Public License v3.0

# frida-mcp-server

A local MCP server for authorized iOS app inspection with [Frida](https://frida.re). Exposes 50+ short-named tools for attaching to apps, capturing and replaying network traffic, fuzzing requests, scanning for mobile API vulnerabilities, browsing storage, tracing Objective-C methods, dumping binaries, and installing bypass hooks — **zero FLEX dependency, pure Frida**.

Use this only on apps, devices, and programs where you have explicit authorization.

---

## Table of Contents

- [What It Does](#what-it-does)
- [Architecture](#architecture)
- [Quick Install](#quick-install)
- [Detailed Installation](#detailed-installation)
- [Requirements](#requirements)
- [CLI Commands](#cli-commands)
- [MCP Configuration](#mcp-configuration)
- [Tool Categories](#tool-categories)
- [Common Workflows](#common-workflows)
- [Bundled Skills](#bundled-skills)
- [Troubleshooting](#troubleshooting)
- [Repository Layout](#repository-layout)
- [License](#license)

---

## What It Does

frida-mcp-server turns AI coding agents into iOS security analysts. It bridges the Model Context Protocol (MCP) with Frida's dynamic instrumentation framework, giving agents direct, programmatic access to a running iOS app's internals — all over stdio.

**Capabilities include:**

- **Network capture** — Hook NSURLSession at runtime to capture every HTTP/HTTPS request and response, including headers, bodies, and timing. No proxy required.
- **Request replay & interception** — Replay captured requests with header/body overrides, or install in-flight rewrite rules that modify matching requests before they leave the device.
- **Security scanning** — Automatically scan captured traffic for plaintext endpoints, weak JWTs, leaked API keys, missing HSTS, permissive CORS, and stack trace exposure.
- **Fuzzing** — Fuzz any captured request against 8 preset payload sets (SQLi, XSS, path traversal, command injection, SSRF, auth bypass, NoSQL injection, LDAP injection).
- **Storage inspection** — Browse Keychain items, NSUserDefaults, HTTP cookies, sandbox files, and SQLite databases. Read, write, and pull files from the device.
- **Objective-C runtime** — Search classes, list methods, find live heap instances, inspect ivars, and invoke selectors with typed arguments — all on the main queue.
- **Method tracing** — Hook any ObjC method and buffer its invocations, arguments, and return values for later analysis.
- **Binary dump** — Decrypt and dump the app's Mach-O binary (frida-ios-dump style) for offline static analysis.
- **Crypto hooks** — Capture CommonCrypto CCCrypt calls including keys, IVs, and plaintext/ciphertext buffers.
- **Bypasses** — One-command SSL pinning bypass and jailbreak detection evasion.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        AI Agent (MCP Client)                 │
│    Claude Code / Cursor / OpenCode / Codex / Cline / ...     │
└──────────────────────────┬──────────────────────────────────┘
                           │ MCP stdio transport
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    frida-mcp-server (Node.js CLI)             │
│                  bin/cli.js — install / serve / doctor       │
└──────────────────────────┬──────────────────────────────────┘
                           │ spawns
                           ▼
┌─────────────────────────────────────────────────────────────┐
│               frida_mcp_server.py (Python MCP Server)         │
│    • 64 MCP tools with short names                           │
│    • Session management with health checks                   │
│    • JS execution engine with ObjC.schedule(mainQueue)       │
│    • Auto-retry on dead sessions                             │
└──────────────────────────┬──────────────────────────────────┘
                           │ frida RPC
                           ▼
┌─────────────────────────────────────────────────────────────┐
│               frida-server (iOS Device / Simulator)          │
│    • NSURLSession hooks (network capture)                    │
│    • ObjC runtime introspection                              │
│    • Method tracing buffers                                  │
│    • CommonCrypto hooks                                      │
│    • SSL unpin / JB bypass scripts                           │
└─────────────────────────────────────────────────────────────┘
```

**Key design decisions:**

- **Zero FLEX dependency** — All network capture uses pure Frida NSURLSession hooks. No FLEX framework needs to be embedded in the target app.
- **Main queue safety** — All ObjC calls are wrapped in `ObjC.schedule(ObjC.mainQueue)` to prevent UIKit/AppKit crashes from background thread access.
- **Session resilience** — Every tool call checks session health. Dead sessions are detected, cleaned up, and the agent is informed automatically.
- **Short tool names** — All 64 tools use concise, distinctive names (`apps`, `connect`, `requests`, `replay`, `replay_as`, `race`, `diff`, `webviews`, `swift_classes`, `har_export`, etc.) for efficient agent usage.

---

## Quick Install

```bash
npm install -g github:xtofuub/frida-mcp-server && frida-mcp-server install
```

This installs the CLI globally, copies bundled skills to detected agent directories, and registers MCP configurations for supported clients.

---

## Detailed Installation

### 1. Install the Package

```bash
# From GitHub (latest)
npm install -g github:xtofuub/frida-mcp-server

# From local clone
cd frida-mcp-server
npm install -g .
```

### 2. Run the Installer

```bash
frida-mcp-server install
```

The installer will:
1. Copy bundled skills to all detected agent directories (`~/.claude/skills/`, `~/.cursor/skills/`, `~/.config/opencode/skills/`, etc.)
2. Register MCP server configurations in each agent's config file
3. Print the current stdio MCP config for verification

### 3. Verify Setup

```bash
frida-mcp-server doctor
```

This checks:
- Server file exists
- CLI file exists
- Bundled skills are present
- Python executable works
- Required Python packages (`frida`, `mcp`) are importable

### 4. Install Python Dependencies

```bash
pip install frida frida-tools mcp
```

### 5. Start Frida Server on Device

```bash
# On your jailbroken iOS device (via SSH)
./frida-server &

# Or via USB on macOS
iproxy 27042 27042 &
```

### Agent-Specific Installation

| Agent | Command |
| --- | --- |
| Claude Code | `npm install -g github:xtofuub/frida-mcp-server && frida-mcp-server install --claude-code` |
| Claude Desktop | `npm install -g github:xtofuub/frida-mcp-server && frida-mcp-server install` |
| OpenCode | `npm install -g github:xtofuub/frida-mcp-server && frida-mcp-server install` |
| Cursor | `npm install -g github:xtofuub/frida-mcp-server && frida-mcp-server install` |
| Codex | `npm install -g github:xtofuub/frida-mcp-server && frida-mcp-server install` |

---

## Requirements

| Requirement | Details |
| --- | --- |
| **Python** | 3.10+ |
| **Python packages** | `frida`, `frida-tools`, `mcp` |
| **Node.js** | 18+ |
| **iOS device** | Jailbroken, with `frida-server` running |
| **Connection** | USB (recommended) or network access to device |
| **Authorization** | Explicit permission to test the target app |

### Frida Server Setup

1. Download the matching `frida-server` for your device architecture from [frida releases](https://github.com/frida/frida/releases)
2. SSH into your device and make it executable: `chmod +x frida-server`
3. Run it: `./frida-server &`
4. Verify from your host: `frida-ps -U`

---

## CLI Commands

| Command | What it does |
| --- | --- |
| `frida-mcp-server install` | Install bundled skills + register MCP configs for detected clients |
| `frida-mcp-server register` | Register MCP configs without copying skills |
| `frida-mcp-server serve` | Start the Python MCP server over stdio |
| `frida-mcp-server config` | Print the stdio MCP configuration JSON |
| `frida-mcp-server path` | Print the absolute path to `frida_mcp_server.py` |
| `frida-mcp-server doctor` | Check local runtime prerequisites |
| `frida-mcp-server help` | Show help text |

### Install Options

| Flag | Description |
| --- | --- |
| `--force`, `-f` | Overwrite existing installed skill directories |
| `--no-config` | Skip MCP config registration |
| `--no-skills` | Skip bundled skill installation |
| `--claude-code` | Force Claude Code CLI registration attempt |
| `--dry-run` | Show what would be installed without writing files |

### Environment Variables

| Variable | Description | Default |
| --- | --- | --- |
| `FRIDA_MCP_PYTHON` | Python executable used by MCP configs | `python` (win32) / `python3` (other) |

---

## MCP Configuration

### Standard MCP Config

Add this to your agent's MCP configuration:

```json
{
  "mcpServers": {
    "frida": {
      "command": "frida-mcp-server",
      "args": ["serve"]
    }
  }
}
```

### OpenCode Config

```jsonc
{
  "mcp": {
    "frida": {
      "type": "local",
      "command": ["python3", "frida_mcp_server.py"],
      "enabled": true
    }
  }
}
```

### SSE Transport (Remote)

```bash
frida-mcp-server serve --transport sse --port 8099
```

---

## Tool Categories

The server exposes **64 tools** across 13 categories. See [TOOLS.md](TOOLS.md) for the complete reference.

### Connection (5 tools)
`apps`, `connect`, `spawn`, `sessions`, `disconnect`

### App Info (2 tools)
`info`, `modules`

### Network Capture (6 tools)
`requests`, `request`, `monitor`, `search`, `ws_frames`, `har_export`

### Request Replay & Interception (10 tools)
`replay`, `replay_as`, `race`, `diff`, `intercept`, `intercept_match`, `intercepts`, `intercept_toggle`, `intercept_rm`, `intercept_logs`

### Security Analysis (4 tools)
`scan`, `fuzz`, `endpoints`, `jwt`

### Attack Surface (6 tools)
`schemes`, `open_url`, `entitlements`, `pasteboard`, `memory`, `strings`

### Storage (10 tools)
`defaults`, `defaults_set`, `keychain`, `cookies`, `files`, `read`, `pull`, `push`, `sqlite`, `sqlite_query`

### Objective-C Runtime (6 tools)
`classes`, `methods`, `instances`, `inspect`, `call`, `exec`

### Swift Runtime (3 tools)
`swift_modules`, `swift_classes`, `swift_methods`

### WebViews & Bridges (3 tools)
`webviews`, `webview_eval`, `jsbridge`

### Method Tracing (4 tools)
`trace`, `trace_logs`, `traces`, `trace_stop`

### Binary Dump (1 tool)
`dump`

### Crypto & Logs (4 tools)
`crypto`, `crypto_logs`, `logs`, `logs_drain`

### Bypasses (2 tools)
`ssl_unpin`, `jb_bypass`

---

## Common Workflows

### Connect and Capture Traffic

```
connect("com.example.app")
requests(count=100)
```

### Inspect and Replay a Request

```
requests(count=50)
request(index=0)
replay(index=0, headers={"Authorization": "Bearer test-token"})
```

### Intercept and Modify In-Flight

```
intercept(pattern="/api/user", set_body='{"admin":true}')
# Use the app — matching requests are modified automatically
intercept_logs()
intercept_rm()
```

### Scan for Vulnerabilities

```
fuzz(index=0, target="query:id", payload_set="sqli")
fuzz(index=0, target="body", payload_set="xss")
scan(count=100)
```

### Browse Storage

```
keychain()
cookies()
defaults()
sqlite()
sqlite_query(path="/path/to/cache.db", sql="SELECT * FROM cache")
```

### Decrypt Binary

```
dump(output_path="./decrypted.ipa")
```

### Trace a Method

```
classes(search="Auth")
methods(class_name="AuthManager")
trace(class_name="AuthManager", selector="- loginWithToken:")
trace_logs()
trace_stop()
```

### SSL Unpin + Capture

```
connect("com.example.app")
ssl_unpin(enable=true)
requests(count=100)
```

### JWT Analysis

```
jwt(token="eyJ...")
```

### IDOR / BOLA in Two Calls

```
replay_as(index=0, auth="Bearer <user_b_token>")
diff(a_index=0, b_index=<latest>)
```

### Race Condition Probe

```
race(index=0, n=20, delay_ms=0)
# inspect by_status — multiple 200s on a "redeem once" endpoint = abuse
```

### Export Capture to HAR

```
har_export(output_path="./capture.har", count=500)
```

### WebView Inspection

```
webviews()
webview_eval(js="document.cookie")
jsbridge()
```

### Memory Scan for Secrets

```
memory(pattern="api_key", encoding="ascii")
strings(path="/path/to/Frameworks/AppBinary", min_length=20, search="password")
```

---

## Bundled Skills

The package includes an **iOS Advanced Dynamic Pentest Skill** that teaches agents how to think like mobile red teamers. It covers:

- API flow reconstruction and trust boundary analysis
- Parameter mining across all input surfaces
- Manual replication cues and replay testing
- Authorization abuse patterns (IDOR, BOLA, cross-tenant)
- Business logic abuse (price tampering, reward duplication)
- Path traversal and file access testing
- React Native / hybrid app specific techniques
- Deep link and navigation abuse
- Local storage and runtime secret extraction
- Traffic analysis methodology
- Reporting standards for high-impact findings

The skill is automatically installed to detected agent directories during `frida-mcp-server install`.

---

## Troubleshooting

### `frida.ServerNotRespondingError`

Ensure `frida-server` is running on the device and accessible via USB or network:
```bash
frida-ps -U
```

### `ModuleNotFoundError: No module named 'frida'`

Install Python dependencies:
```bash
pip install frida frida-tools mcp
```

### Session dies after app crash

The server auto-detects dead sessions and cleans them up. Simply call `connect()` again to start a fresh session.

### Network capture shows no requests

- Ensure the app uses `NSURLSession` (most do). Apps using raw sockets or custom TLS stacks won't be captured.
- Call `connect()` first — network hooks are installed automatically on connect.
- Try `monitor()` to establish a baseline, then interact with the app.

### SSL pinning still blocking

Some apps use additional pinning layers beyond NSURLSession. Try:
```
ssl_unpin(enable=true)
# If still blocked, try tracing the pinning class:
classes(search="Pinning")
trace(class_name="<ClassName>", selector="<selector>")
```

### `doctor` reports missing packages

```bash
pip install --upgrade frida frida-tools mcp
frida-mcp-server doctor
```

---

## Repository Layout

```
frida-mcp-server/
├── bin/
│   └── cli.js                  # Node.js CLI wrapper (install, serve, doctor, etc.)
├── skills/
│   └── ios-advanced-pentest/
│       └── SKILL.md            # Bundled pentest methodology skill
├── docs/                       # Additional documentation
├── frida_mcp_server.py          # Python MCP server (pure Frida, 64 tools)
├── TOOLS.md                    # Complete tool reference with examples
├── README.md                   # This file
├── package.json                # npm package manifest
├── mcp.config.example.jsonc    # Example MCP configuration
└── LICENSE                     # MIT License
```

---

## License

MIT

# flex-mcp-server

`flex-mcp-server` is a local MCP server for authorized iOS app inspection with [Frida](https://frida.re) and [FLEX](https://github.com/Flipboard/FLEX). It exposes 60+ `flex_*` tools for attaching to apps, driving the UI, capturing and replaying traffic, fuzzing requests, scanning for common mobile API issues, browsing storage, tracing Objective-C methods, dumping binaries, and installing common SSL or jailbreak bypass hooks.

The repo also bundles an MCP-aware `reverse-engineering-ios-app-with-frida` skill so compatible agents can use the server with a guided mobile security workflow.

Use this only on apps, devices, and programs where you have explicit authorization.

## Quick Install

After you have installed the required Python packages yourself, install the npm package and run the installer. The installer copies the bundled skill and registers the MCP server for detected clients.

### All Detected Clients

```bash
npm install -g github:xtofuub/flex-mcp-server && flex-mcp-server install
```

### Agent Presets

Use one of these when you want to force setup for a specific agent, even on a fresh machine where that agent's folder may not exist yet.

| Agent | macOS/Linux one-liner |
| --- | --- |
| Claude Code | `npm install -g github:xtofuub/flex-mcp-server && flex-mcp-server install --claude-code` |
| Claude Desktop | `mkdir -p "$HOME/Library/Application Support/Claude" && npm install -g github:xtofuub/flex-mcp-server && flex-mcp-server install` |
| OpenCode | `mkdir -p ~/.config/opencode && npm install -g github:xtofuub/flex-mcp-server && flex-mcp-server install` |
| Cursor | `mkdir -p ~/.cursor && npm install -g github:xtofuub/flex-mcp-server && flex-mcp-server install` |
| Codex | `mkdir -p ~/.codex && npm install -g github:xtofuub/flex-mcp-server && flex-mcp-server install` |

Windows Command Prompt:

```cmd
npm install -g github:xtofuub/flex-mcp-server && flex-mcp-server install
```

Windows PowerShell presets:

```powershell
# Claude Desktop
New-Item -ItemType Directory -Force "$env:APPDATA\Claude"; npm install -g github:xtofuub/flex-mcp-server; if ($LASTEXITCODE -eq 0) { flex-mcp-server install }

# OpenCode
New-Item -ItemType Directory -Force "$HOME\.config\opencode"; npm install -g github:xtofuub/flex-mcp-server; if ($LASTEXITCODE -eq 0) { flex-mcp-server install }

# Cursor
New-Item -ItemType Directory -Force "$HOME\.cursor"; npm install -g github:xtofuub/flex-mcp-server; if ($LASTEXITCODE -eq 0) { flex-mcp-server install }

# Codex
New-Item -ItemType Directory -Force "$HOME\.codex"; npm install -g github:xtofuub/flex-mcp-server; if ($LASTEXITCODE -eq 0) { flex-mcp-server install }

# Claude Code
npm install -g github:xtofuub/flex-mcp-server; if ($LASTEXITCODE -eq 0) { flex-mcp-server install --claude-code }
```

On Linux, Claude Desktop-style config uses `~/.config/Claude` instead of the macOS Application Support path:

```bash
mkdir -p ~/.config/Claude && npm install -g github:xtofuub/flex-mcp-server && flex-mcp-server install
```

### Any MCP client

If you installed the package but skipped the installer, run:

```bash
flex-mcp-server install
```

The installer writes config entries for detected supported clients and also prints the exact stdio MCP config for manual setup:

```json
{
  "mcpServers": {
    "frida-flex": {
      "command": "flex-mcp-server",
      "args": ["serve"]
    }
  }
}
```

To install the package without touching local agent folders or MCP configs, only run the npm half:

```bash
npm install -g github:xtofuub/flex-mcp-server
```

If your system uses `python3` instead of `python`, set the launcher before running the installer:

```bash
FLEX_MCP_PYTHON=python3 flex-mcp-server install
```

## Requirements

- Python 3.10+
- Python packages installed in the Python environment used by the MCP server:
  - `frida`
  - `frida-tools`
  - `mcp`
- Node.js 18+
- A jailbroken iOS device with `frida-server` running, or an app build with Frida Gadget injected
- USB access to the device from the machine running the MCP server
- Optional: FLEXing or a FLEX-enabled app build for the visual FLEX toolbar and FLEX network recorder

This repo intentionally does not ship or auto-install a `requirements.txt`. Frida client versions often need to match the `frida-server` or Frida Gadget version in your lab, so install the Python packages yourself with the versions that fit your device setup.

Quick sanity checks:

```bash
python -c "import frida, mcp; print('Python deps OK')"
frida-ls-devices
```

## Local Development Install

Clone the repo and run the installer from source:

```bash
git clone https://github.com/xtofuub/flex-mcp-server.git
cd flex-mcp-server
npm install
node bin/cli.js install
```

For a source checkout, the installer prints a config that points at the local `flex_mcp_server.py` path.

## CLI

```bash
flex-mcp-server install          # install bundled skills and register detected MCP configs
flex-mcp-server install --force  # overwrite existing skill installs
flex-mcp-server install --claude-code
flex-mcp-server register         # register detected MCP configs without copying skills
flex-mcp-server install --no-config
flex-mcp-server install --no-skills
flex-mcp-server serve            # start the MCP server over stdio
flex-mcp-server config           # print the MCP config for this install
flex-mcp-server path             # print the Python server path
flex-mcp-server doctor           # check Python, packages, and bundled files
```

The generated MCP configs use the Python launcher and absolute `flex_mcp_server.py` path for reliability. `flex-mcp-server serve` is also available when you want a command-based config.

## Automatic Config Registration

The installer updates the clients it can detect on the current machine:

| Client | Registration behavior |
| --- | --- |
| Claude Code | Runs `claude mcp add frida-flex flex-mcp-server serve` if the `claude` CLI is available. |
| Claude Desktop | Updates `claude_desktop_config.json` when the Claude config directory exists. |
| Cursor | Updates `~/.cursor/mcp.json` when `~/.cursor` exists. |
| OpenCode | Updates or creates `~/.config/opencode/opencode.json` when `opencode` is on PATH or an OpenCode config directory exists. Skills install to `~/.config/opencode/skills/`. |
| Codex | Updates `~/.codex/config.toml` when `~/.codex` exists. |

Existing config files get a timestamped `.bak-*` backup before they are changed. Unsupported clients still get the bundled skill when their skill directory is detected, but their MCP config may need manual setup.

## Remote SSE Mode

Stdio is safest for local clients. If you need to run the server on a lab host and connect remotely, start SSE mode on the host:

```bash
flex-mcp-server serve --transport sse --host 127.0.0.1 --port 8099
```

Then forward the port from your workstation:

```bash
ssh -L 8099:localhost:8099 user@lab-host
```

Remote MCP config:

```json
{
  "mcp": {
    "frida-flex": {
      "type": "remote",
      "url": "http://localhost:8099/sse"
    }
  }
}
```

Do not expose the SSE port to an untrusted network. The server can execute Frida JavaScript inside the target app.

## What The Install Gives Your Agent

The npm install flow gives supported agents two things:

1. A `frida-flex` MCP server that exposes the `flex_*` tools below.
2. The bundled `reverse-engineering-ios-app-with-frida` skill, copied into detected agent skill directories.

The MCP gives the agent callable tools. The skill gives the agent pentest strategy, ordering, checklists, and bug bounty playbooks for using those tools coherently.

## Bundled Skill

Installed skill:

| Skill | Description |
| --- | --- |
| `reverse-engineering-ios-app-with-frida` | Guides authorized iOS reverse engineering and mobile pentest work with Frida, FLEX, runtime tracing, traffic analysis, storage review, crypto inspection, bypass hooks, and binary dumping. |

Skill references included:

| Reference | What it gives the agent |
| --- | --- |
| `references/mcp-integration.md` | Full `flex_*` MCP tool map with parameters and suggested usage. |
| `references/bugbounty-playbooks.md` | End-to-end mobile bug bounty playbooks for recon, auth, IDOR, injection, deep links, secrets, crypto, persistence, interception, and anti-tamper testing. |
| `references/owasp-mobile-top10.md` | OWASP Mobile Top 10 checks mapped to concrete Frida/FLEX workflows. |
| `references/masvs-checklist.md` | MASVS-style verification checklist with tool-driven checks. |
| `references/workflows.md` | General Frida iOS reversing workflows. |
| `references/api-reference.md` | Raw Frida CLI and JavaScript API fallback notes. |
| `references/standards.md` | Security testing standards context. |
| `scripts/agent.py` and `scripts/process.py` | Helper scripts packaged with the skill for agent workflows. |

## MCP Tools

All tools return a dictionary with `success` plus tool-specific fields. Most tools accept optional `session_id`; when omitted, the most recent session is used.

### Connection

| Tool | Description |
| --- | --- |
| `flex_list_apps()` | Enumerate installed apps visible to Frida. |
| `flex_connect(bundle_id)` | Attach to an app by bundle id, or spawn it if attach fails. |
| `flex_spawn(bundle_id)` | Force-start a fresh app process and attach. |
| `flex_sessions()` | List active MCP sessions. |
| `flex_disconnect(session_id)` | Detach from one session or the current session. |

### FLEX UI And App Info

| Tool | Description |
| --- | --- |
| `flex_show(session_id)` | Show the FLEX toolbar in the target app. |
| `flex_hide(session_id)` | Hide the FLEX toolbar. |
| `flex_app_info(session_id)` | Return bundle id, version, build, paths, and runtime context. |
| `flex_modules(search, limit, session_id)` | List loaded Mach-O modules. |

### UI Automation

| Tool | Description |
| --- | --- |
| `flex_ui_tree(max_depth, include_hidden, max_nodes, session_id)` | Return the UIKit view tree with object ids, class names, text/accessibility fields, visibility, enabled state, and best-effort screen frames. |
| `flex_ui_find(query, class_name, include_hidden, max_depth, limit, session_id)` | Search the UI tree by text, accessibility label/identifier/value, placeholder, title, or class. |
| `flex_ui_tap(element_id, text, x, y, include_hidden, session_id)` | Activate a view by tree id, text query, or coordinate hit-test. Prefers accessibility and `UIControl` actions over raw touch injection. |
| `flex_ui_type_text(element_id, text, query, clear, session_id)` | Set or insert text into a UIKit text input found by id or semantic query. |
| `flex_ui_scroll(element_id, direction, amount, session_id)` | Scroll a target `UIScrollView`, or the first visible scroll view if no id is provided. |

### Network Capture

| Tool | Description |
| --- | --- |
| `flex_network(enable, session_id)` | Toggle FLEX network recording. |
| `flex_requests(count, session_id)` | List captured network requests. |
| `flex_request_details(index, max_body_bytes, session_id)` | Return request and response headers plus body snippets. |
| `flex_search_requests(keyword, search_bodies, session_id)` | Search captured URLs, headers, and optionally bodies. |
| `flex_monitor(session_id)` | Poll for new network transactions since the last call. |

### Replay And Interception

| Tool | Description |
| --- | --- |
| `flex_replay_request(index, method, url, headers, body, session_id)` | Replay a captured request with optional method, URL, header, or body overrides. |
| `flex_intercept_add(...)` | Add a URL pattern or regex rule that can rewrite method, URL, headers, and body in flight. |
| `flex_intercept_list(session_id)` | List active interception rules. |
| `flex_intercept_toggle(rule_id, enabled, session_id)` | Enable or disable an interception rule. |
| `flex_intercept_remove(rule_id, session_id)` | Remove one interception rule, or all rules when no id is passed. |
| `flex_intercept_logs(limit, clear, session_id)` | Read the interception modification log. |

### Fuzzing And Scanning

| Tool | Description |
| --- | --- |
| `flex_scan_vulnerabilities(count, session_id)` | Scan captured traffic for common mobile API issues and secret leaks. |
| `flex_fuzz_request(index, target, payload_set, session_id)` | Replay a request with payload sets for SQLi, XSS, traversal, command injection, NoSQL, IDOR, auth bypass, or buffer overflow probes. |
| `flex_endpoints_map(count, session_id)` | Group captured traffic by host and path, then summarize endpoint coverage. |
| `flex_decode_jwt(token)` | Decode a JWT and flag weak algorithms or missing claims. |

### Attack Surface

| Tool | Description |
| --- | --- |
| `flex_url_schemes(session_id)` | Read URL schemes and associated domains. |
| `flex_open_url(url, session_id)` | Open a URL through `UIApplication` to test deep links. |
| `flex_entitlements(session_id)` | Dump app entitlements, app groups, keychain groups, and related signing flags. |
| `flex_pasteboard(session_id)` | Read the general pasteboard. |
| `flex_memory_scan(pattern, encoding, max_hits, session_id)` | Search process memory for ASCII or hex patterns. |
| `flex_strings(path, min_length, max_results, search, local, session_id)` | Extract printable strings from a local or device-side binary. |
| `flex_logs(enable, session_id)` | Install or remove NSLog and `os_log` capture hooks. |
| `flex_log_events(limit, clear, session_id)` | Read captured log events. |

### Storage

| Tool | Description |
| --- | --- |
| `flex_userdefaults(search, session_id)` | Read `NSUserDefaults`, optionally filtered by search text. |
| `flex_set_userdefault(key, value, session_id)` | Write a value to `NSUserDefaults`. |
| `flex_keychain(session_id)` | Dump generic password keychain items visible to the app. |
| `flex_cookies(session_id)` | Read `NSHTTPCookieStorage`. |
| `flex_files(path, session_id)` | List sandbox files. |
| `flex_read_file(path, max_bytes, session_id)` | Read a UTF-8 file from the sandbox. |
| `flex_pull_file(device_path, output_path, max_size, session_id)` | Pull a binary-safe file from the device to the host. |
| `flex_sqlite_list(session_id)` | Discover SQLite databases in the app sandbox. |
| `flex_sqlite_query(path, sql, limit, session_id)` | Query a SQLite database through the app process. |

### Objective-C Runtime

| Tool | Description |
| --- | --- |
| `flex_list_classes(search, limit, session_id)` | Search loaded Objective-C classes. |
| `flex_methods(class_name, include_inherited, session_id)` | List methods for a class. |
| `flex_instances(class_name, limit, session_id)` | Find live heap instances of a class. |
| `flex_inspect(target, session_id)` | Inspect a class, pointer, or object. |
| `flex_call(target, selector, args, session_id)` | Invoke an Objective-C selector with typed arguments. |
| `flex_execute(js_code, session_id)` | Run raw Frida JavaScript as an escape hatch. |

### Method Tracing

| Tool | Description |
| --- | --- |
| `flex_trace_start(class_name, selector, scope, session_id)` | Hook a method and buffer calls, arguments, returns, and errors. |
| `flex_trace_logs(hook_id, limit, clear, session_id)` | Read trace events. |
| `flex_trace_list(session_id)` | List active trace hooks. |
| `flex_trace_stop(hook_id, session_id)` | Stop one trace hook, or all trace hooks when no id is passed. |

### Binary Dumping

| Tool | Description |
| --- | --- |
| `flex_dump_binary(output_path, module_name, session_id)` | Dump and patch the encrypted running Mach-O slice, similar to frida-ios-dump. |

### Bypasses And Crypto

| Tool | Description |
| --- | --- |
| `flex_ssl_unpin(enable, session_id)` | Install or remove common SSL pinning bypass hooks. |
| `flex_jailbreak_bypass(enable, session_id)` | Hide common jailbreak indicators from the target app. |
| `flex_crypto_hooks(enable, session_id)` | Capture CommonCrypto key, IV, input, and output events. |
| `flex_crypto_logs(limit, clear, session_id)` | Read captured crypto events. |

See [docs/TOOLS.md](docs/TOOLS.md) for additional workflow examples.

## Basic Workflow

```text
flex_list_apps()
flex_connect("com.example.target")
flex_network(true)
# Use the app: log in, browse, trigger sensitive flows.
flex_requests(count=100)
flex_scan_vulnerabilities(count=100)
```

Replay and mutate a captured request:

```text
flex_request_details(index=12)
flex_replay_request(index=12, headers={"Authorization": "Bearer <test-token>"})
flex_fuzz_request(index=12, target="body.email", payload_set="sqli")
```

Inspect local storage:

```text
flex_keychain()
flex_cookies()
flex_userdefaults()
flex_sqlite_list()
```

Trace runtime behavior:

```text
flex_list_classes(search="Auth")
flex_methods(class_name="AuthManager")
flex_trace_start(class_name="AuthManager", selector="- loginWithToken:")
flex_trace_logs(clear=true)
```

Autonomous UI plus traffic loop:

```text
flex_connect("com.example.target")
flex_network(true)
flex_ui_tree(max_depth=8)
flex_ui_find(query="login")
flex_ui_tap(text="Login")
flex_ui_type_text(query="email", text="researcher@example.com")
flex_ui_type_text(query="password", text="<test-password>")
flex_ui_tap(text="Sign In")
flex_monitor()
flex_scan_vulnerabilities(count=200)
flex_request_details(index=12)
flex_replay_request(index=12, headers={"Authorization": "Bearer <test-token>"})
flex_fuzz_request(index=12, target="body.email", payload_set="sqli")
```

The agent decides what to press from the structured UI tree: visible labels, accessibility metadata, control class, enabled state, and frame. It should prefer semantic identifiers over coordinates, then use network capture/replay/fuzzing only inside your authorized test scope.

## Repository Layout

```text
.
|-- bin/cli.js                  # Node wrapper used by npm and MCP clients
|-- docs/TOOLS.md               # Full MCP tool reference
|-- skills/                     # Bundled agent skill and references
|-- flex_mcp_server.py          # Python FastMCP server
|-- mcp.config.example.jsonc    # Example stdio MCP config
|-- package.json                # npm package metadata
`-- README.md
```

## Troubleshooting

Run:

```bash
flex-mcp-server doctor
```

Common fixes:

- `No USB device found`: start `frida-server` on the device and confirm USB pairing.
- `ModuleNotFoundError: frida` or `mcp`: install those packages into the Python environment used by `flex-mcp-server`; choose Frida versions that match your device-side Frida setup.
- `Cannot find module ... bin\cli.js` from an older failed install: remove the broken global package folder and command shims, reinstall, then run `flex-mcp-server install`.
- `FastMCP.run() got an unexpected keyword argument 'host'`: upgrade to the latest GitHub package. SSE host and port are now applied through FastMCP settings before `run()`.
- MCP client starts but no tools appear: confirm the client config points to `flex-mcp-server serve` or to the absolute `flex_mcp_server.py` path printed by `flex-mcp-server config`.
- FLEX toolbar tools fail: install FLEX/FLEXing in the target app. Frida-only tools still work without FLEX.

## License

This project is MIT licensed. The bundled skill and upstream tools retain their own licenses.

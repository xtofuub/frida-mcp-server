# flex-mcp-server

MCP server for controlling the [FLEX](https://github.com/Flipboard/FLEX) debugger on jailbroken iOS devices via [Frida](https://frida.re). Runs locally or remotely over SSE.

## Requirements

- Jailbroken iPhone with [FLEXing](https://github.com/NSExceptional/FLEXing) .deb installed (from Cydia/Sileo)
- iPhone connected via USB
- Python 3.10+ with `frida-tools` (`pip install frida-tools`)
- The `mcp` and `frida` Python packages (`pip install mcp frida`)

## Quick Start

```bash
# 1. Connect your iPhone via USB
# 2. Verify Frida sees it
frida-ls-devices

# 3. Run the MCP server
python flex_mcp_server.py
```

The server speaks STDIO by default — configure your MCP client to launch it:

### OpenCode

Add to `~/.config/opencode/opencode.jsonc`:

```json
{
  "mcp": {
    "frida-flex": {
      "type": "local",
      "command": [
        "python",
        "/path/to/flex-mcp-server/flex_mcp_server.py"
      ],
      "enabled": true
    }
  }
}
```

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "frida-flex": {
      "command": "python",
      "args": ["/path/to/flex-mcp-server/flex_mcp_server.py"]
    }
  }
}
```

### Cursor

Add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "frida-flex": {
      "command": "python",
      "args": ["/path/to/flex-mcp-server/flex_mcp_server.py"]
    }
  }
}
```

## Remote Access (SSE)

Run the server on the machine with the iPhone:

```bash
python flex_mcp_server.py --transport sse --port 8099
```

Tunnel from another machine:

```bash
ssh -L 8099:localhost:8099 user@host
```

Configure the remote client:

```json
{
  "mcp": {
    "frida-flex": {
      "type": "remote",
      "url": "http://localhost:8099/sse",
      "enabled": true
    }
  }
}
```

## Tools

| Tool | Description |
|------|-------------|
| `flex_connect` | Connect to the target iOS app via Frida. Auto-spawns if not running. |
| `flex_show` | Show the FLEX toolbar on the device. |
| `flex_hide` | Hide the FLEX toolbar. |
| `flex_network` | Enable or disable FLEX network request capture. |
| `flex_requests` | List all captured network requests (method, URL, status, timing). |
| `flex_request_body` | Get the full cached response body of a specific transaction. |
| `flex_search_requests` | Search captured requests by keyword in the URL. |
| `flex_find_credits` | Search all transactions (URLs + response bodies) for credit/financial terms. |
| `flex_monitor` | Poll for new transactions since the last check — useful for live interception. |
| `flex_userdefaults` | Browse the app's NSUserDefaults with optional keyword filter. |
| `flex_set_userdefault` | Set a value in the app's NSUserDefaults. |
| `flex_execute` | Execute arbitrary JavaScript in the app process via Frida. |
| `flex_list_classes` | List Objective-C classes matching a search term. |
| `flex_spawn` | Force-restart the target app with Frida attached. |
| `flex_disconnect` | Disconnect the Frida session. |

## Typical Workflow

1. `flex_connect` — attach to the iOS app
2. `flex_show` — show the FLEX toolbar on device
3. `flex_network` — enable network capture
4. Navigate the app to the feature/screen you want to inspect
5. `flex_requests` — see all captured API calls
6. `flex_find_credits` — automatically search for credit/financial endpoints
7. `flex_request_body` — inspect the full response of any transaction
8. `flex_monitor` — keep polling for new transactions in real-time

## Credits

- [FLEX](https://github.com/Flipboard/FLEX) — in-app debugging tool by Flipboard
- [FLEXing](https://github.com/NSExceptional/FLEXing) — tweak that loads FLEX system-wide
- [Frida](https://frida.re) — dynamic instrumentation toolkit

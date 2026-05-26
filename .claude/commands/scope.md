---
description: Scope gate — confirm target + authorization and attach the frida MCP before any testing.
argument-hint: <bundle_id|app name> [--device UDID]
---

Scope gate for `$ARGUMENTS`. Do not test anything until this passes.

1. **Identify** the target. If ambiguous or empty, run `mcp__frida__apps` and list
   installed apps with bundle id + pid; ask the user to pick. Never default to a
   hardcoded app.
2. **Authorization check.** Confirm the user is authorized to assess this app
   (own app, client engagement, bug-bounty program in scope). If unclear, stop
   and ask. Refuse unauthorized targets.
3. **Attach.** `mcp__frida__connect(bundle_id)` — or `mcp__frida__spawn` for a
   clean launch. Report device, pid, and confirm the session with
   `mcp__frida__sessions`.
4. **Baseline.** `mcp__frida__info` + `mcp__frida__entitlements` so later phases
   have ground truth (bundle id, version, sandbox HOME, entitlements).

Output: a one-line GO/NO-GO with the confirmed bundle id and device.

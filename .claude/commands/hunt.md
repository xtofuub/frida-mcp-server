---
description: Test an iOS app for vulnerabilities across storage, network, crypto, runtime-logic, and bypass classes.
argument-hint: <bundle_id> [--mode normal|yolo] [--focus storage|network|crypto|runtime|paywall|bypass]
---

Hunt `$ARGUMENTS`. Respect the mode tiers from `/autopilot` (confirm ACTIVE +
BYPASS actions unless `--mode yolo`). Delegate deep work to the **ios-hunt**
subagent (and **ios-runtime** for the logic phase). Cover, in order, weighting
`--focus` if given.

**No UI control:** the MCP can't tap buttons. When a flow needs UI, hook/trace
first, then tell the user exactly what to press, wait for confirmation, then drain
logs and analyze.

**Passive (always):**
- `mcp__frida__scan` over captured traffic — plaintext HTTP, JWT alg=none, leaked
  API keys, CORS, cookie flags, stack traces.
- `mcp__frida__jwt` on captured tokens. `mcp__frida__strings` / `mcp__frida__dump`
  for hardcoded secrets. `mcp__frida__crypto_logs` for keys/IVs (arm
  `mcp__frida__crypto` — BYPASS tier). `mcp__frida__memory` scan for secrets.
- Storage: `keychain`, `defaults`, `cookies`, `sqlite_query`, `files`/`read` —
  tokens/PII at rest, secrets in UserDefaults vs Keychain.

**Active (tiered):**
- `mcp__frida__fuzz` ranked params — payload_set ∈ sqli, xss, idor_numeric,
  idor_uuid, path_traversal, cmd_inj, nosql, auth_bypass, buffer_overflow.
- `mcp__frida__replay` / `replay_as` — strip/swap auth for BOLA/IDOR/mass-assign.
- `mcp__frida__race` — TOCTOU on state-changing endpoints.
- `mcp__frida__intercept` / `intercept_match` — rewrite in-flight requests.
- `mcp__frida__open_url` — exercise each deep-link scheme handler.

**IAP / paywall / entitlements (tiered):** does the server enforce purchases, or
does the app trust the client? Flip local state (`defaults_set`, plist via
`files`/`read`, `keychain`), flip the gate (`gates`→`exec`), force StoreKit/receipt
validators, edit RevenueCat/Adapty caches, or rewrite the entitlement response
(`intercept_match`); then confirm whether paid data is still served. See
`skills/reverse-engineering-ios-app-with-frida/references/iap-paywall-testing.md`.

**Runtime logic (tiered — the interesting bugs):** delegate to **ios-runtime**.
- `gates(app_only=True)` ranks `BOOL`-returning decision methods (by type
  encoding, not name) + backing ivars. Names only weight the score — don't
  hardcode them; low-score methods can still be the real gate.
- `trace` a candidate → user drives the flow → `trace_logs` to see which fire.
- `exec` a return-flip (`retval.replace(ptr(1))`) or `instances`+`inspect`+`call`
  one object; re-drive the flow; **observe whether capability is gained**.
- See `skills/reverse-engineering-ios-app-with-frida/references/runtime-logic-hunting.md`.

**Bypass (tiered, defense-quality test):**
- `mcp__frida__ssl_unpin`, `mcp__frida__jb_bypass` — if trivially bypassed, that's
  a finding about defense strength.

Map every candidate to a control in
`skills/reverse-engineering-ios-app-with-frida/references/masvs-checklist.md` and
`owasp-mobile-top10.md`. Use `bugbounty-playbooks.md` for concrete chains.

For each hit, log the winning technique: `python scripts/memory.py log patterns`.
Output: candidate findings with evidence + the exact tool calls to reproduce.
Hand them to `/validate`.

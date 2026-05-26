---
description: Test an iOS app for vulnerabilities across storage, network, crypto, and bypass classes.
argument-hint: <bundle_id> [--mode normal|yolo] [--focus storage|network|crypto|bypass]
---

Hunt `$ARGUMENTS`. Respect the mode tiers from `/autopilot` (confirm ACTIVE +
BYPASS actions unless `--mode yolo`). Delegate deep work to the **ios-hunt**
subagent. Cover, in order, weighting `--focus` if given:

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

**Bypass (tiered, defense-quality test):**
- `mcp__frida__ssl_unpin`, `mcp__frida__jb_bypass` — if trivially bypassed, that's
  a finding about defense strength.

Map every candidate to a control in
`skills/reverse-engineering-ios-app-with-frida/references/masvs-checklist.md` and
`owasp-mobile-top10.md`. Use `bugbounty-playbooks.md` for concrete chains.

For each hit, log the winning technique: `python scripts/memory.py log patterns`.
Output: candidate findings with evidence + the exact tool calls to reproduce.
Hand them to `/validate`.

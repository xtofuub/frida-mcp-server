---
description: Map an attached iOS app's attack surface (passive) and rank it for hunting.
argument-hint: <bundle_id> (must already be connected, or pass to auto-connect)
---

Recon for `$ARGUMENTS`. **Passive only** — no hooks, no active requests.

Connect if not already attached (`mcp__frida__connect`). Then delegate breadth to
the **ios-recon** subagent, or run inline:

- **App**: `mcp__frida__info`, `mcp__frida__entitlements` — version, sandbox HOME,
  over-broad entitlements, app/keychain groups, associated domains.
- **Code**: `mcp__frida__modules` (3rd-party SDKs: Firebase, Stripe, auth libs),
  `mcp__frida__swift_modules`, `mcp__frida__classes` (app-owned namespaces).
- **Entry points**: `mcp__frida__schemes` (deep links), `mcp__frida__webviews`.
- **Traffic so far**: `mcp__frida__endpoints`, `mcp__frida__requests` — hosts,
  paths, auth style.
- **Storage map**: `mcp__frida__files`, `mcp__frida__sqlite` (locations only).

**Rank** the surface for the next phase. Weight by `patterns.jsonl`
(`python scripts/memory.py query patterns`) — endpoint shapes / techniques that
produced findings on past targets float to the top.

Output: a ranked attack-surface table (surface, why it ranks, suggested tools)
and the ATS / entitlement red flags.

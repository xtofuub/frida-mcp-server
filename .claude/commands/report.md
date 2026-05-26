---
description: Write an impact-first iOS assessment report from the validated findings.
argument-hint: <bundle_id> [--out ./reports/<id>.md]
---

Report for `$ARGUMENTS`. Delegate to the **ios-reporter** subagent. Source the
validated findings from `python scripts/memory.py query audit --bundle <id>`.

Use `skills/reverse-engineering-ios-app-with-frida/assets/template.md` as the
structure. For each finding include:

- Title, MASVS control, severity.
- **Impact first** — what an attacker gains.
- **Reproduction** — the exact `mcp__frida__*` call sequence.
- **Evidence** — captured request/response, file path + contents, key/IV, trace.
- **Remediation** — concrete iOS fix (Keychain w/ proper accessibility, cert
  pinning, server-side authz, remove debug flags).

Open with an executive summary (target, scope, date, finding counts by severity)
and a coverage note mapping which MASVS/OWASP-MASVS controls were exercised.

Write to `--out` (default `./reports/<bundle_id>-<date>.md`). Output the path and
the severity breakdown.

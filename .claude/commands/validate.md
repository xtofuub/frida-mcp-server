---
description: Gate candidate findings — kill weak ones, keep only reproducible, MASVS-mapped issues.
argument-hint: <bundle_id> (operates on the current hunt's candidates)
---

Validate the candidate findings for `$ARGUMENTS`. Delegate to the
**ios-validator** subagent. Every candidate must clear the **7-question gate**:

1. **Reproducible?** Re-run the exact `mcp__frida__*` calls — does it trigger again?
2. **Real impact?** Concrete attacker capability, not theoretical.
3. **In scope / app's fault?** Not OS behavior, not a deliberate debug build artifact.
4. **Attacker-reachable?** Reachable without already owning the device/root, or
   state the precondition honestly.
5. **Not a duplicate?** Check `python scripts/memory.py query audit --bundle <id>`.
6. **Evidence captured?** Request/response, file contents, key material, or trace.
7. **MASVS-mapped?** Tie to a control in `references/masvs-checklist.md`; assign
   severity (🔴/🟠/🟡/🟢).

Drop anything that fails. For survivors, write the validated record:
`python scripts/memory.py log audit --bundle <id> --json '{...}'`.

Output: a kept/killed table with the reason for each kill, and the validated set
ready for `/report`.

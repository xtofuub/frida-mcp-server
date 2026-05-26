---
description: Resume an assessment from hunt-memory — skip done work, go straight to untested surface.
argument-hint: <bundle_id> [--mode normal]
---

Resume the assessment of `$ARGUMENTS` using prior memory. Do **not** re-run
recon/hunt that already produced results.

1. Load state: `python scripts/memory.py resume --bundle <id>`. This returns prior
   validated findings, winning patterns, and the **untested** attack surface
   recorded in the last session's journal.
2. Re-attach: `mcp__frida__connect(<id>)`. Confirm scope (target unchanged,
   still authorized).
3. Summarize for the user: what was already found, what's still untested.
4. Drive `/hunt` straight at the untested surface, in priority order, applying
   the winning patterns first.
5. Validate new candidates (`/validate`), append to `audit.jsonl`, and update the
   journal with remaining untested items.

If memory is empty for this target, say so and fall back to `/autopilot <id>`.

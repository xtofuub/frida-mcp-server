# MASVS v2 Checklist → MCP Tool Mapping

Maps each Mobile Application Security Verification Standard (MASVS) v2 control to the exact `flex_*` invocation that verifies it. Severity: 🔴 critical / 🟠 high / 🟡 medium / 🟢 informational.

---

## MASVS-STORAGE

| Control | Description | Tool chain |
|---|---|---|
| 🔴 1.1 | App stores sensitive data only in intended, secure locations | `flex_files` + `flex_sqlite_list` + `flex_sqlite_query` — check Documents/Caches for tokens, PII |
| 🟠 1.2 | Sensitive data is not exposed via IPC | `flex_url_schemes` + `flex_open_url` — confirm scheme handlers don't leak data |

## MASVS-CRYPTO

| Control | Description | Tool chain |
|---|---|---|
| 🔴 2.1 | App relies on platform-provided crypto | `flex_crypto_hooks` — see CCCrypt usage |
| 🟠 2.2 | App uses strong primitives and parameters | `flex_crypto_logs` — flag alg=1/2 (DES/3DES), key_len=8, static IVs |

## MASVS-AUTH

| Control | Description | Tool chain |
|---|---|---|
| 🔴 3.1 | App uses platform-secure auth (no homegrown) | `flex_decode_jwt` (alg=none?) + `flex_strings` for hardcoded creds |
| 🔴 3.2 | Step-up auth required for sensitive operations | `flex_replay_request` with stripped auth on sensitive endpoints |
| 🟠 3.3 | App informs the user about active sessions | (manual UI check) |
| 🟠 3.4 | Session bound to client | Replay request from new context — `flex_replay_request` with modified User-Agent/IP-spoofing header |

## MASVS-NETWORK

| Control | Description | Tool chain |
|---|---|---|
| 🔴 4.1 | App uses secure protocols only | `flex_search_requests(keyword="http://")` + `flex_scan_vulnerabilities` |
| 🔴 4.2 | App pins keys/certs for sensitive endpoints | `flex_ssl_unpin(enable=True)` — if bypass works, pinning isn't enforced |
| 🟡 4.3 | App rejects untrusted certs at runtime | Run with proxy + observe — bypass should not be trivial |

## MASVS-PLATFORM

| Control | Description | Tool chain |
|---|---|---|
| 🟠 5.1 | App uses platform-secure mechanisms | `flex_entitlements` — over-privileged entitlements? |
| 🟠 5.2 | App is well-behaved with respect to platform features | `flex_url_schemes` + `flex_open_url` for each |
| 🟡 5.3 | App restricts data leaks via UI | `flex_pasteboard` — sensitive data left in clipboard |
| 🟡 5.4 | App doesn't expose sensitive data through screen recording | `flex_strings(path=..., search="screenshot")` + UI check |
| 🟡 5.5 | App enforces a reasonable WebView config | `flex_methods("WKWebViewConfiguration")` — `javaScriptEnabled`, `allowFileAccessFromFileURLs` |
| 🟡 5.6 | App doesn't expose IPC entry points unintentionally | `flex_url_schemes` + open every scheme variant |

## MASVS-CODE

| Control | Description | Tool chain |
|---|---|---|
| 🟠 6.1 | App requires up-to-date platform versions | `flex_app_info` → check `min_os` |
| 🟠 6.2 | App has explicit handling of for crashes / errors | `flex_logs` + trigger errors |
| 🟡 6.3 | App catches and discards excessive error info | `flex_scan_vulnerabilities` — looks for stack traces in 5xx |
| 🟡 6.4 | App uses up-to-date dependencies | `flex_modules` — cross-reference advisories |

## MASVS-RESILIENCE

| Control | Description | Tool chain |
|---|---|---|
| 🟢 7.1 | App impedes static analysis | `flex_dump_binary` + `flex_strings` — too few strings = obfuscated |
| 🟢 7.2 | App impedes dynamic analysis | `flex_jailbreak_bypass(enable=True)` — does it still detect? |
| 🟢 7.3 | App impedes deobfuscation | (manual via Ghidra/Hopper on decrypted binary) |
| 🟢 7.4 | App impedes tampering | `flex_dump_binary` → modify → re-sign → check if app validates checksum |

---

## How to use this in practice

This is a coverage checklist, not a script. As the agent works through an audit, mark each control as:

- ✅ **Pass** — tool returned clean
- ❌ **Fail** — tool found an issue (save the evidence for the report)
- ⚠️ **Partial** — needs manual verification
- ➖ **N/A** — control doesn't apply

The agent's autonomous loop:

```
for control in masvs_controls:
    run tool_chain(control)
    record result + evidence
    if FAIL: drill in with playbooks/bugbounty-playbooks.md
```

After every control has been touched, produce the final report.

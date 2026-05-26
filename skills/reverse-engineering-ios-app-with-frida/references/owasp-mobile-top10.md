# OWASP Mobile Top 10 (2024) → MCP Tool Mapping

For each category, the Frida MCP tool chain that covers it. Use this as the audit's table of contents.

---

## M1 — Improper Credential Usage

Hardcoded credentials, weak token storage, exposed API keys.

```
frida_strings(path="./Target.decrypted", local=True, search="key", min_length=12)
frida_strings(path="./Target.decrypted", local=True, search="secret")
frida_strings(path="./Target.decrypted", local=True, search="password")
frida_keychain
frida_userdefaults(search="token")
frida_sqlite_query(path=..., sql="SELECT * FROM credentials")
frida_scan_vulnerabilities                # detects leaked AWS/Stripe/GitHub/etc. keys
```

## M2 — Inadequate Supply Chain Security

Outdated bundled SDKs with known CVEs.

```
frida_modules(limit=200)
# Cross-reference module names + versions against:
#   https://github.com/advisories
#   GitHub Dependabot advisories for the SDK
frida_strings(path="<framework>.decrypted", local=True, search="version")
```

## M3 — Insecure Authentication / Authorization

Token validation gaps, missing auth checks, weak session management.

```
frida_search_requests(keyword="Bearer")
frida_decode_jwt(token=...)               # alg=none, weak signing, no exp
frida_replay_request(index=N, headers={"Authorization": ""})    # auth strip test
frida_fuzz_request(index=N, target="header:Authorization", payload_set="auth_bypass")
frida_fuzz_request(index=N, target="path", payload_set="idor_numeric")
```

## M4 — Insufficient Input/Output Validation

Injection bugs, output encoding gaps.

```
frida_fuzz_request(index=N, target="query:q", payload_set="sqli")
frida_fuzz_request(index=N, target="body", payload_set="xss")
frida_fuzz_request(index=N, target="query:file", payload_set="path_traversal")
frida_fuzz_request(index=N, target="body", payload_set="cmd_inj")
frida_fuzz_request(index=N, target="body", payload_set="nosql")
```

## M5 — Insecure Communication

Plaintext channels, weak TLS, broken pinning.

```
frida_scan_vulnerabilities                # auto-detects plaintext HTTP, missing HSTS, permissive CORS
frida_search_requests(keyword="http://", search_bodies=False)   # any cleartext?
frida_ssl_unpin(enable=True)              # if pinning bypass works → pinning is software-side only
frida_requests(count=500)                  # any non-https traffic?
```

## M6 — Inadequate Privacy Controls

PII leakage in logs, analytics, third-party SDKs.

```
frida_logs(enable=True)
# ... exercise the app, especially personal data flows ...
frida_log_events(limit=500)               # look for emails, phone numbers, ids in logs
frida_endpoints_map                       # identify which third parties get traffic
frida_pasteboard                          # apps leaking sensitive data to clipboard
frida_search_requests(keyword="@", search_bodies=True)   # emails in body
frida_files(path="$HOME/Library/Caches")  # PII in cache files
```

## M7 — Insufficient Binary Protections

Lack of obfuscation, debugger detection, anti-tampering. (Generally lower severity; sometimes blocks other testing.)

```
frida_strings(path="./Target.decrypted", local=True, search="jailbreak")
frida_strings(path="./Target.decrypted", local=True, search="debug")
frida_jailbreak_bypass(enable=True)       # is the app's JB detection trivial?
frida_modules                              # look for anti-tampering frameworks (Promon, Guardsquare, etc.)
```

## M8 — Security Misconfiguration

Excessive entitlements, debug builds in production, exposed services.

```
frida_entitlements                        # get-task-allow (debuggable), shared keychain groups
frida_url_schemes                         # too many schemes is suspicious
frida_app_info                            # min_os disclosed? debug build flags?
frida_strings(path="./Target.decrypted", local=True, search="DEBUG")
frida_strings(path="./Target.decrypted", local=True, search="staging")
```

## M9 — Insecure Data Storage

Plaintext databases, world-readable files, sensitive data on disk.

```
frida_sqlite_list
frida_sqlite_query(path=..., sql="SELECT name FROM sqlite_master WHERE type='table'")
# For each table:
frida_sqlite_query(path=..., sql="SELECT * FROM <table> LIMIT 5")
frida_files(path="$HOME/Documents")
frida_files(path="$HOME/Library/Preferences")
frida_keychain                            # tokens stored in keychain (good) vs userdefaults (bad)
frida_userdefaults                        # what's stored unencrypted
```

## M10 — Insufficient Cryptography

Hardcoded keys, weak algorithms, broken IV usage.

```
frida_crypto_hooks(enable=True)
# ... exercise encryption flows ...
frida_crypto_logs(limit=500)
# Look for:
#   - alg=2 (DES) or alg=1 (3DES) → weak
#   - same key_hex across runs → hardcoded
#   - iv_hex = 00000000... → static IV (catastrophic for CBC)
#   - key_len=8 → DES
```

---

## Audit run order

The order you'd run an end-to-end MASVS-aligned audit:

1. **Recon** — `frida_app_info`, `frida_entitlements`, `frida_url_schemes`, `frida_modules`, `frida_endpoints_map`
2. **Storage** — `frida_keychain`, `frida_cookies`, `frida_userdefaults`, `frida_sqlite_*`, `frida_files`
3. **Static** — `frida_dump_binary`, `frida_strings` for hardcoded secrets
4. **Crypto** — `frida_crypto_hooks`, exercise encryption, `frida_crypto_logs`
5. **Network passive** — `frida_scan_vulnerabilities` over captured traffic
6. **Network active** — `frida_fuzz_request` against every parameter that looks server-evaluated
7. **Auth** — JWT decode, auth strip, replay, rate limit
8. **Deep links** — `frida_url_schemes` + `frida_open_url` for each
9. **Memory** — `frida_memory_scan` for secrets found in 1–4
10. **Bypass-as-a-test** — `frida_ssl_unpin`, `frida_jailbreak_bypass` to gauge defense quality

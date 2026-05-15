# OWASP Mobile Top 10 (2024) → MCP Tool Mapping

For each category, the FLEX MCP tool chain that covers it. Use this as the audit's table of contents.

---

## M1 — Improper Credential Usage

Hardcoded credentials, weak token storage, exposed API keys.

```
flex_strings(path="./Target.decrypted", local=True, search="key", min_length=12)
flex_strings(path="./Target.decrypted", local=True, search="secret")
flex_strings(path="./Target.decrypted", local=True, search="password")
flex_keychain
flex_userdefaults(search="token")
flex_sqlite_query(path=..., sql="SELECT * FROM credentials")
flex_scan_vulnerabilities                # detects leaked AWS/Stripe/GitHub/etc. keys
```

## M2 — Inadequate Supply Chain Security

Outdated bundled SDKs with known CVEs.

```
flex_modules(limit=200)
# Cross-reference module names + versions against:
#   https://github.com/advisories
#   GitHub Dependabot advisories for the SDK
flex_strings(path="<framework>.decrypted", local=True, search="version")
```

## M3 — Insecure Authentication / Authorization

Token validation gaps, missing auth checks, weak session management.

```
flex_search_requests(keyword="Bearer")
flex_decode_jwt(token=...)               # alg=none, weak signing, no exp
flex_replay_request(index=N, headers={"Authorization": ""})    # auth strip test
flex_fuzz_request(index=N, target="header:Authorization", payload_set="auth_bypass")
flex_fuzz_request(index=N, target="path", payload_set="idor_numeric")
```

## M4 — Insufficient Input/Output Validation

Injection bugs, output encoding gaps.

```
flex_fuzz_request(index=N, target="query:q", payload_set="sqli")
flex_fuzz_request(index=N, target="body", payload_set="xss")
flex_fuzz_request(index=N, target="query:file", payload_set="path_traversal")
flex_fuzz_request(index=N, target="body", payload_set="cmd_inj")
flex_fuzz_request(index=N, target="body", payload_set="nosql")
```

## M5 — Insecure Communication

Plaintext channels, weak TLS, broken pinning.

```
flex_scan_vulnerabilities                # auto-detects plaintext HTTP, missing HSTS, permissive CORS
flex_search_requests(keyword="http://", search_bodies=False)   # any cleartext?
flex_ssl_unpin(enable=True)              # if pinning bypass works → pinning is software-side only
flex_requests(count=500)                  # any non-https traffic?
```

## M6 — Inadequate Privacy Controls

PII leakage in logs, analytics, third-party SDKs.

```
flex_logs(enable=True)
# ... exercise the app, especially personal data flows ...
flex_log_events(limit=500)               # look for emails, phone numbers, ids in logs
flex_endpoints_map                       # identify which third parties get traffic
flex_pasteboard                          # apps leaking sensitive data to clipboard
flex_search_requests(keyword="@", search_bodies=True)   # emails in body
flex_files(path="$HOME/Library/Caches")  # PII in cache files
```

## M7 — Insufficient Binary Protections

Lack of obfuscation, debugger detection, anti-tampering. (Generally lower severity; sometimes blocks other testing.)

```
flex_strings(path="./Target.decrypted", local=True, search="jailbreak")
flex_strings(path="./Target.decrypted", local=True, search="debug")
flex_jailbreak_bypass(enable=True)       # is the app's JB detection trivial?
flex_modules                              # look for anti-tampering frameworks (Promon, Guardsquare, etc.)
```

## M8 — Security Misconfiguration

Excessive entitlements, debug builds in production, exposed services.

```
flex_entitlements                        # get-task-allow (debuggable), shared keychain groups
flex_url_schemes                         # too many schemes is suspicious
flex_app_info                            # min_os disclosed? debug build flags?
flex_strings(path="./Target.decrypted", local=True, search="DEBUG")
flex_strings(path="./Target.decrypted", local=True, search="staging")
```

## M9 — Insecure Data Storage

Plaintext databases, world-readable files, sensitive data on disk.

```
flex_sqlite_list
flex_sqlite_query(path=..., sql="SELECT name FROM sqlite_master WHERE type='table'")
# For each table:
flex_sqlite_query(path=..., sql="SELECT * FROM <table> LIMIT 5")
flex_files(path="$HOME/Documents")
flex_files(path="$HOME/Library/Preferences")
flex_keychain                            # tokens stored in keychain (good) vs userdefaults (bad)
flex_userdefaults                        # what's stored unencrypted
```

## M10 — Insufficient Cryptography

Hardcoded keys, weak algorithms, broken IV usage.

```
flex_crypto_hooks(enable=True)
# ... exercise encryption flows ...
flex_crypto_logs(limit=500)
# Look for:
#   - alg=2 (DES) or alg=1 (3DES) → weak
#   - same key_hex across runs → hardcoded
#   - iv_hex = 00000000... → static IV (catastrophic for CBC)
#   - key_len=8 → DES
```

---

## Audit run order

The order you'd run an end-to-end MASVS-aligned audit:

1. **Recon** — `flex_app_info`, `flex_entitlements`, `flex_url_schemes`, `flex_modules`, `flex_endpoints_map`
2. **Storage** — `flex_keychain`, `flex_cookies`, `flex_userdefaults`, `flex_sqlite_*`, `flex_files`
3. **Static** — `flex_dump_binary`, `flex_strings` for hardcoded secrets
4. **Crypto** — `flex_crypto_hooks`, exercise encryption, `flex_crypto_logs`
5. **Network passive** — `flex_scan_vulnerabilities` over captured traffic
6. **Network active** — `flex_fuzz_request` against every parameter that looks server-evaluated
7. **Auth** — JWT decode, auth strip, replay, rate limit
8. **Deep links** — `flex_url_schemes` + `flex_open_url` for each
9. **Memory** — `flex_memory_scan` for secrets found in 1–4
10. **Bypass-as-a-test** — `flex_ssl_unpin`, `flex_jailbreak_bypass` to gauge defense quality

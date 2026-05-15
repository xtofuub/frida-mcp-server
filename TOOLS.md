# Tool Reference

All tools return `{success: true/false, ...}` plus tool-specific fields. Most accept `session_id`; omitted = most recent session.

Use these tools only on apps and devices you own or are authorized to test.

## Connection

| Tool | Purpose |
| --- | --- |
| `apps` | List installed apps visible to Frida. |
| `connect(bundle_id)` | Attach to an app (spawn if needed) + install network hooks. |
| `spawn(bundle_id)` | Force-start a fresh process and attach. |
| `sessions` | List active Frida sessions (with health checks). |
| `disconnect(session_id)` | Detach + clean up hooks. |

## App Info

| Tool | Purpose |
| --- | --- |
| `info(session_id)` | Bundle ID, version, build, sandbox home. |
| `modules(session_id)` | List loaded Mach-O modules. |

## Network Capture

| Tool | Purpose |
| --- | --- |
| `requests(count, session_id)` | List captured requests (pure Frida NSURLSession hooks, no FLEX). |
| `request(index, max_body_bytes, session_id)` | Full request/response details (headers, body). |
| `monitor(session_id)` | Poll for new transactions (first call = baseline). |
| `search(keyword, search_bodies, session_id)` | Search URLs and optionally bodies. |
| `ws_frames(count, clear, session_id)` | List captured WebSocket frames (NSURLSessionWebSocketTask). |
| `har_export(output_path, count, session_id)` | Export captured requests to a HAR 1.2 file. |

## Request Replay & Interception

| Tool | Purpose |
| --- | --- |
| `replay(index, method, url, headers, body, timeout, session_id)` | Replay a request with optional overrides via NSURLSession. With `index>=0`, the captured request is loaded as a base; explicit args override its fields. |
| `replay_as(index, auth, cookie, extra_headers, timeout, session_id)` | Replay with swapped credentials. Built-in IDOR / BOLA harness. |
| `race(index, n, delay_ms, timeout, session_id)` | Fire N concurrent replays of a captured request. Surfaces business-logic abuse (double-spend, coupon reuse). |
| `diff(a_index, b_index, session_id)` | Diff two captured transactions (status, headers, body — JSON-aware). One-call IDOR confirmation. |
| `intercept(pattern, regex, method_filter, set_url, set_method, set_headers, add_headers, remove_headers, set_body, session_id)` | Add in-flight modification rule (rewrite URL, method, headers, body). |
| `intercept_match(pattern, regex, method_filter, count, session_id)` | Dry-run an intercept rule against captured traffic. Verify a pattern before installing. |
| `intercepts(session_id)` | List active intercept rules. |
| `intercept_toggle(rule_id, enabled, session_id)` | Enable/disable a rule. |
| `intercept_rm(rule_id, session_id)` | Remove one rule, or all when id is empty. |
| `intercept_logs(limit, clear, session_id)` | Read intercept modification log. |

## Security Analysis

| Tool | Purpose |
| --- | --- |
| `scan(count, session_id)` | Scan traffic for issues (plaintext HTTP, JWT weak, API key leaks, HSTS, CORS, stack traces). |
| `fuzz(index, target, payloads, payload_set, timeout_per, max_payloads, session_id)` | Fuzz requests with 8 preset payload sets. |
| `endpoints(count, session_id)` | Group traffic by host/path for attack-surface mapping. |
| `jwt(token)` | Decode a JWT and flag weak/missing claims. |

## Attack Surface

| Tool | Purpose |
| --- | --- |
| `schemes(session_id)` | Read URL schemes (CFBundleURLTypes). |
| `open_url(url, session_id)` | Open a deep link via UIApplication.openURL. |
| `entitlements(session_id)` | Dump app entitlements via SecTaskCopyValueForEntitlement. |
| `pasteboard(session_id)` | Read the general UIPasteboard. |
| `memory(pattern, encoding, max_hits, session_id)` | Scan rw- memory for ASCII or hex patterns. |
| `strings(path, min_length, max_results, search, local, session_id)` | Extract printable strings from a binary. |

## Storage

| Tool | Purpose |
| --- | --- |
| `defaults(search, session_id)` | Browse NSUserDefaults. |
| `defaults_set(key, value, session_id)` | Write a value to NSUserDefaults. |
| `keychain(session_id)` | Dump generic password keychain items (SecItemCopyMatching). |
| `cookies(session_id)` | Read NSHTTPCookieStorage. |
| `files(path, session_id)` | List sandbox directory. |
| `read(path, max_bytes, session_id)` | Read a UTF-8 file from sandbox. |
| `pull(device_path, output_path, max_size, session_id)` | Pull binary file from device to host (chunked). |
| `push(local_path, device_path, session_id)` | Upload a host file to device sandbox. |
| `sqlite(session_id)` | Find SQLite databases in sandbox. |
| `sqlite_query(path, sql, limit, session_id)` | Run SQL against a sandbox SQLite database. |

## Objective-C Runtime

| Tool | Purpose |
| --- | --- |
| `classes(search, limit, session_id)` | Search loaded ObjC classes. |
| `methods(class_name, include_inherited, session_id)` | List methods for a class. |
| `instances(class_name, limit, session_id)` | Find live heap instances. |
| `inspect(target, session_id)` | Inspect class, pointer, or object (ivars, description). |
| `call(target, selector, args, session_id)` | Invoke an ObjC selector with typed arguments. |
| `exec(js_code, session_id)` | Run arbitrary Frida JS. |

## Swift Runtime

| Tool | Purpose |
| --- | --- |
| `swift_modules(session_id)` | List Swift modules visible to Frida (requires `Swift.available`). |
| `swift_classes(search, module, limit, session_id)` | Search Swift classes by substring; optionally filter by module. |
| `swift_methods(class_name, module, session_id)` | List methods and fields of a Swift class. |

## WebViews & Bridges

| Tool | Purpose |
| --- | --- |
| `webviews(session_id)` | List live WKWebView / UIWebView instances with URL and title. |
| `webview_eval(js, address, session_id)` | Evaluate JS inside a WKWebView via `evaluateJavaScript:`. |
| `jsbridge(session_id)` | Enumerate `WKScriptMessageHandler` channels and `JSContext` exports. |

## Method Tracing

| Tool | Purpose |
| --- | --- |
| `trace(class_name, selector, session_id)` | Hook an ObjC method, buffer calls + returns. |
| `trace_logs(hook_id, limit, clear, session_id)` | Read trace events. |
| `traces(session_id)` | List active trace hooks. |
| `trace_stop(hook_id, session_id)` | Stop one or all trace hooks. |

## Binary Dump

| Tool | Purpose |
| --- | --- |
| `dump(output_path, module_name, session_id)` | Dump + patch decrypted Mach-O (frida-ios-dump style). |

## Crypto & Logs

| Tool | Purpose |
| --- | --- |
| `crypto(enable, session_id)` | Hook CommonCrypto CCCrypt — capture keys/IVs. |
| `crypto_logs(limit, clear, session_id)` | Read captured crypto events. |
| `logs(enable, session_id)` | Capture NSLog and os_log calls. |
| `logs_drain(limit, clear, session_id)` | Drain captured log buffer. |

## Bypasses

| Tool | Purpose |
| --- | --- |
| `ssl_unpin(enable, session_id)` | Install/remove SSL pinning bypass (Secure Transport + AFNetworking). |
| `jb_bypass(enable, session_id)` | Hide jailbreak indicators (file checks, URL schemes, fork). |

## Common Workflows

### Connect And Capture Traffic

```text
connect("com.example.app")
requests(count=100)
```

### Inspect a Request

```text
requests(count=50)
request(index=0)
replay(index=0, headers={"Authorization": "Bearer test-token"})
```

### Intercept and Modify

```text
intercept(pattern="/api/user", set_body='{"admin":true}')
# Now use the app — requests matching /api/user will have body replaced
intercept_logs()
intercept_rm()
```

### Scan for Vulnerabilities

```text
fuzz(index=0, target="query:id", payload_set="sqli")
fuzz(index=0, target="body", payload_set="xss")
scan(count=100)
```

### Dump Storage

```text
keychain()
cookies()
defaults()
sqlite()
sqlite_query(path="/path/to/cache.db", sql="SELECT * FROM cache")
```

### Decrypt Binary

```text
dump(output_path="./decrypted.ipa", session_id="...")
```

### Trace a Method

```text
classes(search="Auth")
methods(class_name="AuthManager")
trace(class_name="AuthManager", selector="- loginWithToken:")
trace_logs()
trace_stop()
```

### SSL Unpin + Traffic

```text
connect("com.example.app")
ssl_unpin(enable=true)
requests(count=100)
```

### JWT Analysis

```text
jwt(token="eyJ...")
```

### IDOR / BOLA in Two Calls

```text
# 1. capture user A's request, then replay as user B and diff the responses
replay_as(index=0, auth="Bearer <user_b_token>")
diff(a_index=0, b_index=<latest>)
```

### Race Condition Probe

```text
race(index=0, n=20, delay_ms=0)
# inspect by_status — multiple 200s on a "redeem once" endpoint = abuse
```

### Export Captured Traffic to HAR

```text
har_export(output_path="./capture.har", count=500)
# import into Burp / Postman / Caido
```

### WebView Inspection

```text
webviews()
webview_eval(js="document.cookie")
jsbridge()
```

### Push a File to the Device

```text
push(local_path="./payload.bin", device_path="/var/mobile/Containers/Data/Application/<UUID>/tmp/p.bin")
```

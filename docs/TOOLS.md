# Tool Reference

All tools return a JSON-like dictionary with `success` plus tool-specific fields. Most tools accept an optional `session_id`; when omitted, the most recently created session is used.

Use these tools only on apps and devices you own or are authorized to test.

## Connection

| Tool | Purpose |
| --- | --- |
| `flex_list_apps` | List installed apps visible to Frida. |
| `flex_connect(bundle_id)` | Attach to an app, or spawn it if attach fails. |
| `flex_spawn(bundle_id)` | Force-start a fresh process and attach. |
| `flex_sessions` | List active MCP sessions. |
| `flex_disconnect(session_id)` | Detach from one session or the current session. |

## FLEX UI And App Info

| Tool | Purpose |
| --- | --- |
| `flex_show` | Show the FLEX toolbar in the target app. |
| `flex_hide` | Hide the FLEX toolbar. |
| `flex_app_info` | Return bundle id, version, build, paths, and runtime context. |
| `flex_modules(search, limit)` | List loaded Mach-O modules. |

## UI Automation

| Tool | Purpose |
| --- | --- |
| `flex_ui_tree(max_depth, include_hidden, max_nodes)` | Return a structured UIKit view tree with object ids, class names, text/accessibility fields, visible/enabled state, and best-effort screen frames. |
| `flex_ui_find(query, class_name, include_hidden, max_depth, limit)` | Find UI elements by text, accessibility metadata, placeholder, title, or class name. |
| `flex_ui_tap(element_id, text, x, y, include_hidden)` | Activate an element by id, text query, or coordinate hit-test. Uses semantic UIKit actions when possible. |
| `flex_ui_type_text(element_id, text, query, clear)` | Set or insert text into a text input found by id or semantic query. |
| `flex_ui_scroll(element_id, direction, amount)` | Scroll a specific `UIScrollView`, or the first visible scroll view if no id is provided. |

## Network Capture

| Tool | Purpose |
| --- | --- |
| `flex_network(enable)` | Toggle FLEX network recording. |
| `flex_requests(count)` | List captured requests. |
| `flex_request_details(index, max_body_bytes)` | Return headers and request/response body snippets. |
| `flex_search_requests(keyword, search_bodies)` | Search captured URLs, headers, and optionally bodies. |
| `flex_monitor` | Poll for new network transactions. |

## Replay And Interception

| Tool | Purpose |
| --- | --- |
| `flex_replay_request(index, method, url, headers, body)` | Replay a captured request with optional overrides. |
| `flex_intercept_add(...)` | Add a URL pattern or regex rule that can rewrite method, URL, headers, and body. |
| `flex_intercept_list` | List active interception rules. |
| `flex_intercept_toggle(rule_id, enabled)` | Enable or disable a rule. |
| `flex_intercept_remove(rule_id)` | Remove one rule, or all rules when no id is passed. |
| `flex_intercept_logs(limit, clear)` | Read the interception modification log. |

## Fuzzing And Scanning

| Tool | Purpose |
| --- | --- |
| `flex_scan_vulnerabilities(count)` | Scan captured traffic for common mobile API issues and secret leaks. |
| `flex_fuzz_request(index, target, payload_set)` | Replay a request with payload sets for SQLi, XSS, traversal, command injection, NoSQL, IDOR, auth bypass, or buffer overflow probes. |
| `flex_endpoints_map(count)` | Group captured traffic by host/path and summarize endpoint coverage. |
| `flex_decode_jwt(token)` | Decode a JWT and flag weak or missing claims. |

## Attack Surface

| Tool | Purpose |
| --- | --- |
| `flex_url_schemes` | Read URL schemes and associated domains. |
| `flex_open_url(url)` | Open a URL through `UIApplication` to test deep links. |
| `flex_entitlements` | Dump app entitlements, app groups, keychain groups, and related signing flags. |
| `flex_pasteboard` | Read the general pasteboard. |
| `flex_memory_scan(pattern, encoding, max_hits)` | Search process memory for ASCII or hex patterns. |
| `flex_strings(path, min_length, max_results, search, local)` | Extract printable strings from a local or device-side binary. |
| `flex_logs(enable)` | Install or remove NSLog and os_log capture hooks. |
| `flex_log_events(limit, clear)` | Read captured log events. |

## Storage

| Tool | Purpose |
| --- | --- |
| `flex_userdefaults(search)` | Read `NSUserDefaults`. |
| `flex_set_userdefault(key, value)` | Write a value to `NSUserDefaults`. |
| `flex_keychain` | Dump generic password keychain items visible to the app. |
| `flex_cookies` | Read `NSHTTPCookieStorage`. |
| `flex_files(path)` | List sandbox files. |
| `flex_read_file(path, max_bytes)` | Read a UTF-8 file from the sandbox. |
| `flex_pull_file(device_path, output_path, max_size)` | Pull a binary-safe file from the device to the host. |
| `flex_sqlite_list` | Discover SQLite databases in the app sandbox. |
| `flex_sqlite_query(path, sql, limit)` | Query a SQLite database through the app process. |

## Objective-C Runtime

| Tool | Purpose |
| --- | --- |
| `flex_list_classes(search, limit)` | Search loaded Objective-C classes. |
| `flex_methods(class_name, include_inherited)` | List methods for a class. |
| `flex_instances(class_name, limit)` | Find live heap instances. |
| `flex_inspect(target)` | Inspect a class, pointer, or object. |
| `flex_call(target, selector, args)` | Invoke an Objective-C selector with typed arguments. |
| `flex_execute(js_code)` | Run raw Frida JavaScript as an escape hatch. |

## Method Tracing

| Tool | Purpose |
| --- | --- |
| `flex_trace_start(class_name, selector, scope)` | Hook a method and buffer calls, arguments, returns, and errors. |
| `flex_trace_logs(hook_id, limit, clear)` | Read trace events. |
| `flex_trace_list` | List active trace hooks. |
| `flex_trace_stop(hook_id)` | Stop one trace hook or all trace hooks. |

## Binary Dumping

| Tool | Purpose |
| --- | --- |
| `flex_dump_binary(output_path, module_name)` | Dump and patch the encrypted running Mach-O slice, similar to frida-ios-dump. |

## Bypasses And Crypto

| Tool | Purpose |
| --- | --- |
| `flex_ssl_unpin(enable)` | Install or remove common SSL pinning bypass hooks. |
| `flex_jailbreak_bypass(enable)` | Hide common jailbreak indicators from the target app. |
| `flex_crypto_hooks(enable)` | Capture CommonCrypto key, IV, input, and output events. |
| `flex_crypto_logs(limit, clear)` | Read captured crypto events. |

## Common Workflows

### Connect And Capture Traffic

```text
flex_connect("com.example.app")
flex_network(true)
# Use the app.
flex_requests(count=100)
flex_scan_vulnerabilities(count=100)
```

### Navigate UI And Watch Traffic

```text
flex_connect("com.example.app")
flex_network(true)
flex_ui_tree(max_depth=8)
flex_ui_find(query="login")
flex_ui_tap(text="Login")
flex_ui_type_text(query="email", text="researcher@example.com")
flex_ui_type_text(query="password", text="<test-password>")
flex_ui_tap(text="Sign In")
flex_monitor()
flex_scan_vulnerabilities(count=200)
```

### Replay A Request With Different Auth

```text
flex_request_details(index=12)
flex_replay_request(index=12, headers={"Authorization": "Bearer <test-token>"})
```

### Map Storage And Secrets

```text
flex_keychain()
flex_cookies()
flex_userdefaults()
flex_sqlite_list()
```

### Trace A Sensitive Method

```text
flex_list_classes(search="Auth")
flex_methods(class_name="AuthManager")
flex_trace_start(class_name="AuthManager", selector="- loginWithToken:")
flex_trace_logs(clear=true)
```

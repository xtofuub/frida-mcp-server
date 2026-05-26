# Frida MCP — Tool Mapping for This Skill

When the `frida-mcp-server` (a.k.a. `frida`) MCP server is connected, use these `frida_*` tools in place of the raw CLI commands shown in [SKILL.md](../SKILL.md). The MCP keeps a persistent Frida session, so you can attach once and chain investigations without re-spawning.

## Discovery & attach

| Skill step | MCP tool | Notes |
|---|---|---|
| `frida-ps -Ua` | `frida_list_apps` | Returns installed apps with bundle id + pid. |
| `frida -U -n App` / `frida -U -f bundle.id` | `frida_connect(bundle_id)` | Auto-attaches, or spawns if not running. Enables Frida network capture (NSURLSession hooks). |
| `frida -U -f bundle.id --no-pause` (clean restart) | `frida_spawn(bundle_id)` | Force-restart fresh. |
| — | `frida_sessions`, `frida_disconnect` | Manage active sessions. |
| `otool -L`, list loaded dylibs | `frida_modules(search, limit)` | Lists every loaded Mach-O module with base, size, on-disk path. |
| Bundle info / sandbox path | `frida_app_info` | Bundle id, version, build, sandbox HOME. |

## UI automation

Use these when the agent needs to drive the app itself instead of asking the user to tap around manually.

| Skill step | MCP tool | Notes |
|---|---|---|
| Inspect current screen | `frida_ui_tree(max_depth, include_hidden, max_nodes)` | Returns UIKit nodes with id, class, text/title/placeholder, accessibility label/id/value, visible/enabled state, and screen frame. |
| Find an element | `frida_ui_find(query, class_name, include_hidden)` | Search by text, accessibility metadata, placeholder, title, or class. Prefer visible enabled controls. |
| Press a control | `frida_ui_tap(element_id OR text OR x/y)` | Prefer `element_id` from the tree. Text search is useful for buttons like Login/Continue. Coordinate hit-test is a fallback. |
| Fill forms | `frida_ui_type_text(element_id OR query, text, clear)` | Sets text and emits editing-changed for UIControl text fields when possible. |
| Move through lists | `frida_ui_scroll(element_id, direction, amount)` | Scroll a selected `UIScrollView`, or the first visible scroll view. |

Autonomous navigation loop:

```
frida_connect("com.target.app")
frida_network(true)
frida_ui_tree(max_depth=8)
frida_ui_find(query="login")
frida_ui_tap(text="Login")
frida_ui_type_text(query="email", text="<authorized-test-account>")
frida_ui_type_text(query="password", text="<authorized-test-password>")
frida_ui_tap(text="Sign In")
frida_monitor()
frida_scan_vulnerabilities(count=200)
```

The agent should choose targets using semantic metadata first (accessibility label/id, visible text, class, enabled state) and use coordinates only as a fallback.

## Static + dynamic recon

| Skill step | MCP tool |
|---|---|
| `class-dump` headers / enumerate ObjC classes | `frida_list_classes(search, limit)` |
| List methods of a class | `frida_methods(class_name, include_inherited)` |
| Heap-walk live instances | `frida_instances(class_name, limit)` |
| Inspect ivars of an instance | `frida_inspect(target)` |
| Invoke any selector | `frida_call(target, selector, args)` |
| Arbitrary Frida JS | `frida_execute(js_code)` |

## Network

| Skill step | MCP tool |
|---|---|
| Hook `NSURLSession` for traffic | `frida_network(true)`, `frida_requests`, `frida_request_details` |
| Search traffic by keyword | `frida_search_requests(keyword, search_bodies=True)` |
| Live monitor | `frida_monitor` |

## Method tracing (replacement for `frida-trace`)

```
frida_trace_start("URLSession", "dataTaskWithRequest_completionHandler_")
# exercise the app...
frida_trace_logs(hook_id)
frida_trace_stop(hook_id)
```

Use `frida_trace_list` to see what's hooked and `scope="instance"` / `"class"` if auto-detection picks the wrong dispatcher.

## Secrets & storage

| Skill goal | MCP tool |
|---|---|
| Dump Keychain (`SecItemCopyMatching`) | `frida_keychain` |
| `NSUserDefaults` snapshot | `frida_userdefaults(search)` |
| Mutate UserDefaults | `frida_set_userdefault(key, value)` |
| Cookies (`NSHTTPCookieStorage`) | `frida_cookies` |
| List sandbox files | `frida_files(path)` |
| Read a sandbox file | `frida_read_file(path, max_bytes)` |
| Pull a file binary-safe to host | `frida_pull_file(device_path, output_path)` |
| Find sandbox SQLite DBs | `frida_sqlite_list` |
| Run SQL against a DB | `frida_sqlite_query(path, sql, limit)` |

## Binary decryption (frida-ios-dump replacement)

The MCP implements the core of `frida-ios-dump` natively:

```
frida_dump_binary(output_path="./TargetApp.decrypted")
```

What it does:
1. Resolves the main executable (or a specific `module_name`).
2. Reads the on-disk Mach-O into NSMutableData.
3. Handles thin and fat binaries — matches the running slice via Mach-O magic.
4. Walks load commands, finds `LC_ENCRYPTION_INFO` / `LC_ENCRYPTION_INFO_64`, copies the decrypted region from process memory (`mod.base + cryptoff`) over the on-disk encrypted bytes, and zeros `cryptid`.
5. Streams the patched binary back to the host in 4 MB chunks and writes it to `output_path`.

The returned dict includes `slices_patched` (offset/size of every patched region) and `device_path` (the original location). For full-IPA repackaging, dump the main binary plus any `Frameworks/*.dylib` via repeated calls.

## Bypasses (skill's "Common Pitfalls" section)

| Skill scenario | MCP tool |
|---|---|
| SSL pinning bypass | `frida_ssl_unpin(enable=True)` — hooks `SSLHandshake`, `SSLSetPeerDomainName`, `nw_tls_create_peer_trust`, `AFSecurityPolicy`. |
| Jailbreak detection bypass | `frida_jailbreak_bypass(enable=True)` — hooks `NSFileManager fileExistsAtPath:`, `UIApplication canOpenURL:`, `stat`, neutralizes `fork`. |
| `CCCrypt` / `CCCryptorCreate` key extraction | `frida_crypto_hooks(enable=True)`, then `frida_crypto_logs(limit, clear)` to drain key/iv/data events. |

All bypass hooks are session-scoped persistent scripts. They're cleaned up when you call `frida_disconnect`.

## Canonical end-to-end workflow

```
frida_list_apps                                   # find the bundle id
frida_connect("com.target.app")                   # attach
frida_app_info                                    # confirm bundle, paths
frida_modules(search="Target", limit=20)          # find the main module
frida_dump_binary(output_path="./Target.decrypted")  # frida-ios-dump
frida_ssl_unpin(true); frida_jailbreak_bypass(true)   # neutralize defenses
frida_crypto_hooks(true)                          # arm CCCrypt logging
# ...exercise the app...
frida_requests(count=200)                         # see the network
frida_search_requests("auth", search_bodies=true)
frida_request_details(index=42)                   # full headers + body
frida_crypto_logs(limit=200)                      # captured keys/IVs
frida_keychain                                    # final secret sweep
frida_disconnect                                  # clean up
```

## Bug-bounty / pentest additions (most autonomous workflows)

| Need | Tool |
|---|---|
| Re-send a captured request with modifications | `frida_replay_request(index, method?, url?, headers?, body?)` |
| Rewrite in-flight requests by URL pattern | `frida_intercept_add(pattern OR regex, set_url?, set_method?, set_headers?, add_headers?, remove_headers?, set_body?)` + `frida_intercept_list/toggle/remove/logs` |
| Run a battery of detectors over captured traffic | `frida_scan_vulnerabilities(count)` — plaintext HTTP, JWT alg=none, leaked API keys, CORS, cookie flags, stack traces, etc. |
| Fuzz one field of a captured request | `frida_fuzz_request(index, target='query:name'\|'body'\|'header:NAME'\|'path', payload_set='sqli'\|'xss'\|'path_traversal'\|'cmd_inj'\|'nosql'\|'idor_numeric'\|'idor_uuid'\|'auth_bypass'\|'buffer_overflow')` |
| Map every host + endpoint the app touched | `frida_endpoints_map(count)` |
| Inspect a JWT (alg, claims, weak properties) | `frida_decode_jwt(token)` |
| Enumerate registered deep-link schemes | `frida_url_schemes` |
| Test a deep link handler | `frida_open_url(url)` |
| Dump the app's entitlements | `frida_entitlements` |
| Read the pasteboard | `frida_pasteboard` |
| Scan process memory for a pattern (find secrets in heap) | `frida_memory_scan(pattern, encoding='ascii'\|'hex')` |
| Extract printable strings from a binary | `frida_strings(path, local=True\|False, search?)` |
| Capture NSLog / os_log calls | `frida_logs(enable=True)` + `frida_log_events(limit, clear)` |

## When to bypass the MCP

Drop to raw `frida_execute(js_code)` or the `frida` CLI when:
- You need to interpose a custom `NativeCallback` (the MCP exposes pre-baked hooks only).
- You're hooking pure-Swift code that requires `Module.enumerateExports` discovery — write a short script and pass it to `frida_execute`.
- You need `frida-trace`'s auto-generated handler stubs for exploratory work — easier in the CLI than via MCP for one-offs.
- You're hooking a non-CommonCrypto crypto library (libsodium, BoringSSL, OpenSSL) — find the module with `frida_modules` and write the Interceptor.attach by hand.

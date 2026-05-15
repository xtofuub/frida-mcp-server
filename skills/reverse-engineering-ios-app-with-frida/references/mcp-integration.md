# FLEX MCP — Tool Mapping for This Skill

When the `flex-mcp-server` (a.k.a. `frida-flex`) MCP server is connected, use these `flex_*` tools in place of the raw CLI commands shown in [SKILL.md](../SKILL.md). The MCP keeps a persistent Frida session, so you can attach once and chain investigations without re-spawning.

## Discovery & attach

| Skill step | MCP tool | Notes |
|---|---|---|
| `frida-ps -Ua` | `flex_list_apps` | Returns installed apps with bundle id + pid. |
| `frida -U -n App` / `frida -U -f bundle.id` | `flex_connect(bundle_id)` | Auto-attaches, or spawns if not running. Enables FLEX network capture when FLEX is loaded. |
| `frida -U -f bundle.id --no-pause` (clean restart) | `flex_spawn(bundle_id)` | Force-restart fresh. |
| — | `flex_sessions`, `flex_disconnect` | Manage active sessions. |
| `otool -L`, list loaded dylibs | `flex_modules(search, limit)` | Lists every loaded Mach-O module with base, size, on-disk path. |
| Bundle info / sandbox path | `flex_app_info` | Bundle id, version, build, sandbox HOME. |

## UI automation

Use these when the agent needs to drive the app itself instead of asking the user to tap around manually.

| Skill step | MCP tool | Notes |
|---|---|---|
| Inspect current screen | `flex_ui_tree(max_depth, include_hidden, max_nodes)` | Returns UIKit nodes with id, class, text/title/placeholder, accessibility label/id/value, visible/enabled state, and screen frame. |
| Find an element | `flex_ui_find(query, class_name, include_hidden)` | Search by text, accessibility metadata, placeholder, title, or class. Prefer visible enabled controls. |
| Press a control | `flex_ui_tap(element_id OR text OR x/y)` | Prefer `element_id` from the tree. Text search is useful for buttons like Login/Continue. Coordinate hit-test is a fallback. |
| Fill forms | `flex_ui_type_text(element_id OR query, text, clear)` | Sets text and emits editing-changed for UIControl text fields when possible. |
| Move through lists | `flex_ui_scroll(element_id, direction, amount)` | Scroll a selected `UIScrollView`, or the first visible scroll view. |

Autonomous navigation loop:

```
flex_connect("com.target.app")
flex_network(true)
flex_ui_tree(max_depth=8)
flex_ui_find(query="login")
flex_ui_tap(text="Login")
flex_ui_type_text(query="email", text="<authorized-test-account>")
flex_ui_type_text(query="password", text="<authorized-test-password>")
flex_ui_tap(text="Sign In")
flex_monitor()
flex_scan_vulnerabilities(count=200)
```

The agent should choose targets using semantic metadata first (accessibility label/id, visible text, class, enabled state) and use coordinates only as a fallback.

## Static + dynamic recon

| Skill step | MCP tool |
|---|---|
| `class-dump` headers / enumerate ObjC classes | `flex_list_classes(search, limit)` |
| List methods of a class | `flex_methods(class_name, include_inherited)` |
| Heap-walk live instances | `flex_instances(class_name, limit)` |
| Inspect ivars of an instance | `flex_inspect(target)` |
| Invoke any selector | `flex_call(target, selector, args)` |
| Arbitrary Frida JS | `flex_execute(js_code)` |

## Network

| Skill step | MCP tool |
|---|---|
| Hook `NSURLSession` for traffic | `flex_network(true)`, `flex_requests`, `flex_request_details` |
| Search traffic by keyword | `flex_search_requests(keyword, search_bodies=True)` |
| Live monitor | `flex_monitor` |

## Method tracing (replacement for `frida-trace`)

```
flex_trace_start("URLSession", "dataTaskWithRequest_completionHandler_")
# exercise the app...
flex_trace_logs(hook_id)
flex_trace_stop(hook_id)
```

Use `flex_trace_list` to see what's hooked and `scope="instance"` / `"class"` if auto-detection picks the wrong dispatcher.

## Secrets & storage

| Skill goal | MCP tool |
|---|---|
| Dump Keychain (`SecItemCopyMatching`) | `flex_keychain` |
| `NSUserDefaults` snapshot | `flex_userdefaults(search)` |
| Mutate UserDefaults | `flex_set_userdefault(key, value)` |
| Cookies (`NSHTTPCookieStorage`) | `flex_cookies` |
| List sandbox files | `flex_files(path)` |
| Read a sandbox file | `flex_read_file(path, max_bytes)` |
| Pull a file binary-safe to host | `flex_pull_file(device_path, output_path)` |
| Find sandbox SQLite DBs | `flex_sqlite_list` |
| Run SQL against a DB | `flex_sqlite_query(path, sql, limit)` |

## Binary decryption (frida-ios-dump replacement)

The MCP implements the core of `frida-ios-dump` natively:

```
flex_dump_binary(output_path="./TargetApp.decrypted")
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
| SSL pinning bypass | `flex_ssl_unpin(enable=True)` — hooks `SSLHandshake`, `SSLSetPeerDomainName`, `nw_tls_create_peer_trust`, `AFSecurityPolicy`. |
| Jailbreak detection bypass | `flex_jailbreak_bypass(enable=True)` — hooks `NSFileManager fileExistsAtPath:`, `UIApplication canOpenURL:`, `stat`, neutralizes `fork`. |
| `CCCrypt` / `CCCryptorCreate` key extraction | `flex_crypto_hooks(enable=True)`, then `flex_crypto_logs(limit, clear)` to drain key/iv/data events. |

All bypass hooks are session-scoped persistent scripts. They're cleaned up when you call `flex_disconnect`.

## Canonical end-to-end workflow

```
flex_list_apps                                   # find the bundle id
flex_connect("com.target.app")                   # attach
flex_app_info                                    # confirm bundle, paths
flex_modules(search="Target", limit=20)          # find the main module
flex_dump_binary(output_path="./Target.decrypted")  # frida-ios-dump
flex_ssl_unpin(true); flex_jailbreak_bypass(true)   # neutralize defenses
flex_crypto_hooks(true)                          # arm CCCrypt logging
# ...exercise the app...
flex_requests(count=200)                         # see the network
flex_search_requests("auth", search_bodies=true)
flex_request_details(index=42)                   # full headers + body
flex_crypto_logs(limit=200)                      # captured keys/IVs
flex_keychain                                    # final secret sweep
flex_disconnect                                  # clean up
```

## Bug-bounty / pentest additions (most autonomous workflows)

| Need | Tool |
|---|---|
| Re-send a captured request with modifications | `flex_replay_request(index, method?, url?, headers?, body?)` |
| Rewrite in-flight requests by URL pattern | `flex_intercept_add(pattern OR regex, set_url?, set_method?, set_headers?, add_headers?, remove_headers?, set_body?)` + `flex_intercept_list/toggle/remove/logs` |
| Run a battery of detectors over captured traffic | `flex_scan_vulnerabilities(count)` — plaintext HTTP, JWT alg=none, leaked API keys, CORS, cookie flags, stack traces, etc. |
| Fuzz one field of a captured request | `flex_fuzz_request(index, target='query:name'\|'body'\|'header:NAME'\|'path', payload_set='sqli'\|'xss'\|'path_traversal'\|'cmd_inj'\|'nosql'\|'idor_numeric'\|'idor_uuid'\|'auth_bypass'\|'buffer_overflow')` |
| Map every host + endpoint the app touched | `flex_endpoints_map(count)` |
| Inspect a JWT (alg, claims, weak properties) | `flex_decode_jwt(token)` |
| Enumerate registered deep-link schemes | `flex_url_schemes` |
| Test a deep link handler | `flex_open_url(url)` |
| Dump the app's entitlements | `flex_entitlements` |
| Read the pasteboard | `flex_pasteboard` |
| Scan process memory for a pattern (find secrets in heap) | `flex_memory_scan(pattern, encoding='ascii'\|'hex')` |
| Extract printable strings from a binary | `flex_strings(path, local=True\|False, search?)` |
| Capture NSLog / os_log calls | `flex_logs(enable=True)` + `flex_log_events(limit, clear)` |

## When to bypass the MCP

Drop to raw `flex_execute(js_code)` or the `frida` CLI when:
- You need to interpose a custom `NativeCallback` (the MCP exposes pre-baked hooks only).
- You're hooking pure-Swift code that requires `Module.enumerateExports` discovery — write a short script and pass it to `flex_execute`.
- You need `frida-trace`'s auto-generated handler stubs for exploratory work — easier in the CLI than via MCP for one-offs.
- You're hooking a non-CommonCrypto crypto library (libsodium, BoringSSL, OpenSSL) — find the module with `flex_modules` and write the Interceptor.attach by hand.

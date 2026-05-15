#!/usr/bin/env python3
"""FLEX MCP Server - Control FLEX debugger on iOS via Frida. App-agnostic."""

import sys, os, re, json, time, base64, threading, frida
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("FLEX iOS Debugger")
_sessions = {}
_traces = {}
_named_hooks = {}
_intercept_rules = {}
_intercept_counter = 0
_trace_counter = 0


def get_usb_device():
    try:
        return frida.get_usb_device(timeout=5)
    except Exception as e:
        raise RuntimeError(f"No USB device found: {e}")


def get_or_spawn(bundle_id):
    device = get_usb_device()
    try:
        return device.attach(bundle_id), "attach"
    except Exception:
        pid = device.spawn([bundle_id])
        session = device.attach(pid)
        device.resume(pid)
        time.sleep(3)
        return session, "spawn"


def exec_js(session, js_code, timeout=15):
    messages = []
    event = threading.Event()

    def on_msg(msg, data):
        if msg["type"] == "send":
            messages.append(msg["payload"])
        elif msg["type"] == "error":
            messages.append({"error": msg.get("description", str(msg))})
        event.set()

    wrapped = (
        "(function() {"
        "  try {"
        f"   var __result = {js_code};"
        "    send(JSON.stringify({ok: true, result: __result !== undefined ? String(__result) : 'undefined'}));"
        "  } catch(e) {"
        "    send(JSON.stringify({ok: false, error: e.message, stack: e.stack}));"
        "  }"
        "})();"
    )
    s = session.create_script(wrapped)
    s.on("message", on_msg)
    s.load()
    event.wait(timeout)
    s.unload()
    if messages:
        try:
            return json.loads(messages[-1])
        except Exception:
            return {"ok": False, "error": f"parse: {messages[-1]}"}
    return {"ok": False, "error": "timeout"}


def exec_js_stream(session, js_code, timeout=300, on_chunk=None):
    """Run JS that emits many send() messages until {__done: true}. Collects (payload, data) tuples."""
    chunks = []
    info = {"__done": False}
    error = {"msg": None}
    done = threading.Event()

    def on_msg(msg, data):
        if msg["type"] == "error":
            error["msg"] = msg.get("description", str(msg))
            done.set()
            return
        if msg["type"] != "send":
            return
        p = msg["payload"]
        if isinstance(p, dict) and "__error" in p:
            error["msg"] = p["__error"]
        if isinstance(p, dict) and p.get("__done"):
            info.update(p)
            done.set()
            return
        chunks.append((p, data))
        if on_chunk:
            try:
                on_chunk(p, data)
            except Exception:
                pass

    s = session.create_script(js_code)
    s.on("message", on_msg)
    s.load()
    done.wait(timeout)
    s.unload()
    return {"info": info, "chunks": chunks, "error": error["msg"]}


def safe_str(s, maxlen=500):
    if not s:
        return ""
    try:
        s = str(s)
        if len(s) > maxlen:
            s = s[:maxlen] + "..."
        return s
    except Exception:
        return "<binary data>"


def _get_session(session_id=""):
    if not _sessions:
        raise RuntimeError("No active sessions. Call flex_connect first.")
    sid = session_id or next(iter(_sessions))
    if sid not in _sessions:
        raise RuntimeError(f"Session '{sid}' not found. Active: {list(_sessions.keys())}")
    return sid, _sessions[sid]


# ============================================================
# CONNECTION
# ============================================================

@mcp.tool()
def flex_list_apps() -> dict:
    """List installed applications on the connected device."""
    try:
        device = get_usb_device()
        apps = device.enumerate_applications()
        return {
            "success": True,
            "device": device.name,
            "count": len(apps),
            "apps": [{"identifier": a.identifier, "name": a.name, "pid": a.pid} for a in apps],
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_connect(bundle_id: str) -> dict:
    """Attach (or spawn) the iOS app and enable FLEX network capture if available.

    Args:
        bundle_id: Bundle identifier (e.g. 'com.apple.mobilesafari'). Use flex_list_apps to discover.
    """
    try:
        session, method = get_or_spawn(bundle_id)
        sid = f"flex_{bundle_id}_{int(time.time())}"
        _sessions[sid] = session
        flex_loaded = exec_js(session, "!!ObjC.classes.FLEXManager").get("result") == "true"
        recorder_ok = exec_js(session, "!!ObjC.classes.FLEXNetworkRecorder").get("result") == "true"
        if flex_loaded:
            exec_js(session, "ObjC.classes.FLEXManager.sharedManager().setNetworkDebuggingEnabled_(true)")
        return {
            "success": True,
            "session_id": sid,
            "method": method,
            "flex_loaded": flex_loaded,
            "recorder_available": recorder_ok,
            "device": get_usb_device().name,
            "app": bundle_id,
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_spawn(bundle_id: str) -> dict:
    """Force-restart the app fresh with Frida attached.

    Args:
        bundle_id: Bundle identifier of the target app.
    """
    try:
        device = get_usb_device()
        pid = device.spawn([bundle_id])
        session = device.attach(pid)
        device.resume(pid)
        time.sleep(2)
        sid = f"flex_{bundle_id}_{int(time.time())}"
        _sessions[sid] = session
        return {"success": True, "session_id": sid, "pid": pid}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_sessions() -> dict:
    """List active Frida sessions."""
    return {"success": True, "count": len(_sessions), "sessions": list(_sessions.keys())}


@mcp.tool()
def flex_disconnect(session_id: str = "") -> dict:
    """Disconnect from app session(s).

    Args:
        session_id: Specific session id, or empty to disconnect all.
    """
    def _cleanup(sid):
        for hid in list(_traces.get(sid, {})):
            try:
                _traces[sid][hid]["script"].unload()
            except Exception:
                pass
        _traces.pop(sid, None)
        for name in list(_named_hooks.get(sid, {})):
            try:
                _named_hooks[sid][name]["script"].unload()
            except Exception:
                pass
        _named_hooks.pop(sid, None)
        ir = _intercept_rules.pop(sid, None)
        if ir and ir.get("script"):
            try:
                ir["script"].unload()
            except Exception:
                pass
    try:
        if session_id:
            if session_id in _sessions:
                _cleanup(session_id)
                try:
                    _sessions[session_id].detach()
                except Exception:
                    pass
                del _sessions[session_id]
            return {"success": True, "disconnected": [session_id]}
        ids = list(_sessions.keys())
        for sid in ids:
            _cleanup(sid)
            try:
                _sessions[sid].detach()
            except Exception:
                pass
        _sessions.clear()
        return {"success": True, "disconnected": ids}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================
# EXPLORER & INFO
# ============================================================

@mcp.tool()
def flex_show(session_id: str = "") -> dict:
    """Show the FLEX explorer toolbar on the device."""
    try:
        _, session = _get_session(session_id)
        exec_js(
            session,
            "ObjC.classes.FLEXManager.sharedManager().performSelectorOnMainThread_withObject_waitUntilDone_("
            "ObjC.selector('showExplorer'), null, false); 'dispatched'",
        )
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_hide(session_id: str = "") -> dict:
    """Hide the FLEX explorer toolbar."""
    try:
        _, session = _get_session(session_id)
        exec_js(
            session,
            "ObjC.classes.FLEXManager.sharedManager().performSelectorOnMainThread_withObject_waitUntilDone_("
            "ObjC.selector('hideExplorer'), null, false); 'dispatched'",
        )
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_app_info(session_id: str = "") -> dict:
    """Get bundle info for the attached app (identifier, version, build, sandbox home)."""
    try:
        _, session = _get_session(session_id)
        r = exec_js(session, """
        (function(){
            var b = ObjC.classes.NSBundle.mainBundle();
            var info = b.infoDictionary();
            var env = ObjC.classes.NSProcessInfo.processInfo().environment();
            function s(k){ var v = info.objectForKey_(k); return v ? String(v) : ''; }
            return JSON.stringify({
                bundle_id: String(b.bundleIdentifier()),
                bundle_path: String(b.bundlePath()),
                name: s('CFBundleName'),
                display_name: s('CFBundleDisplayName'),
                version: s('CFBundleShortVersionString'),
                build: s('CFBundleVersion'),
                executable: s('CFBundleExecutable'),
                min_os: s('MinimumOSVersion'),
                home: env.objectForKey_('HOME') ? String(env.objectForKey_('HOME')) : ''
            });
        })()
        """)
        if r.get("ok"):
            return {"success": True, "info": json.loads(r["result"])}
        return {"success": False, "error": str(r)}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================
# NETWORK
# ============================================================

@mcp.tool()
def flex_network(enable: bool = True, session_id: str = "") -> dict:
    """Enable or disable FLEX network capture.

    Args:
        enable: True to start capturing, False to stop.
    """
    try:
        sid, session = _get_session(session_id)
        val = "true" if enable else "false"
        r = exec_js(
            session,
            f"ObjC.classes.FLEXManager.sharedManager().setNetworkDebuggingEnabled_({val}); "
            f"String(ObjC.classes.FLEXManager.sharedManager().isNetworkDebuggingEnabled())",
        )
        return {"success": True, "session": sid, "enabled": r.get("result")}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_requests(count: int = 50, session_id: str = "") -> dict:
    """List captured network requests (method, URL, status, timing).

    Args:
        count: Maximum number of requests to return.
    """
    try:
        _, session = _get_session(session_id)
        r = exec_js(session, f"""
        (function(){{
            var recorder = ObjC.classes.FLEXNetworkRecorder.defaultRecorder();
            var txns = recorder.HTTPTransactions();
            var result = [];
            var max = Math.min(txns.count(), {int(count)});
            for (var i = 0; i < max; i++) {{
                try {{
                    var t = txns.objectAtIndex_(i);
                    var req = t.request();
                    var resp = t.response();
                    result.push({{
                        index: i,
                        method: req ? String(req.HTTPMethod()) : '?',
                        url: req ? String(req.URL().absoluteString()) : '?',
                        status: resp ? resp.statusCode() : -1,
                        latency: t.latency(),
                        duration: t.duration()
                    }});
                }} catch(e) {{}}
            }}
            return JSON.stringify(result);
        }})()
        """)
        if r.get("ok"):
            transactions = json.loads(r["result"])
            return {"success": True, "count": len(transactions), "transactions": transactions}
        return {"success": False, "error": str(r)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_request_details(index: int, max_body_bytes: int = 16384, session_id: str = "") -> dict:
    """Full request + response details: method, URL, headers, bodies.

    Args:
        index: Transaction index from flex_requests.
        max_body_bytes: Cap on each body size returned.
    """
    try:
        _, session = _get_session(session_id)
        r = exec_js(session, f"""
        (function(){{
            var recorder = ObjC.classes.FLEXNetworkRecorder.defaultRecorder();
            var txns = recorder.HTTPTransactions();
            if ({int(index)} >= txns.count()) return JSON.stringify({{error: 'Index out of range'}});
            var t = txns.objectAtIndex_({int(index)});
            var req = t.request();
            var resp = t.response();

            function headersToObj(h) {{
                if (!h) return {{}};
                var out = {{}};
                var keys = h.allKeys();
                for (var i = 0; i < keys.count(); i++) {{
                    var k = String(keys.objectAtIndex_(i));
                    out[k] = String(h.objectForKey_(keys.objectAtIndex_(i)));
                }}
                return out;
            }}

            function dataToStr(d) {{
                if (!d) return '';
                try {{
                    var ns = ObjC.classes.NSString.alloc().initWithData_encoding_(d, 4);
                    return ns ? String(ns) : '<binary ' + d.length() + ' bytes>';
                }} catch(e) {{ return '<binary ' + d.length() + ' bytes>'; }}
            }}

            var reqBody = req ? req.HTTPBody() : null;
            var respBody = recorder.cachedResponseBodyForTransaction_(t);

            return JSON.stringify({{
                index: {int(index)},
                request: {{
                    method: req ? String(req.HTTPMethod()) : '',
                    url: req ? String(req.URL().absoluteString()) : '',
                    headers: req ? headersToObj(req.allHTTPHeaderFields()) : {{}},
                    body: dataToStr(reqBody)
                }},
                response: {{
                    status: resp ? resp.statusCode() : -1,
                    headers: resp ? headersToObj(resp.allHeaderFields()) : {{}},
                    body: dataToStr(respBody)
                }},
                latency: t.latency(),
                duration: t.duration()
            }});
        }})()
        """, timeout=20)
        if r.get("ok"):
            data = json.loads(r["result"])
            if "error" in data:
                return {"success": False, "error": data["error"]}
            data["request"]["body"] = safe_str(data["request"].get("body", ""), max_body_bytes)
            data["response"]["body"] = safe_str(data["response"].get("body", ""), max_body_bytes)
            return {"success": True, **data}
        return {"success": False, "error": str(r)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_search_requests(keyword: str, search_bodies: bool = False, session_id: str = "") -> dict:
    """Search captured requests by keyword. Optionally also scan response bodies.

    Args:
        keyword: Search term (case-insensitive).
        search_bodies: If True, also search response bodies (slower).
    """
    try:
        _, session = _get_session(session_id)
        kw = json.dumps(keyword)
        sb = "true" if search_bodies else "false"
        r = exec_js(session, f"""
        (function(){{
            var recorder = ObjC.classes.FLEXNetworkRecorder.defaultRecorder();
            var txns = recorder.HTTPTransactions();
            var kw = {kw}.toLowerCase();
            var searchBodies = {sb};
            var matches = [];
            for (var i = 0; i < txns.count(); i++) {{
                try {{
                    var t = txns.objectAtIndex_(i);
                    var req = t.request();
                    var url = String(req.URL().absoluteString());
                    var matched = null;
                    if (url.toLowerCase().indexOf(kw) !== -1) matched = 'url';
                    if (!matched && searchBodies) {{
                        var body = recorder.cachedResponseBodyForTransaction_(t);
                        if (body) {{
                            try {{
                                var s = ObjC.classes.NSString.alloc().initWithData_encoding_(body, 4);
                                if (s && String(s).toLowerCase().indexOf(kw) !== -1) matched = 'body';
                            }} catch(e) {{}}
                        }}
                    }}
                    if (matched) {{
                        matches.push({{
                            index: i, url: url,
                            method: String(req.HTTPMethod()),
                            matched_in: matched
                        }});
                    }}
                }} catch(e) {{}}
            }}
            return JSON.stringify(matches);
        }})()
        """, timeout=30)
        if r.get("ok"):
            matches = json.loads(r["result"])
            return {"success": True, "count": len(matches), "matches": matches}
        return {"success": False, "error": str(r)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_monitor(session_id: str = "") -> dict:
    """Return new transactions since the last call. First call sets the baseline."""
    try:
        sid, session = _get_session(session_id)
        r = exec_js(session, "String(ObjC.classes.FLEXNetworkRecorder.defaultRecorder().HTTPTransactions().count())")
        current = int(r.get("result", "0"))
        old = getattr(_sessions[sid], "_last_count", None)
        if old is None:
            _sessions[sid]._last_count = current
            return {"success": True, "new_transactions": 0, "total": current, "message": "Baseline set"}
        if current > old:
            r2 = exec_js(session, f"""
            (function(){{
                var recorder = ObjC.classes.FLEXNetworkRecorder.defaultRecorder();
                var txns = recorder.HTTPTransactions();
                var result = [];
                for (var i = {old}; i < txns.count(); i++) {{
                    try {{
                        var t = txns.objectAtIndex_(i);
                        var req = t.request();
                        var resp = t.response();
                        result.push({{
                            index: i,
                            method: String(req.HTTPMethod()),
                            url: String(req.URL().absoluteString()),
                            status: resp ? resp.statusCode() : -1
                        }});
                    }} catch(e) {{}}
                }}
                return JSON.stringify(result);
            }})()
            """)
            new_txns = json.loads(r2["result"]) if r2.get("ok") else []
            _sessions[sid]._last_count = current
            return {"success": True, "new_transactions": len(new_txns), "total": current, "transactions": new_txns}
        return {"success": True, "new_transactions": 0, "total": current}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================
# REQUEST REPLAY / MODIFICATION
# ============================================================

@mcp.tool()
def flex_replay_request(
    index: int = -1,
    method: str = "",
    url: str = "",
    headers: dict = None,
    body: str = "",
    timeout: int = 30,
    session_id: str = "",
) -> dict:
    """Replay a captured request, optionally overriding fields. Sends through NSURLSession and returns the live response.

    Args:
        index: Captured transaction index (from flex_requests). -1 means build from scratch — url is then required.
        method: Override HTTP method (e.g. 'POST'). Empty = keep original.
        url: Override URL. Empty = keep original.
        headers: Dict of headers to set (replaces existing values for the same key). None = keep original.
        body: Override request body (UTF-8 string). Empty = keep original.
        timeout: Max seconds to wait for the response.
    """
    try:
        _, session = _get_session(session_id)
        idx = int(index)
        method_j = json.dumps(method or "")
        url_j = json.dumps(url or "")
        headers_j = json.dumps(headers or {})
        body_j = json.dumps(body or "")
        js = f"""
        (function(){{
            try {{
                var idx = {idx};
                var origReq = null;
                if (idx >= 0) {{
                    var recorder = ObjC.classes.FLEXNetworkRecorder.defaultRecorder();
                    var txns = recorder.HTTPTransactions();
                    if (idx >= txns.count()) {{
                        send({{__error: 'Index out of range'}}); send({{__done: true}}); return;
                    }}
                    origReq = txns.objectAtIndex_(idx).request();
                }}

                var req;
                var urlOverride = {url_j};
                if (origReq) {{
                    req = origReq.mutableCopy();
                    if (urlOverride) req.setURL_(ObjC.classes.NSURL.URLWithString_(urlOverride));
                }} else {{
                    if (!urlOverride) {{
                        send({{__error: 'url required when index < 0'}}); send({{__done: true}}); return;
                    }}
                    req = ObjC.classes.NSMutableURLRequest.requestWithURL_(
                        ObjC.classes.NSURL.URLWithString_(urlOverride)
                    );
                }}

                var methodOverride = {method_j};
                if (methodOverride) req.setHTTPMethod_(methodOverride);

                var headerOverrides = {headers_j};
                for (var k in headerOverrides) {{
                    req.setValue_forHTTPHeaderField_(headerOverrides[k], k);
                }}

                var bodyOverride = {body_j};
                if (bodyOverride) {{
                    var bd = ObjC.classes.NSString.stringWithString_(bodyOverride).dataUsingEncoding_(4);
                    req.setHTTPBody_(bd);
                }}

                // Capture final state for the response
                var finalUrl = String(req.URL().absoluteString());
                var finalMethod = String(req.HTTPMethod());
                var finalHeaders = {{}};
                var hf = req.allHTTPHeaderFields();
                if (hf) {{
                    var keys = hf.allKeys();
                    for (var i = 0; i < keys.count(); i++) {{
                        var key = String(keys.objectAtIndex_(i));
                        finalHeaders[key] = String(hf.objectForKey_(keys.objectAtIndex_(i)));
                    }}
                }}

                var session = ObjC.classes.NSURLSession.sharedSession();
                var t0 = Date.now();
                var completion = new ObjC.Block({{
                    retType: 'void',
                    argTypes: ['object', 'object', 'object'],
                    implementation: function(data, response, error) {{
                        var status = -1;
                        var respHeaders = {{}};
                        if (response) {{
                            try {{
                                var resp = new ObjC.Object(response);
                                status = resp.statusCode();
                                var ah = resp.allHeaderFields();
                                if (ah) {{
                                    var rk = ah.allKeys();
                                    for (var i = 0; i < rk.count(); i++) {{
                                        var k = String(rk.objectAtIndex_(i));
                                        respHeaders[k] = String(ah.objectForKey_(rk.objectAtIndex_(i)));
                                    }}
                                }}
                            }} catch(e) {{}}
                        }}
                        var bodyStr = '';
                        var byteLen = 0;
                        if (data) {{
                            try {{
                                var d = new ObjC.Object(data);
                                byteLen = d.length();
                                var s = ObjC.classes.NSString.alloc().initWithData_encoding_(d, 4);
                                bodyStr = s ? String(s) : '<binary ' + byteLen + ' bytes>';
                            }} catch(e) {{}}
                        }}
                        var errStr = '';
                        if (error) {{
                            try {{ errStr = String(new ObjC.Object(error)); }} catch(e) {{}}
                        }}
                        send({{
                            type: 'response',
                            status: status,
                            headers: respHeaders,
                            body: bodyStr,
                            body_size: byteLen,
                            error: errStr,
                            elapsed_ms: Date.now() - t0,
                            sent: {{
                                url: finalUrl, method: finalMethod, headers: finalHeaders
                            }}
                        }});
                        send({{__done: true}});
                    }}
                }});

                var task = session.dataTaskWithRequest_completionHandler_(req, completion);
                task.resume();
            }} catch(e) {{
                send({{__error: e.message + ' :: ' + (e.stack || '')}});
                send({{__done: true}});
            }}
        }})();
        """
        result = exec_js_stream(session, js, timeout=timeout + 5)
        if result["error"]:
            return {"success": False, "error": result["error"]}
        for payload, _data in result["chunks"]:
            if isinstance(payload, dict) and payload.get("type") == "response":
                return {"success": True, **{k: v for k, v in payload.items() if k != "type"}}
        return {"success": False, "error": "no response received (timeout?)"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================
# IN-FLIGHT INTERCEPTION
# ============================================================

_INTERCEPT_JS = """
(function(){
    var rules = [];
    var log = [];
    var maxLog = 2000;

    function matchesRule(url, method, rule) {
        if (rule.method_filter && rule.method_filter !== method.toUpperCase()) return false;
        if (rule.regex) {
            try { return new RegExp(rule.regex).test(url); } catch(e) { return false; }
        }
        return rule.pattern && url.indexOf(rule.pattern) !== -1;
    }

    function applyRule(reqIn, rule) {
        var req = reqIn.mutableCopy();
        if (rule.set_url) {
            req.setURL_(ObjC.classes.NSURL.URLWithString_(rule.set_url));
        }
        if (rule.set_method) {
            req.setHTTPMethod_(rule.set_method);
        }
        if (rule.remove_headers && rule.remove_headers.length) {
            for (var i = 0; i < rule.remove_headers.length; i++) {
                req.setValue_forHTTPHeaderField_(null, rule.remove_headers[i]);
            }
        }
        if (rule.set_headers) {
            for (var k in rule.set_headers) {
                req.setValue_forHTTPHeaderField_(rule.set_headers[k], k);
            }
        }
        if (rule.add_headers) {
            for (var k2 in rule.add_headers) {
                req.addValue_forHTTPHeaderField_(rule.add_headers[k2], k2);
            }
        }
        if (typeof rule.set_body === 'string' && rule.set_body.length > 0) {
            var bd = ObjC.classes.NSString.stringWithString_(rule.set_body).dataUsingEncoding_(4);
            req.setHTTPBody_(bd);
        }
        return req;
    }

    function hookOne(selector) {
        try {
            var m = ObjC.classes.NSURLSession[selector];
            if (!m) return false;
            Interceptor.attach(m.implementation, {
                onEnter: function(args) {
                    try {
                        var origReq = new ObjC.Object(args[2]);
                        var url = String(origReq.URL().absoluteString());
                        var method = String(origReq.HTTPMethod());
                        for (var i = 0; i < rules.length; i++) {
                            var rule = rules[i];
                            if (!rule.enabled) continue;
                            if (!matchesRule(url, method, rule)) continue;
                            var mutated = applyRule(origReq, rule);
                            args[2] = mutated.handle;
                            log.push({
                                rule_id: rule.id,
                                hook: selector,
                                original: {url: url, method: method},
                                modified: {
                                    url: String(mutated.URL().absoluteString()),
                                    method: String(mutated.HTTPMethod())
                                },
                                time: Date.now()
                            });
                            if (log.length > maxLog) log.shift();
                            break;
                        }
                    } catch(e) {
                        log.push({error: 'intercept onEnter: ' + e.message, time: Date.now()});
                    }
                }
            });
            return true;
        } catch(e) { return false; }
    }

    var hooked = [];
    if (hookOne('- dataTaskWithRequest:completionHandler:')) hooked.push('dataTaskWithRequest:completionHandler:');
    if (hookOne('- dataTaskWithRequest:')) hooked.push('dataTaskWithRequest:');
    if (hookOne('- uploadTaskWithRequest:fromData:completionHandler:')) hooked.push('uploadTaskWithRequest:fromData:completionHandler:');
    if (hookOne('- downloadTaskWithRequest:completionHandler:')) hooked.push('downloadTaskWithRequest:completionHandler:');

    rpc.exports = {
        addRule: function(rule) {
            rules.push(rule);
            return rules.length;
        },
        removeRule: function(id) {
            var before = rules.length;
            rules = rules.filter(function(r){ return r.id !== id; });
            return before - rules.length;
        },
        listRules: function() { return rules; },
        getLogs: function(limit, clear) {
            var slice = limit > 0 ? log.slice(-limit) : log.slice();
            if (clear) log = [];
            return slice;
        },
        setEnabled: function(id, enabled) {
            for (var i = 0; i < rules.length; i++) {
                if (rules[i].id === id) { rules[i].enabled = !!enabled; return true; }
            }
            return false;
        }
    };

    send({__hook_init: true, ok: true, hooked: hooked});
})();
"""


def _ensure_intercept_installed(sid, session):
    state = _intercept_rules.get(sid)
    if state and state.get("script"):
        return state
    ack_event = threading.Event()
    ack = {"ok": False, "error": "", "hooked": []}

    def on_msg(msg, data):
        if msg["type"] != "send":
            return
        p = msg["payload"]
        if isinstance(p, dict) and p.get("__hook_init"):
            ack["ok"] = p.get("ok", False)
            ack["error"] = p.get("error", "")
            ack["hooked"] = p.get("hooked", [])
            ack_event.set()

    script = session.create_script(_INTERCEPT_JS)
    script.on("message", on_msg)
    script.load()
    ack_event.wait(5)
    if not ack["ok"]:
        try:
            script.unload()
        except Exception:
            pass
        raise RuntimeError(ack["error"] or "intercept init timeout")
    _intercept_rules[sid] = {"script": script, "hooked": ack["hooked"]}
    return _intercept_rules[sid]


@mcp.tool()
def flex_intercept_add(
    pattern: str = "",
    regex: str = "",
    method_filter: str = "",
    set_url: str = "",
    set_method: str = "",
    set_headers: dict = None,
    add_headers: dict = None,
    remove_headers: list = None,
    set_body: str = "",
    session_id: str = "",
) -> dict:
    """Install a rule that modifies in-flight NSURLSession requests matching pattern or regex.

    Args:
        pattern: Substring to match against the request URL.
        regex: Full regex (used if pattern is empty).
        method_filter: Optional method filter ('GET', 'POST', etc.). Empty = any method.
        set_url: Replace the URL entirely.
        set_method: Replace the HTTP method.
        set_headers: Dict of headers to set (replaces existing values).
        add_headers: Dict of headers to append (allows duplicates).
        remove_headers: List of header names to remove.
        set_body: Replace the HTTP body (UTF-8 string).

    Returns the rule_id you'll use with flex_intercept_remove / flex_intercept_toggle.
    """
    global _intercept_counter
    try:
        sid, session = _get_session(session_id)
        state = _ensure_intercept_installed(sid, session)
        if not pattern and not regex:
            return {"success": False, "error": "pattern or regex required"}
        _intercept_counter += 1
        rule_id = f"rule_{_intercept_counter}"
        rule = {
            "id": rule_id,
            "enabled": True,
            "pattern": pattern,
            "regex": regex,
            "method_filter": method_filter.upper() if method_filter else "",
            "set_url": set_url,
            "set_method": set_method,
            "set_headers": set_headers or {},
            "add_headers": add_headers or {},
            "remove_headers": remove_headers or [],
            "set_body": set_body,
        }
        state["script"].exports_sync.add_rule(rule)
        return {"success": True, "rule_id": rule_id, "hooked": state.get("hooked", [])}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_intercept_list(session_id: str = "") -> dict:
    """List active interception rules in the session."""
    try:
        sid, _ = _get_session(session_id)
        state = _intercept_rules.get(sid)
        if not state:
            return {"success": True, "rules": [], "message": "Interception not installed yet."}
        rules = state["script"].exports_sync.list_rules()
        return {"success": True, "count": len(rules), "rules": rules, "hooked": state.get("hooked", [])}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_intercept_remove(rule_id: str = "", session_id: str = "") -> dict:
    """Remove a single rule. Empty rule_id removes all rules and uninstalls the hook."""
    try:
        sid, _ = _get_session(session_id)
        state = _intercept_rules.get(sid)
        if not state:
            return {"success": True, "message": "Nothing to remove."}
        if rule_id:
            removed = state["script"].exports_sync.remove_rule(rule_id)
            return {"success": True, "removed": removed}
        try:
            state["script"].unload()
        except Exception:
            pass
        _intercept_rules.pop(sid, None)
        return {"success": True, "uninstalled": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_intercept_toggle(rule_id: str, enabled: bool, session_id: str = "") -> dict:
    """Enable or disable a rule without removing it."""
    try:
        sid, _ = _get_session(session_id)
        state = _intercept_rules.get(sid)
        if not state:
            return {"success": False, "error": "Interception not installed."}
        ok = state["script"].exports_sync.set_enabled(rule_id, enabled)
        return {"success": ok, "rule_id": rule_id, "enabled": enabled if ok else None}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_intercept_logs(limit: int = 100, clear: bool = False, session_id: str = "") -> dict:
    """Get records of intercepted requests (which rule fired, what was changed)."""
    try:
        sid, _ = _get_session(session_id)
        state = _intercept_rules.get(sid)
        if not state:
            return {"success": True, "events": [], "message": "Interception not installed yet."}
        events = state["script"].exports_sync.get_logs(int(limit), bool(clear))
        return {"success": True, "count": len(events), "events": events}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================
# VULNERABILITY SCAN
# ============================================================

_API_KEY_PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS Secret Key", re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])")),
    ("Stripe Live Key", re.compile(r"sk_live_[0-9a-zA-Z]{24,}")),
    ("Stripe Restricted Key", re.compile(r"rk_live_[0-9a-zA-Z]{24,}")),
    ("GitHub Token", re.compile(r"gh[pousr]_[0-9a-zA-Z]{36}")),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("Twilio API Key", re.compile(r"SK[0-9a-fA-F]{32}")),
    ("Firebase URL", re.compile(r"[a-z0-9-]+\.firebaseio\.com")),
    ("Private Key Block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]

_STACK_TRACE_SIGS = [
    "at java.", "at com.", "at sun.", "Caused by:",
    "Traceback (most recent call last)", 'File "', "line ",
    "NullPointerException", "IndexOutOfBoundsException",
    " at /", "/node_modules/", "ActionController::",
    "undefined method `", " in <stdin>",
    "system.web.", "Microsoft.AspNetCore.",
]

_CRED_QS_KEYS = ["token", "access_token", "id_token", "auth_token", "api_key",
                 "apikey", "auth", "password", "passwd", "pwd", "secret",
                 "session", "sessionid", "sid"]


def _decode_jwt_header(token):
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        pad = "=" * (-len(parts[0]) % 4)
        hdr = base64.urlsafe_b64decode(parts[0] + pad).decode("utf-8", errors="ignore")
        return json.loads(hdr)
    except Exception:
        return None


def _scan_single(details):
    findings = []
    req = details.get("request", {}) or {}
    resp = details.get("response", {}) or {}
    url = req.get("url", "") or ""
    method = (req.get("method") or "").upper()
    req_headers = {k.lower(): v for k, v in (req.get("headers") or {}).items()}
    resp_headers = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
    req_body = req.get("body", "") or ""
    resp_body = resp.get("body", "") or ""
    status = resp.get("status", -1)

    if url.lower().startswith("http://"):
        findings.append({"severity": "high", "issue": "Plaintext HTTP",
                         "detail": "Request sent over unencrypted HTTP."})

    try:
        host_part = url.split("://", 1)[1].split("/", 1)[0]
        if "@" in host_part:
            findings.append({"severity": "critical", "issue": "Credentials in URL userinfo",
                             "detail": f"user:pass embedded in URL host: {host_part}"})
    except Exception:
        pass

    low_url = url.lower()
    for key in _CRED_QS_KEYS:
        if f"?{key}=" in low_url or f"&{key}=" in low_url:
            findings.append({"severity": "high", "issue": "Credential in URL query string",
                             "detail": f"`{key}` parameter visible in URL (logged everywhere)."})

    auth = req_headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        hdr = _decode_jwt_header(auth.split(" ", 1)[1].strip())
        if hdr:
            alg = (hdr.get("alg") or "").lower()
            if alg == "none":
                findings.append({"severity": "critical", "issue": "JWT alg=none",
                                 "detail": "Token has unsigned algorithm — server accepting it is broken auth."})
            elif alg in ("hs256", "hs384", "hs512"):
                findings.append({"severity": "info", "issue": "JWT uses HMAC",
                                 "detail": f"alg={alg} — verify the server's secret isn't weak/predictable."})
    if auth.lower().startswith("basic "):
        findings.append({"severity": "medium", "issue": "HTTP Basic auth",
                         "detail": "Base64-encoded credentials sent every request."})

    if url.lower().startswith("https://") and "strict-transport-security" not in resp_headers:
        findings.append({"severity": "low", "issue": "Missing HSTS",
                         "detail": "Response served over HTTPS without Strict-Transport-Security."})
    if resp_headers.get("access-control-allow-origin") == "*":
        if "authorization" in req_headers or "cookie" in req_headers:
            findings.append({"severity": "high", "issue": "Permissive CORS on authenticated endpoint",
                             "detail": "Access-Control-Allow-Origin: * combined with credentials."})
        else:
            findings.append({"severity": "medium", "issue": "Permissive CORS",
                             "detail": "Access-Control-Allow-Origin: *"})

    sc = resp_headers.get("set-cookie", "")
    if sc:
        sc_l = sc.lower()
        if url.lower().startswith("https://") and "secure" not in sc_l:
            findings.append({"severity": "medium", "issue": "Cookie missing Secure flag",
                             "detail": sc[:120]})
        if any(t in sc_l for t in ["session", "auth", "token", "sid", "jwt"]) and "httponly" not in sc_l:
            findings.append({"severity": "medium", "issue": "Session cookie missing HttpOnly",
                             "detail": sc[:120]})
        if "samesite" not in sc_l:
            findings.append({"severity": "low", "issue": "Cookie missing SameSite",
                             "detail": sc[:120]})

    server = resp_headers.get("server", "")
    if server and any(c.isdigit() for c in server):
        findings.append({"severity": "info", "issue": "Server version disclosure",
                         "detail": f"Server: {server}"})

    powered_by = resp_headers.get("x-powered-by", "")
    if powered_by:
        findings.append({"severity": "info", "issue": "X-Powered-By disclosure",
                         "detail": f"X-Powered-By: {powered_by}"})

    if status >= 500:
        for sig in _STACK_TRACE_SIGS:
            if sig in resp_body:
                findings.append({"severity": "medium", "issue": "Stack trace in error response",
                                 "detail": f"Matched: {sig!r}"})
                break

    body_corpus = resp_body + "\n" + req_body
    for name, pat in _API_KEY_PATTERNS:
        if name == "AWS Secret Key":
            continue
        m = pat.search(body_corpus)
        if m:
            findings.append({"severity": "critical", "issue": f"Possible {name} leak",
                             "detail": f"Sample: {m.group()[:40]}..."})

    if method == "GET" and any(p in url for p in ("/login", "/auth", "/signin")) and any(
        k in low_url for k in _CRED_QS_KEYS
    ):
        findings.append({"severity": "high", "issue": "Auth endpoint accepts credentials via GET",
                         "detail": "Sensitive auth fields in GET query string."})

    return findings


@mcp.tool()
def flex_scan_vulnerabilities(count: int = 100, session_id: str = "") -> dict:
    """Scan captured network traffic for common security issues.

    Walks up to `count` captured transactions, pulls headers + bodies, runs a battery of detectors
    (plaintext HTTP, creds in URL, JWT alg=none, missing HSTS, permissive CORS, cookie flags,
    leaked API keys, stack traces in errors, server version disclosure). Returns per-transaction
    findings plus a severity summary.

    Args:
        count: Max transactions to scan from the FLEX recorder.
    """
    try:
        _, session = _get_session(session_id)
        idx_list = flex_requests(count=count, session_id=session_id)
        if not idx_list.get("success"):
            return idx_list
        results = []
        severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for t in idx_list.get("transactions", []):
            details = flex_request_details(
                index=t["index"], max_body_bytes=65536, session_id=session_id
            )
            if not details.get("success"):
                continue
            findings = _scan_single(details)
            if not findings:
                continue
            for f in findings:
                severity_count[f["severity"]] = severity_count.get(f["severity"], 0) + 1
            results.append({
                "index": t["index"],
                "method": t.get("method"),
                "url": t.get("url"),
                "status": t.get("status"),
                "findings": findings,
            })
        return {
            "success": True,
            "scanned": len(idx_list.get("transactions", [])),
            "with_findings": len(results),
            "severity_summary": severity_count,
            "results": results,
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================
# FUZZING
# ============================================================

_FUZZ_PAYLOADS = {
    "sqli": [
        "'", "\"", "''", "' OR '1'='1", "' OR 1=1--", "\" OR \"\"=\"",
        "1' UNION SELECT NULL--", "1; DROP TABLE users--",
        "' AND SLEEP(5)--", "1 OR 1=1", "admin'--", "%27%20OR%201=1--",
    ],
    "xss": [
        "<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>",
        "javascript:alert(1)", "'\"><svg onload=alert(1)>",
        "</script><script>alert(1)</script>", "{{7*7}}", "${7*7}",
    ],
    "path_traversal": [
        "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
        "....//....//etc/passwd", "%2e%2e%2fetc%2fpasswd",
        "..\\..\\windows\\win.ini", "/etc/passwd%00",
    ],
    "cmd_inj": [
        "; id", "| id", "|| id", "&& id", "`id`", "$(id)",
        ";ping -c1 127.0.0.1", "%0a id", "; ls -la",
    ],
    "nosql": [
        "{\"$gt\":\"\"}", "{\"$ne\":null}", "{\"$regex\":\".*\"}",
        "{\"$where\":\"this.password.length > 0\"}",
        "[$ne]=", "'||'a'=='a", "';return true;//",
    ],
    "idor_numeric": [
        "0", "1", "2", "100", "1000", "999999999",
        "-1", "-999", "0x0", "00001", "1.0", "1e10",
    ],
    "idor_uuid": [
        "00000000-0000-0000-0000-000000000000",
        "11111111-1111-1111-1111-111111111111",
        "ffffffff-ffff-ffff-ffff-ffffffffffff",
        "deadbeef-dead-beef-dead-beefdeadbeef",
    ],
    "auth_bypass": [
        "", "null", "undefined", "[]", "{}", "0", "false",
        "Bearer null", "Bearer undefined", "Bearer ", "Bearer 0",
    ],
    "buffer_overflow": [
        "A" * 256, "A" * 1024, "A" * 4096, "%s" * 64, "%n%n%n%n",
    ],
}

_SQL_ERROR_SIGS = [
    "SQL syntax", "mysql_fetch", "sqlite3.OperationalError",
    "ORA-", "PostgreSQL", "psycopg2", "Microsoft SQL", "SQLSTATE",
    "unterminated quoted string", "MariaDB", "sqlite_master",
]
_TRAVERSAL_SIGS = ["root:x:", "[boot loader]", "/bin/bash", "/bin/sh"]
_CMD_INJ_SIGS = ["uid=", "gid=", "groups=", "Linux ", "Darwin Kernel"]


def _detect_response_anomalies(payload, body, status, baseline):
    flags = []
    bl_status = baseline.get("status", -1)
    bl_size = baseline.get("body_size", 0)
    if status != bl_status and status != -1:
        flags.append(f"status changed {bl_status}->{status}")
    if bl_size > 0 and abs(len(body) - bl_size) > max(50, bl_size * 0.3):
        flags.append(f"body size delta ({bl_size}->{len(body)})")
    if any(sig in body for sig in _SQL_ERROR_SIGS):
        flags.append("SQL error signature in response")
    if any(sig in body for sig in _TRAVERSAL_SIGS):
        flags.append("path traversal success signature")
    if any(sig in body for sig in _CMD_INJ_SIGS):
        flags.append("command injection signature")
    if payload and payload in body and len(payload) > 4:
        flags.append("payload reflected in response (possible XSS)")
    if status >= 500:
        flags.append(f"server error {status}")
    return flags


@mcp.tool()
def flex_fuzz_request(
    index: int,
    target: str,
    payloads: list = None,
    payload_set: str = "",
    timeout_per: int = 10,
    max_payloads: int = 50,
    session_id: str = "",
) -> dict:
    """Fuzz a captured request by mutating one field through a list of payloads.

    Args:
        index: Captured transaction index (from flex_requests).
        target: What to fuzz. Forms:
            - 'query:NAME' — replace value of URL query param NAME
            - 'query_append:NAME' — append payload to value of query param NAME
            - 'body' — replace entire body
            - 'body_append' — append to body
            - 'header:NAME' — replace value of header NAME
            - 'path' — append payload to the URL path
        payloads: Custom payload list. Overrides payload_set if given.
        payload_set: Preset name: sqli, xss, path_traversal, cmd_inj, nosql,
            idor_numeric, idor_uuid, auth_bypass, buffer_overflow.
        timeout_per: Max seconds per request.
        max_payloads: Hard cap on number of attempts.

    Returns a list of {payload, status, body_size, elapsed_ms, anomalies} entries,
    plus a baseline measurement (original unmodified request) for comparison.
    """
    try:
        sid, _ = _get_session(session_id)
        if payloads is None:
            payloads = _FUZZ_PAYLOADS.get(payload_set or "", [])
        if not payloads:
            return {"success": False, "error": "no payloads (provide payloads= or payload_set=)"}
        payloads = payloads[:max_payloads]

        base = flex_request_details(index=index, max_body_bytes=4096, session_id=session_id)
        if not base.get("success"):
            return {"success": False, "error": f"could not fetch baseline: {base.get('error')}"}
        orig_url = base["request"]["url"]
        orig_method = base["request"]["method"]
        orig_headers = dict(base["request"].get("headers") or {})
        orig_body = base["request"].get("body", "")

        baseline_replay = flex_replay_request(index=index, timeout=timeout_per, session_id=session_id)
        baseline_summary = {
            "status": baseline_replay.get("status", -1),
            "body_size": baseline_replay.get("body_size", 0),
        }

        results = []
        from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

        for payload in payloads:
            override = {}
            t = target.lower()
            if t.startswith("query:") or t.startswith("query_append:"):
                name = target.split(":", 1)[1]
                append = t.startswith("query_append:")
                parsed = urlparse(orig_url)
                qs = parse_qsl(parsed.query, keep_blank_values=True)
                new_qs, replaced = [], False
                for k, v in qs:
                    if k == name:
                        new_qs.append((k, (v + payload) if append else payload))
                        replaced = True
                    else:
                        new_qs.append((k, v))
                if not replaced:
                    new_qs.append((name, payload))
                override["url"] = urlunparse(parsed._replace(query=urlencode(new_qs)))
            elif t == "body":
                override["body"] = payload
            elif t == "body_append":
                override["body"] = orig_body + payload
            elif t.startswith("header:"):
                name = target.split(":", 1)[1]
                new_h = dict(orig_headers)
                new_h[name] = payload
                override["headers"] = new_h
            elif t == "path":
                parsed = urlparse(orig_url)
                new_path = parsed.path.rstrip("/") + "/" + payload.lstrip("/")
                override["url"] = urlunparse(parsed._replace(path=new_path))
            else:
                return {"success": False, "error": f"unknown target: {target}"}

            r = flex_replay_request(
                index=-1, method=orig_method, url=override.get("url", orig_url),
                headers=override.get("headers", orig_headers),
                body=override.get("body", orig_body),
                timeout=timeout_per, session_id=session_id,
            )
            body_text = r.get("body", "") or ""
            anomalies = _detect_response_anomalies(
                payload, body_text, r.get("status", -1), baseline_summary
            )
            results.append({
                "payload": payload[:200],
                "status": r.get("status", -1),
                "body_size": r.get("body_size", 0),
                "elapsed_ms": r.get("elapsed_ms"),
                "anomalies": anomalies,
                "body_preview": body_text[:200] if anomalies else "",
            })

        interesting = [r for r in results if r["anomalies"]]
        return {
            "success": True,
            "baseline": baseline_summary,
            "target": target,
            "payload_set": payload_set,
            "tried": len(results),
            "interesting": len(interesting),
            "results": results,
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================
# ATTACK SURFACE / DISCOVERY
# ============================================================

@mcp.tool()
def flex_endpoints_map(count: int = 500, session_id: str = "") -> dict:
    """Group captured traffic by host + path template — quick attack-surface map.

    Returns hosts with their endpoints, methods seen, response status histogram, and
    whether the endpoint requires Authorization. Useful as the first scan when
    auditing an unknown app.
    """
    try:
        _, _ = _get_session(session_id)
        idx_list = flex_requests(count=count, session_id=session_id)
        if not idx_list.get("success"):
            return idx_list
        from urllib.parse import urlparse
        hosts = {}
        for t in idx_list.get("transactions", []):
            try:
                u = urlparse(t["url"])
                host = u.netloc
                path = u.path or "/"
                bucket = hosts.setdefault(host, {})
                endpoint = bucket.setdefault(path, {
                    "methods": set(), "statuses": {}, "count": 0, "has_auth_call": False,
                })
                endpoint["methods"].add(t.get("method", "?"))
                s = t.get("status", -1)
                endpoint["statuses"][s] = endpoint["statuses"].get(s, 0) + 1
                endpoint["count"] += 1
            except Exception:
                continue
        for txn in idx_list.get("transactions", []):
            try:
                details = flex_request_details(index=txn["index"], max_body_bytes=0, session_id=session_id)
                if not details.get("success"):
                    continue
                hs = {k.lower() for k in (details["request"].get("headers") or {}).keys()}
                if "authorization" in hs or "x-api-key" in hs or "cookie" in hs:
                    u = urlparse(txn["url"])
                    if u.netloc in hosts and u.path in hosts[u.netloc]:
                        hosts[u.netloc][u.path]["has_auth_call"] = True
            except Exception:
                continue
        out = []
        for host, endpoints in hosts.items():
            out.append({
                "host": host,
                "endpoint_count": len(endpoints),
                "endpoints": sorted([
                    {
                        "path": p,
                        "methods": sorted(e["methods"]),
                        "count": e["count"],
                        "statuses": e["statuses"],
                        "has_auth_call": e["has_auth_call"],
                    } for p, e in endpoints.items()
                ], key=lambda x: -x["count"]),
            })
        out.sort(key=lambda x: -x["endpoint_count"])
        return {"success": True, "host_count": len(out), "hosts": out}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_url_schemes(session_id: str = "") -> dict:
    """List URL schemes the app handles (CFBundleURLTypes from Info.plist)."""
    try:
        _, session = _get_session(session_id)
        r = exec_js(session, """
        (function(){
            var info = ObjC.classes.NSBundle.mainBundle().infoDictionary();
            var types = info.objectForKey_('CFBundleURLTypes');
            var out = [];
            if (types) {
                for (var i = 0; i < types.count(); i++) {
                    var entry = types.objectAtIndex_(i);
                    var name = entry.objectForKey_('CFBundleURLName');
                    var schemes = entry.objectForKey_('CFBundleURLSchemes');
                    var schArr = [];
                    if (schemes) {
                        for (var j = 0; j < schemes.count(); j++) {
                            schArr.push(String(schemes.objectAtIndex_(j)));
                        }
                    }
                    out.push({
                        name: name ? String(name) : '',
                        schemes: schArr
                    });
                }
            }
            var assoc = info.objectForKey_('com.apple.developer.associated-domains');
            return JSON.stringify({url_types: out, associated_domains: assoc ? String(assoc) : null});
        })()
        """)
        if r.get("ok"):
            return {"success": True, **json.loads(r["result"])}
        return {"success": False, "error": str(r)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_open_url(url: str, session_id: str = "") -> dict:
    """Open a URL inside the app via UIApplication.openURL: — test deep link handlers.

    Useful for hammering schemes returned by flex_url_schemes with attacker-controlled inputs.
    """
    try:
        _, session = _get_session(session_id)
        u = json.dumps(url)
        r = exec_js(session, f"""
        (function(){{
            var nsurl = ObjC.classes.NSURL.URLWithString_({u});
            if (!nsurl) return JSON.stringify({{ok: false, error: 'invalid URL'}});
            var app = ObjC.classes.UIApplication.sharedApplication();
            if (app['- openURL:options:completionHandler:']) {{
                var empty = ObjC.classes.NSDictionary.dictionary();
                app.openURL_options_completionHandler_(nsurl, empty, null);
            }} else {{
                app.openURL_(nsurl);
            }}
            return JSON.stringify({{ok: true, opened: {u}}});
        }})()
        """, timeout=10)
        if r.get("ok"):
            data = json.loads(r["result"])
            return {"success": data.get("ok", False), **data}
        return {"success": False, "error": str(r)}
    except Exception as e:
        return {"success": False, "error": str(e)}


_KNOWN_ENTITLEMENTS = [
    "application-identifier",
    "com.apple.developer.team-identifier",
    "com.apple.developer.associated-domains",
    "com.apple.security.application-groups",
    "keychain-access-groups",
    "aps-environment",
    "com.apple.developer.icloud-services",
    "com.apple.developer.icloud-container-identifiers",
    "com.apple.developer.in-app-payments",
    "com.apple.developer.networking.HotspotConfiguration",
    "com.apple.developer.networking.networkextension",
    "com.apple.developer.networking.vpn.api",
    "com.apple.developer.healthkit",
    "com.apple.developer.homekit",
    "com.apple.developer.siri",
    "com.apple.developer.usernotifications.communication",
    "com.apple.developer.kernel.extended-virtual-addressing",
    "com.apple.security.get-task-allow",
    "com.apple.developer.devicecheck.appattest-environment",
]


@mcp.tool()
def flex_entitlements(session_id: str = "") -> dict:
    """Dump the app's entitlements (signed values, queried via SecTaskCopyValueForEntitlement)."""
    try:
        _, session = _get_session(session_id)
        keys_j = json.dumps(_KNOWN_ENTITLEMENTS)
        r = exec_js(session, f"""
        (function(){{
            var SecTaskCreateFromSelf = new NativeFunction(
                Module.findExportByName('Security', 'SecTaskCreateFromSelf'),
                'pointer', ['pointer']);
            var SecTaskCopyValueForEntitlement = new NativeFunction(
                Module.findExportByName('Security', 'SecTaskCopyValueForEntitlement'),
                'pointer', ['pointer', 'pointer', 'pointer']);
            var task = SecTaskCreateFromSelf(ptr(0));
            if (task.isNull()) return JSON.stringify({{error: 'SecTaskCreateFromSelf failed'}});
            var keys = {keys_j};
            var out = {{}};
            for (var i = 0; i < keys.length; i++) {{
                var keyStr = ObjC.classes.NSString.stringWithString_(keys[i]);
                var val = SecTaskCopyValueForEntitlement(task, keyStr.handle, ptr(0));
                if (!val.isNull()) {{
                    try {{
                        out[keys[i]] = String(new ObjC.Object(val));
                    }} catch(e) {{ out[keys[i]] = '<unreadable>'; }}
                }}
            }}
            return JSON.stringify(out);
        }})()
        """, timeout=15)
        if r.get("ok"):
            data = json.loads(r["result"])
            if "error" in data:
                return {"success": False, "error": data["error"]}
            return {"success": True, "count": len(data), "entitlements": data}
        return {"success": False, "error": str(r)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_pasteboard(session_id: str = "") -> dict:
    """Read the system pasteboard (general UIPasteboard)."""
    try:
        _, session = _get_session(session_id)
        r = exec_js(session, """
        (function(){
            var pb = ObjC.classes.UIPasteboard.generalPasteboard();
            return JSON.stringify({
                string: pb.string() ? String(pb.string()) : null,
                has_url: !!pb.URL(),
                url: pb.URL() ? String(pb.URL()) : null,
                has_image: pb.image() ? true : false,
                num_items: pb.numberOfItems()
            });
        })()
        """)
        if r.get("ok"):
            return {"success": True, **json.loads(r["result"])}
        return {"success": False, "error": str(r)}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================
# MEMORY / STATIC
# ============================================================

@mcp.tool()
def flex_memory_scan(pattern: str, encoding: str = "ascii", max_hits: int = 50, session_id: str = "") -> dict:
    """Scan writable memory regions for a byte pattern. Find secrets/tokens in the heap.

    Args:
        pattern: The needle. If encoding='hex' it's bytes (e.g. 'deadbeef'); else ASCII text.
        encoding: 'ascii' (default) or 'hex'.
        max_hits: Stop after this many matches.
    """
    try:
        _, session = _get_session(session_id)
        if encoding == "hex":
            hex_str = pattern.replace(" ", "").replace("0x", "")
            if len(hex_str) % 2 != 0:
                return {"success": False, "error": "hex pattern must have even length"}
            frida_pattern = " ".join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
        else:
            frida_pattern = " ".join(f"{ord(c):02x}" for c in pattern)
        fp = json.dumps(frida_pattern)
        ctx_size = max(16, min(len(pattern) * 2 + 16, 64))
        r = exec_js(session, f"""
        (function(){{
            var ranges = Process.enumerateRanges({{protection: 'r--', coalesce: true}});
            var hits = [];
            for (var i = 0; i < ranges.length && hits.length < {int(max_hits)}; i++) {{
                var r = ranges[i];
                try {{
                    Memory.scanSync(r.base, r.size, {fp}).forEach(function(m) {{
                        if (hits.length >= {int(max_hits)}) return;
                        var ctx;
                        try {{ ctx = m.address.readByteArray({ctx_size}); }} catch(e) {{ ctx = null; }}
                        var hex = '';
                        if (ctx) {{
                            var u = new Uint8Array(ctx);
                            for (var k = 0; k < u.length; k++) {{
                                hex += (u[k] < 16 ? '0' : '') + u[k].toString(16);
                            }}
                        }}
                        hits.push({{
                            address: m.address.toString(),
                            region_base: r.base.toString(),
                            region_size: r.size,
                            file: r.file ? r.file.path : null,
                            context_hex: hex
                        }});
                    }});
                }} catch(e) {{}}
            }}
            return JSON.stringify(hits);
        }})()
        """, timeout=60)
        if r.get("ok"):
            hits = json.loads(r["result"])
            return {"success": True, "count": len(hits), "hits": hits}
        return {"success": False, "error": str(r)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_strings(path: str, min_length: int = 6, max_results: int = 1000, search: str = "", local: bool = False, session_id: str = "") -> dict:
    """Extract printable ASCII strings from a binary file (host-local or device-side).

    Args:
        path: File path. If local=True, host filesystem; otherwise device sandbox.
        min_length: Minimum run length.
        max_results: Hard cap.
        search: Optional case-insensitive substring filter.
    """
    try:
        if local:
            with open(path, "rb") as f:
                data = f.read()
        else:
            _, session = _get_session(session_id)
            p = json.dumps(path)
            r = exec_js(session, f"""
            (function(){{
                var d = ObjC.classes.NSData.dataWithContentsOfFile_({p});
                if (!d) return JSON.stringify({{error: 'cannot read'}});
                return JSON.stringify({{size: d.length()}});
            }})()
            """)
            if not r.get("ok"):
                return {"success": False, "error": str(r)}
            meta = json.loads(r["result"])
            if "error" in meta:
                return {"success": False, "error": meta["error"]}
            pull = flex_pull_file(device_path=path, output_path=path.replace("/", "_") + ".tmp",
                                  session_id=session_id)
            if not pull.get("success"):
                return {"success": False, "error": pull.get("error")}
            with open(pull["output_path"], "rb") as f:
                data = f.read()
            try:
                os.unlink(pull["output_path"])
            except Exception:
                pass

        runs = []
        current = bytearray()
        search_lc = search.lower() if search else ""
        for b in data:
            if 0x20 <= b < 0x7f:
                current.append(b)
            else:
                if len(current) >= min_length:
                    s = current.decode("ascii", errors="replace")
                    if not search_lc or search_lc in s.lower():
                        runs.append(s)
                        if len(runs) >= max_results:
                            break
                current = bytearray()
        if len(current) >= min_length and len(runs) < max_results:
            s = current.decode("ascii", errors="replace")
            if not search_lc or search_lc in s.lower():
                runs.append(s)
        return {"success": True, "count": len(runs), "strings": runs}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================
# LOGS
# ============================================================

_LOG_HOOK_JS = """
(function(){
    var log = [];
    var maxLog = 2000;

    function record(prefix, text) {
        log.push({src: prefix, text: text, time: Date.now()});
        if (log.length > maxLog) log.shift();
    }

    try {
        var nslog = Module.findExportByName(null, 'NSLog');
        if (nslog) {
            Interceptor.attach(nslog, {
                onEnter: function(args) {
                    try {
                        var fmt = new ObjC.Object(args[0]);
                        record('NSLog', String(fmt).substring(0, 500));
                    } catch(e) {}
                }
            });
        }
    } catch(e) {}

    try {
        var oslog = Module.findExportByName(null, '_os_log_impl');
        if (oslog) {
            Interceptor.attach(oslog, {
                onEnter: function(args) {
                    try {
                        var fmt = args[2].readUtf8String();
                        record('os_log', (fmt || '').substring(0, 500));
                    } catch(e) {}
                }
            });
        }
    } catch(e) {}

    rpc.exports = {
        drain: function(limit, clear) {
            var slice = limit > 0 ? log.slice(-limit) : log.slice();
            if (clear) log = [];
            return slice;
        }
    };

    send({__hook_init: true, ok: true});
})();
"""


@mcp.tool()
def flex_logs(enable: bool = True, session_id: str = "") -> dict:
    """Capture NSLog and os_log calls. Pair with flex_log_events to drain the buffer."""
    try:
        sid, session = _get_session(session_id)
        if not enable:
            return _remove_named_hook(sid, "logs")
        if sid in _named_hooks and "logs" in _named_hooks[sid]:
            return {"success": True, "already_installed": True}
        ack_event = threading.Event()
        ack = {"ok": False, "error": ""}

        def on_msg(msg, data):
            if msg["type"] != "send":
                return
            p = msg["payload"]
            if isinstance(p, dict) and p.get("__hook_init"):
                ack["ok"] = p.get("ok", False)
                ack["error"] = p.get("error", "")
                ack_event.set()

        script = session.create_script(_LOG_HOOK_JS)
        script.on("message", on_msg)
        script.load()
        ack_event.wait(5)
        if not ack["ok"]:
            try:
                script.unload()
            except Exception:
                pass
            return {"success": False, "error": ack["error"] or "init timeout"}
        _named_hooks.setdefault(sid, {})["logs"] = {"script": script, "events": []}
        return {"success": True, "installed": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_log_events(limit: int = 100, clear: bool = False, session_id: str = "") -> dict:
    """Drain captured log events (requires flex_logs(enable=True))."""
    try:
        sid, _ = _get_session(session_id)
        h = _named_hooks.get(sid, {}).get("logs")
        if not h:
            return {"success": True, "events": [], "message": "Log capture not installed."}
        events = h["script"].exports_sync.drain(int(limit), bool(clear))
        return {"success": True, "count": len(events), "events": events}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================
# HELPERS / ANALYZERS (pure Python — no device round-trip)
# ============================================================

@mcp.tool()
def flex_decode_jwt(token: str) -> dict:
    """Decode a JWT and flag weak/missing security properties (alg=none, HS, no exp, etc.)."""
    try:
        token = token.strip()
        if token.lower().startswith("bearer "):
            token = token[7:].strip()
        parts = token.split(".")
        if len(parts) < 2:
            return {"success": False, "error": "not a JWT (need 2+ dot-separated parts)"}

        def _b64(p):
            pad = "=" * (-len(p) % 4)
            return base64.urlsafe_b64decode(p + pad).decode("utf-8", errors="replace")

        header = json.loads(_b64(parts[0]))
        payload = json.loads(_b64(parts[1]))
        warnings = []
        alg = (header.get("alg") or "").lower()
        if alg == "none":
            warnings.append({"severity": "critical", "issue": "alg=none (unsigned)"})
        if alg.startswith("hs"):
            warnings.append({"severity": "info", "issue": f"HMAC ({alg}) — server secret must be strong"})
        if "kid" in header:
            warnings.append({"severity": "info", "issue": f"kid={header['kid']} — possible kid injection / file path"})
        if "exp" not in payload:
            warnings.append({"severity": "medium", "issue": "no exp claim — token does not expire"})
        else:
            import time as _t
            if payload["exp"] - _t.time() > 365 * 24 * 3600:
                warnings.append({"severity": "medium", "issue": "exp > 1 year (very long-lived token)"})
        if "iss" not in payload:
            warnings.append({"severity": "low", "issue": "no iss claim"})
        if "aud" not in payload:
            warnings.append({"severity": "low", "issue": "no aud claim"})
        return {
            "success": True,
            "header": header,
            "payload": payload,
            "signature_present": len(parts) == 3 and bool(parts[2]),
            "warnings": warnings,
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================
# STORAGE
# ============================================================

@mcp.tool()
def flex_userdefaults(search: str = "", session_id: str = "") -> dict:
    """Browse NSUserDefaults.

    Args:
        search: Optional substring filter for keys.
    """
    try:
        _, session = _get_session(session_id)
        sj = json.dumps(search)
        r = exec_js(session, f"""
        (function(){{
            var ud = ObjC.classes.NSUserDefaults.standardUserDefaults();
            var dict = ud.dictionaryRepresentation();
            var keys = dict.allKeys();
            var entries = [];
            var filter = {sj};
            for (var i = 0; i < keys.count(); i++) {{
                try {{
                    var key = String(keys.objectAtIndex_(i));
                    if (!filter || key.toLowerCase().indexOf(filter.toLowerCase()) !== -1) {{
                        var val = dict.objectForKey_(keys.objectAtIndex_(i));
                        var valStr = val ? String(val) : 'nil';
                        if (valStr.length > 300) valStr = valStr.substring(0, 300);
                        entries.push({{key: key, value: valStr}});
                    }}
                }} catch(e) {{}}
            }}
            return JSON.stringify(entries);
        }})()
        """)
        if r.get("ok"):
            return {"success": True, "entries": json.loads(r["result"])}
        return {"success": False, "error": str(r)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_set_userdefault(key: str, value: str, session_id: str = "") -> dict:
    """Set a value in NSUserDefaults (stored as NSString).

    Args:
        key: UserDefaults key.
        value: Value to set.
    """
    try:
        _, session = _get_session(session_id)
        k, v = json.dumps(key), json.dumps(value)
        exec_js(session, f"""
        (function(){{
            var ud = ObjC.classes.NSUserDefaults.standardUserDefaults();
            ud.setObject_forKey_(ObjC.classes.NSString.stringWithString_({v}), {k});
            ud.synchronize();
            return 'ok';
        }})()
        """)
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_keychain(session_id: str = "") -> dict:
    """Dump generic password keychain items (service, account, value)."""
    try:
        _, session = _get_session(session_id)
        r = exec_js(session, """
        (function(){
            var q = ObjC.classes.NSMutableDictionary.dictionary();
            q.setObject_forKey_('genp', 'class');
            q.setObject_forKey_(ObjC.classes.NSNumber.numberWithBool_(true), 'r_Attributes');
            q.setObject_forKey_(ObjC.classes.NSNumber.numberWithBool_(true), 'r_Data');
            q.setObject_forKey_('m_LimitAll', 'm_Limit');

            var copyMatch = new NativeFunction(
                Module.findExportByName('Security', 'SecItemCopyMatching'),
                'int', ['pointer', 'pointer']
            );
            var resPtr = Memory.alloc(Process.pointerSize);
            var status = copyMatch(q.handle, resPtr);
            if (status !== 0) return JSON.stringify({error: 'SecItemCopyMatching status ' + status});

            var arr = new ObjC.Object(Memory.readPointer(resPtr));
            var out = [];
            for (var i = 0; i < arr.count(); i++) {
                var item = arr.objectAtIndex_(i);
                var svc = item.objectForKey_('svce');
                var acct = item.objectForKey_('acct');
                var grp = item.objectForKey_('agrp');
                var data = item.objectForKey_('v_Data');
                var dataStr = '';
                if (data) {
                    try {
                        var s = ObjC.classes.NSString.alloc().initWithData_encoding_(data, 4);
                        dataStr = s ? String(s) : '<binary ' + data.length() + ' bytes>';
                    } catch(e) { dataStr = '<binary>'; }
                }
                out.push({
                    service: svc ? String(svc) : '',
                    account: acct ? String(acct) : '',
                    access_group: grp ? String(grp) : '',
                    value: dataStr
                });
            }
            return JSON.stringify(out);
        })()
        """, timeout=20)
        if r.get("ok"):
            data = json.loads(r["result"])
            if isinstance(data, dict) and "error" in data:
                return {"success": False, "error": data["error"]}
            return {"success": True, "count": len(data), "items": data}
        return {"success": False, "error": str(r)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_cookies(session_id: str = "") -> dict:
    """Dump all cookies in NSHTTPCookieStorage."""
    try:
        _, session = _get_session(session_id)
        r = exec_js(session, """
        (function(){
            var store = ObjC.classes.NSHTTPCookieStorage.sharedHTTPCookieStorage();
            var cookies = store.cookies();
            var out = [];
            for (var i = 0; i < cookies.count(); i++) {
                var c = cookies.objectAtIndex_(i);
                try {
                    out.push({
                        name: String(c.name()),
                        value: String(c.value()),
                        domain: String(c.domain()),
                        path: String(c.path()),
                        secure: c.isSecure() ? true : false,
                        http_only: c.isHTTPOnly() ? true : false,
                        expires: c.expiresDate() ? String(c.expiresDate()) : null
                    });
                } catch(e) {}
            }
            return JSON.stringify(out);
        })()
        """, timeout=15)
        if r.get("ok"):
            data = json.loads(r["result"])
            return {"success": True, "count": len(data), "cookies": data}
        return {"success": False, "error": str(r)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_files(path: str = "", session_id: str = "") -> dict:
    """List files in the app sandbox. Empty path means the app HOME directory.

    Args:
        path: Absolute path, or empty for sandbox home.
    """
    try:
        _, session = _get_session(session_id)
        p = json.dumps(path)
        r = exec_js(session, f"""
        (function(){{
            var fm = ObjC.classes.NSFileManager.defaultManager();
            var path = {p};
            if (!path || path === '') {{
                path = String(ObjC.classes.NSProcessInfo.processInfo().environment().objectForKey_('HOME'));
            }}
            var err = Memory.alloc(Process.pointerSize);
            var contents = fm.contentsOfDirectoryAtPath_error_(path, err);
            if (!contents) return JSON.stringify({{error: 'Cannot read directory', path: path}});
            var out = [];
            for (var i = 0; i < contents.count(); i++) {{
                var name = String(contents.objectAtIndex_(i));
                var full = path + '/' + name;
                var isDirBuf = Memory.alloc(1);
                fm.fileExistsAtPath_isDirectory_(full, isDirBuf);
                var attrs = fm.attributesOfItemAtPath_error_(full, err);
                var size = -1;
                if (attrs) {{
                    var s = attrs.objectForKey_('NSFileSize');
                    if (s) size = s.longLongValue();
                }}
                out.push({{
                    name: name,
                    path: full,
                    is_dir: Memory.readU8(isDirBuf) !== 0,
                    size: size
                }});
            }}
            return JSON.stringify({{path: path, entries: out}});
        }})()
        """, timeout=20)
        if r.get("ok"):
            data = json.loads(r["result"])
            if "error" in data:
                return {"success": False, "error": data["error"], "path": data.get("path")}
            return {"success": True, "path": data["path"], "count": len(data["entries"]), "entries": data["entries"]}
        return {"success": False, "error": str(r)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_read_file(path: str, max_bytes: int = 65536, session_id: str = "") -> dict:
    """Read a file from the device as UTF-8 (reports as binary otherwise).

    Args:
        path: Absolute path.
        max_bytes: Truncate cap.
    """
    try:
        _, session = _get_session(session_id)
        p = json.dumps(path)
        r = exec_js(session, f"""
        (function(){{
            var data = ObjC.classes.NSData.dataWithContentsOfFile_({p});
            if (!data) return JSON.stringify({{error: 'Cannot read file'}});
            var len = data.length();
            var slice = len > {int(max_bytes)} ? data.subdataWithRange_([0, {int(max_bytes)}]) : data;
            var s = ObjC.classes.NSString.alloc().initWithData_encoding_(slice, 4);
            return JSON.stringify({{
                size: len,
                truncated: len > {int(max_bytes)},
                content: s ? String(s) : null,
                binary: !s
            }});
        }})()
        """, timeout=20)
        if r.get("ok"):
            data = json.loads(r["result"])
            if "error" in data:
                return {"success": False, "error": data["error"]}
            return {"success": True, **data}
        return {"success": False, "error": str(r)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_sqlite_list(session_id: str = "") -> dict:
    """Find SQLite databases (.sqlite, .sqlite3, .db) in the app sandbox."""
    try:
        _, session = _get_session(session_id)
        r = exec_js(session, """
        (function(){
            var fm = ObjC.classes.NSFileManager.defaultManager();
            var home = String(ObjC.classes.NSProcessInfo.processInfo().environment().objectForKey_('HOME'));
            var enumerator = fm.enumeratorAtPath_(home);
            var out = [];
            var p;
            while ((p = enumerator.nextObject()) !== null) {
                var name = String(p);
                var lower = name.toLowerCase();
                if (lower.endsWith('.sqlite') || lower.endsWith('.sqlite3') || lower.endsWith('.db')) {
                    var full = home + '/' + name;
                    var err = Memory.alloc(Process.pointerSize);
                    var attrs = fm.attributesOfItemAtPath_error_(full, err);
                    var size = -1;
                    if (attrs) {
                        var s = attrs.objectForKey_('NSFileSize');
                        if (s) size = s.longLongValue();
                    }
                    out.push({path: full, size: size});
                }
                if (out.length >= 200) break;
            }
            return JSON.stringify(out);
        })()
        """, timeout=30)
        if r.get("ok"):
            data = json.loads(r["result"])
            return {"success": True, "count": len(data), "databases": data}
        return {"success": False, "error": str(r)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_sqlite_query(path: str, sql: str, limit: int = 100, session_id: str = "") -> dict:
    """Run a SQL query against a SQLite database in the app sandbox.

    Args:
        path: Absolute path to .sqlite/.db file.
        sql: SQL statement.
        limit: Row cap for SELECTs.
    """
    try:
        _, session = _get_session(session_id)
        p, q, lim = json.dumps(path), json.dumps(sql), int(limit)
        r = exec_js(session, f"""
        (function(){{
            function findFn(name) {{
                return Module.findExportByName('libsqlite3.dylib', name)
                    || Module.findExportByName(null, name);
            }}
            var open = new NativeFunction(findFn('sqlite3_open'),'int',['pointer','pointer']);
            var prep = new NativeFunction(findFn('sqlite3_prepare_v2'),'int',['pointer','pointer','int','pointer','pointer']);
            var step = new NativeFunction(findFn('sqlite3_step'),'int',['pointer']);
            var ncol = new NativeFunction(findFn('sqlite3_column_count'),'int',['pointer']);
            var cnam = new NativeFunction(findFn('sqlite3_column_name'),'pointer',['pointer','int']);
            var ctxt = new NativeFunction(findFn('sqlite3_column_text'),'pointer',['pointer','int']);
            var fin  = new NativeFunction(findFn('sqlite3_finalize'),'int',['pointer']);
            var clos = new NativeFunction(findFn('sqlite3_close'),'int',['pointer']);
            var errm = new NativeFunction(findFn('sqlite3_errmsg'),'pointer',['pointer']);

            var dbPtr = Memory.alloc(Process.pointerSize);
            var pathPtr = Memory.allocUtf8String({p});
            if (open(pathPtr, dbPtr) !== 0) return JSON.stringify({{error: 'open failed'}});
            var db = Memory.readPointer(dbPtr);

            var stmtPtr = Memory.alloc(Process.pointerSize);
            var sqlPtr = Memory.allocUtf8String({q});
            if (prep(db, sqlPtr, -1, stmtPtr, ptr(0)) !== 0) {{
                var msg = errm(db).readUtf8String();
                clos(db);
                return JSON.stringify({{error: 'prepare: ' + msg}});
            }}
            var stmt = Memory.readPointer(stmtPtr);

            var ncols = ncol(stmt);
            var cols = [];
            for (var i = 0; i < ncols; i++) cols.push(cnam(stmt, i).readUtf8String());

            var rows = [];
            while (rows.length < {lim}) {{
                var rc = step(stmt);
                if (rc !== 100) break;
                var row = {{}};
                for (var i = 0; i < ncols; i++) {{
                    var p2 = ctxt(stmt, i);
                    row[cols[i]] = p2.isNull() ? null : p2.readUtf8String();
                }}
                rows.push(row);
            }}

            fin(stmt);
            clos(db);
            return JSON.stringify({{columns: cols, rows: rows}});
        }})()
        """, timeout=30)
        if r.get("ok"):
            data = json.loads(r["result"])
            if "error" in data:
                return {"success": False, "error": data["error"]}
            return {"success": True, **data}
        return {"success": False, "error": str(r)}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================
# RUNTIME
# ============================================================

@mcp.tool()
def flex_list_classes(search: str = "", limit: int = 100, session_id: str = "") -> dict:
    """List ObjC classes matching a substring.

    Args:
        search: Optional substring filter.
        limit: Max classes returned.
    """
    try:
        _, session = _get_session(session_id)
        s = json.dumps(search)
        lim = int(limit)
        r = exec_js(session, f"""
        (function(){{
            var classes = Object.keys(ObjC.classes);
            var matches = [];
            var filter = {s};
            for (var i = 0; i < classes.length; i++) {{
                if (!filter || classes[i].indexOf(filter) !== -1) {{
                    var cls = ObjC.classes[classes[i]];
                    var m = cls && cls.$ownMethods ? cls.$ownMethods.length : 0;
                    matches.push({{name: classes[i], methods: m}});
                    if (matches.length >= {lim}) break;
                }}
            }}
            return JSON.stringify({{matches: matches, total: classes.length}});
        }})()
        """, timeout=30)
        if r.get("ok"):
            data = json.loads(r["result"])
            return {"success": True, "count": len(data["matches"]), "total_classes": data["total"], "classes": data["matches"]}
        return {"success": False, "error": str(r)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_methods(class_name: str, include_inherited: bool = False, session_id: str = "") -> dict:
    """List methods of an ObjC class.

    Args:
        class_name: Class name (e.g., 'NSURLSession').
        include_inherited: Include methods from parent classes.
    """
    try:
        _, session = _get_session(session_id)
        cn = json.dumps(class_name)
        prop = "$methods" if include_inherited else "$ownMethods"
        r = exec_js(session, f"""
        (function(){{
            var cls = ObjC.classes[{cn}];
            if (!cls) return JSON.stringify({{error: 'Class not found'}});
            return JSON.stringify({{
                methods: cls.{prop},
                superclass: cls.$superClass ? cls.$superClass.$className : null
            }});
        }})()
        """, timeout=20)
        if r.get("ok"):
            data = json.loads(r["result"])
            if "error" in data:
                return {"success": False, "error": data["error"]}
            return {
                "success": True,
                "count": len(data["methods"]),
                "superclass": data["superclass"],
                "methods": data["methods"],
            }
        return {"success": False, "error": str(r)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_instances(class_name: str, limit: int = 20, session_id: str = "") -> dict:
    """Find live instances of a class on the heap.

    Args:
        class_name: ObjC class name.
        limit: Max instances to return.
    """
    try:
        _, session = _get_session(session_id)
        cn = json.dumps(class_name)
        lim = int(limit)
        r = exec_js(session, f"""
        (function(){{
            var cls = ObjC.classes[{cn}];
            if (!cls) return JSON.stringify({{error: 'Class not found'}});
            var instances = ObjC.chooseSync(cls);
            var out = [];
            for (var i = 0; i < instances.length && i < {lim}; i++) {{
                try {{
                    out.push({{
                        address: instances[i].handle.toString(),
                        description: String(instances[i]).substring(0, 200)
                    }});
                }} catch(e) {{}}
            }}
            return JSON.stringify({{total: instances.length, returned: out.length, instances: out}});
        }})()
        """, timeout=30)
        if r.get("ok"):
            data = json.loads(r["result"])
            if "error" in data:
                return {"success": False, "error": data["error"]}
            return {"success": True, **data}
        return {"success": False, "error": str(r)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_inspect(target: str, session_id: str = "") -> dict:
    """Inspect an instance or class: class name, description, ivars.

    Args:
        target: Pointer ('0x12345678') or class name.
    """
    try:
        _, session = _get_session(session_id)
        t = json.dumps(target)
        r = exec_js(session, f"""
        (function(){{
            var target = {t};
            var obj;
            if (target.indexOf('0x') === 0) {{
                obj = new ObjC.Object(ptr(target));
            }} else {{
                obj = ObjC.classes[target];
                if (!obj) return JSON.stringify({{error: 'Class not found'}});
            }}
            var info = {{
                class: obj.$className || '<class>',
                description: String(obj).substring(0, 300),
                ivars: {{}},
                methods_count: obj.$ownMethods ? obj.$ownMethods.length : 0
            }};
            if (obj.$ivars) {{
                var count = 0;
                for (var k in obj.$ivars) {{
                    if (count++ >= 50) break;
                    try {{
                        var v = obj.$ivars[k];
                        info.ivars[k] = v !== null && v !== undefined ? String(v).substring(0, 200) : 'nil';
                    }} catch(e) {{ info.ivars[k] = '<unreadable>'; }}
                }}
            }}
            return JSON.stringify(info);
        }})()
        """, timeout=20)
        if r.get("ok"):
            data = json.loads(r["result"])
            if "error" in data:
                return {"success": False, "error": data["error"]}
            return {"success": True, **data}
        return {"success": False, "error": str(r)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_call(target: str, selector: str, args: list = None, session_id: str = "") -> dict:
    """Invoke an ObjC selector on a class or instance.

    Args:
        target: Class name (e.g., 'NSUserDefaults') or instance pointer ('0x12345678').
        selector: Method selector using '_' for ':' (e.g., 'objectForKey_').
        args: Args list. Strings -> NSString, numbers -> NSNumber, booleans -> NSNumber.
    """
    try:
        _, session = _get_session(session_id)
        t = json.dumps(target)
        sel = json.dumps(selector)
        aj = json.dumps(args or [])
        r = exec_js(session, f"""
        (function(){{
            var target = {t};
            var obj;
            if (target.indexOf('0x') === 0) {{
                obj = new ObjC.Object(ptr(target));
            }} else {{
                obj = ObjC.classes[target];
                if (!obj) return JSON.stringify({{error: 'Class not found'}});
            }}
            var sel = {sel};
            var fn = obj[sel];
            if (!fn) return JSON.stringify({{error: 'Selector not found: ' + sel}});
            var raw = {aj};
            var conv = raw.map(function(a){{
                if (a === null || a === undefined) return null;
                if (typeof a === 'string') return ObjC.classes.NSString.stringWithString_(a);
                if (typeof a === 'boolean') return ObjC.classes.NSNumber.numberWithBool_(a);
                if (typeof a === 'number') return ObjC.classes.NSNumber.numberWithDouble_(a);
                return a;
            }});
            var result;
            try {{ result = fn.apply(obj, conv); }}
            catch(e) {{ return JSON.stringify({{error: 'Invocation failed: ' + e.message}}); }}
            if (result === undefined || result === null) return JSON.stringify({{result: null}});
            var addr = null;
            try {{ addr = result.handle ? result.handle.toString() : null; }} catch(e) {{}}
            return JSON.stringify({{
                result: String(result).substring(0, 2000),
                address: addr,
                class: result.$className || typeof result
            }});
        }})()
        """, timeout=20)
        if r.get("ok"):
            data = json.loads(r["result"])
            if "error" in data:
                return {"success": False, "error": data["error"]}
            return {"success": True, **data}
        return {"success": False, "error": str(r)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_execute(js_code: str, session_id: str = "") -> dict:
    """Execute arbitrary JavaScript in the app via Frida.

    Args:
        js_code: JavaScript expression. The ObjC namespace is available.
    """
    try:
        _, session = _get_session(session_id)
        r = exec_js(session, js_code, timeout=30)
        return {"success": r.get("ok", False), "result": r}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================
# METHOD TRACING
# ============================================================

def _trace_script_src(class_name, selector, hook_id, scope):
    cn = json.dumps(class_name)
    sel = json.dumps(selector)
    hid = json.dumps(hook_id)
    # scope: 'instance' (- method) or 'class' (+ method) or 'auto'
    sc = json.dumps(scope)
    return f"""
    (function(){{
        try {{
            var cls = ObjC.classes[{cn}];
            if (!cls) {{ send({{__trace_init: true, ok: false, error: 'Class not found'}}); return; }}
            var sel = {sel};
            var scope = {sc};
            var m;
            if (scope === 'class') {{
                m = cls['+ ' + sel.replace(/_/g, ':')];
            }} else if (scope === 'instance') {{
                m = cls['- ' + sel.replace(/_/g, ':')];
            }} else {{
                m = cls[sel] || cls['- ' + sel.replace(/_/g, ':')] || cls['+ ' + sel.replace(/_/g, ':')];
            }}
            if (!m) {{ send({{__trace_init: true, ok: false, error: 'Selector not found: ' + sel}}); return; }}
            var argTypes = m.argumentTypes || [];
            var argCount = Math.max(0, argTypes.length - 2);

            Interceptor.attach(m.implementation, {{
                onEnter: function(args) {{
                    var argInfo = [];
                    for (var i = 0; i < argCount && i < 8; i++) {{
                        try {{ argInfo.push(String(ObjC.Object(args[i + 2])).substring(0, 200)); }}
                        catch(e) {{ argInfo.push('<' + args[i + 2] + '>'); }}
                    }}
                    send({{
                        hook_id: {hid}, type: 'call',
                        class: {cn}, method: sel, args: argInfo, time: Date.now()
                    }});
                }},
                onLeave: function(retval) {{
                    var rv;
                    try {{ rv = String(ObjC.Object(retval)).substring(0, 200); }}
                    catch(e) {{ rv = '<' + retval + '>'; }}
                    send({{
                        hook_id: {hid}, type: 'return',
                        class: {cn}, method: sel, retval: rv, time: Date.now()
                    }});
                }}
            }});
            send({{__trace_init: true, ok: true, hooked: {cn} + ' ' + sel, args: argCount}});
        }} catch(e) {{
            send({{__trace_init: true, ok: false, error: e.message}});
        }}
    }})();
    """


@mcp.tool()
def flex_trace_start(class_name: str, selector: str, scope: str = "auto", session_id: str = "") -> dict:
    """Hook an ObjC method and stream call events to a buffer.

    Args:
        class_name: Class name (e.g., 'NSURLSession').
        selector: Selector with '_' for ':' (e.g., 'dataTaskWithRequest_completionHandler_').
        scope: 'instance', 'class', or 'auto' (default).
    """
    global _trace_counter
    try:
        sid, session = _get_session(session_id)
        _trace_counter += 1
        hook_id = f"hook_{_trace_counter}"
        events = []
        max_events = 1000
        init_ack = {"ok": False, "error": ""}
        ack_event = threading.Event()

        def on_msg(msg, data):
            if msg["type"] != "send":
                return
            p = msg["payload"]
            if isinstance(p, dict):
                if p.get("__trace_init"):
                    init_ack["ok"] = p.get("ok", False)
                    init_ack["error"] = p.get("error", "")
                    ack_event.set()
                else:
                    events.append(p)
                    while len(events) > max_events:
                        events.pop(0)

        script = session.create_script(_trace_script_src(class_name, selector, hook_id, scope))
        script.on("message", on_msg)
        script.load()
        ack_event.wait(5)
        if not init_ack["ok"]:
            try:
                script.unload()
            except Exception:
                pass
            return {"success": False, "error": init_ack["error"] or "init timeout"}

        _traces.setdefault(sid, {})[hook_id] = {
            "script": script,
            "events": events,
            "class": class_name,
            "method": selector,
            "scope": scope,
        }
        return {"success": True, "hook_id": hook_id, "class": class_name, "method": selector, "scope": scope}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_trace_logs(hook_id: str = "", limit: int = 100, clear: bool = False, session_id: str = "") -> dict:
    """Read buffered trace events.

    Args:
        hook_id: Specific hook id, or empty for all hooks in the session.
        limit: Max events per hook.
        clear: Drop returned events from the buffer.
    """
    try:
        sid, _ = _get_session(session_id)
        hooks = _traces.get(sid, {})
        if not hooks:
            return {"success": True, "events": [], "message": "No active hooks"}
        targets = [hook_id] if hook_id else list(hooks.keys())
        out = []
        for hid in targets:
            if hid not in hooks:
                continue
            buf = hooks[hid]["events"]
            slice_ = buf[-limit:] if limit else list(buf)
            out.extend(slice_)
            if clear:
                for _ in slice_:
                    if buf:
                        buf.pop(0)
        return {"success": True, "count": len(out), "events": out}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_trace_list(session_id: str = "") -> dict:
    """List active method-trace hooks in the session."""
    try:
        sid, _ = _get_session(session_id)
        hooks = _traces.get(sid, {})
        return {
            "success": True,
            "hooks": [
                {
                    "hook_id": hid,
                    "class": h["class"],
                    "method": h["method"],
                    "scope": h.get("scope", "auto"),
                    "buffered_events": len(h["events"]),
                }
                for hid, h in hooks.items()
            ],
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_trace_stop(hook_id: str = "", session_id: str = "") -> dict:
    """Stop a trace hook. Empty hook_id stops all hooks in the session."""
    try:
        sid, _ = _get_session(session_id)
        hooks = _traces.get(sid, {})
        targets = [hook_id] if hook_id else list(hooks.keys())
        stopped = []
        for hid in targets:
            if hid not in hooks:
                continue
            try:
                hooks[hid]["script"].unload()
            except Exception:
                pass
            del hooks[hid]
            stopped.append(hid)
        return {"success": True, "stopped": stopped}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================
# BINARY ANALYSIS (frida-ios-dump style)
# ============================================================

@mcp.tool()
def flex_modules(search: str = "", limit: int = 100, session_id: str = "") -> dict:
    """List loaded Mach-O modules (name, base, size, path).

    Args:
        search: Optional substring filter on module name.
        limit: Max modules returned.
    """
    try:
        _, session = _get_session(session_id)
        s = json.dumps(search)
        lim = int(limit)
        r = exec_js(session, f"""
        (function(){{
            var mods = Process.enumerateModules();
            var filter = {s};
            var out = [];
            for (var i = 0; i < mods.length && out.length < {lim}; i++) {{
                var m = mods[i];
                if (!filter || m.name.indexOf(filter) !== -1) {{
                    out.push({{
                        name: m.name,
                        base: m.base.toString(),
                        size: m.size,
                        path: m.path
                    }});
                }}
            }}
            return JSON.stringify({{total: mods.length, modules: out}});
        }})()
        """, timeout=20)
        if r.get("ok"):
            data = json.loads(r["result"])
            return {"success": True, "total": data["total"], "count": len(data["modules"]), "modules": data["modules"]}
        return {"success": False, "error": str(r)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_pull_file(device_path: str, output_path: str, max_size: int = 0, session_id: str = "") -> dict:
    """Pull a file from the device sandbox to a local path (binary-safe, chunked).

    Args:
        device_path: Absolute path on the iOS device.
        output_path: Absolute path on the host where the bytes will be written.
        max_size: Optional cap in bytes (0 = no limit).
    """
    try:
        _, session = _get_session(session_id)
        p = json.dumps(device_path)
        cap = int(max_size)
        js = f"""
        (function(){{
            try {{
                var data = ObjC.classes.NSData.dataWithContentsOfFile_({p});
                if (!data) {{ send({{__error: 'Cannot read'}}); send({{__done: true}}); return; }}
                var len = data.length();
                var cap = {cap};
                var total = (cap > 0 && cap < len) ? cap : len;
                var chunkSize = 4 * 1024 * 1024;
                var sent = 0;
                var idx = 0;
                var basePtr = data.bytes();
                while (sent < total) {{
                    var size = Math.min(chunkSize, total - sent);
                    var ab = basePtr.add(sent).readByteArray(size);
                    send({{chunk: idx, size: size}}, ab);
                    sent += size;
                    idx++;
                }}
                send({{__done: true, total: total, file_size: len}});
            }} catch(e) {{
                send({{__error: e.message}});
                send({{__done: true}});
            }}
        }})();
        """
        result = exec_js_stream(session, js, timeout=600)
        if result["error"]:
            return {"success": False, "error": result["error"]}
        ordered = {}
        for payload, data in result["chunks"]:
            if isinstance(payload, dict) and "chunk" in payload and data is not None:
                ordered[payload["chunk"]] = data
        out_dir = os.path.dirname(os.path.abspath(output_path))
        if out_dir and not os.path.isdir(out_dir):
            os.makedirs(out_dir, exist_ok=True)
        with open(output_path, "wb") as f:
            for i in sorted(ordered):
                f.write(ordered[i])
        return {
            "success": True,
            "output_path": output_path,
            "bytes_written": sum(len(b) for b in ordered.values()),
            "file_size_on_device": result["info"].get("file_size", -1),
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_dump_binary(output_path: str, module_name: str = "", session_id: str = "") -> dict:
    """Dump the decrypted main Mach-O binary (frida-ios-dump style).

    Reads the on-disk binary, patches LC_ENCRYPTION_INFO[_64] commands by copying
    the in-memory decrypted region back into the file image, then streams the
    decrypted bytes to the host. Handles thin and fat (universal) binaries.

    Args:
        output_path: Local path where the decrypted Mach-O will be written.
        module_name: Specific module to dump (empty = main app executable).
    """
    try:
        _, session = _get_session(session_id)
        mn = json.dumps(module_name)
        js = f"""
        (function(){{
            try {{
                var modName = {mn};
                if (!modName) {{
                    var execPath = String(ObjC.classes.NSBundle.mainBundle().executablePath());
                    modName = execPath.split('/').pop();
                }}
                var mod = Process.findModuleByName(modName);
                if (!mod) {{ send({{__error: 'Module not found: ' + modName}}); send({{__done: true}}); return; }}

                var nsData = ObjC.classes.NSData.dataWithContentsOfFile_(mod.path);
                if (!nsData) {{ send({{__error: 'Cannot read on-disk binary: ' + mod.path}}); send({{__done: true}}); return; }}
                var mutable = ObjC.classes.NSMutableData.dataWithData_(nsData);
                var base = mutable.mutableBytes();
                var fileSize = mutable.length();

                function readBE32(ptr) {{
                    return ptr.readU8() * 16777216
                         + ptr.add(1).readU8() * 65536
                         + ptr.add(2).readU8() * 256
                         + ptr.add(3).readU8();
                }}

                // Detect fat binary
                var magic = base.readU32();
                var sliceOff = 0;
                var sliceCount = 1;
                var FAT_MAGIC = 0xcafebabe, FAT_CIGAM = 0xbebafeca;
                var FAT_MAGIC_64 = 0xcafebabf, FAT_CIGAM_64 = 0xbffabaca;
                if (magic === FAT_MAGIC || magic === FAT_CIGAM || magic === FAT_MAGIC_64 || magic === FAT_CIGAM_64) {{
                    var is64Fat = (magic === FAT_MAGIC_64 || magic === FAT_CIGAM_64);
                    var nfat = readBE32(base.add(4));
                    var entrySize = is64Fat ? 32 : 20;
                    var loadedMagic = mod.base.readU32();
                    var found = false;
                    for (var k = 0; k < nfat; k++) {{
                        var entry = base.add(8 + k * entrySize);
                        var off = is64Fat
                            ? (readBE32(entry.add(8)) * 4294967296 + readBE32(entry.add(12)))
                            : readBE32(entry.add(8));
                        if (off + 4 > fileSize) continue;
                        var sliceMagic = base.add(off).readU32();
                        if (sliceMagic === loadedMagic) {{
                            sliceOff = off;
                            found = true;
                            break;
                        }}
                    }}
                    if (!found) {{ send({{__error: 'Could not match fat slice to loaded module'}}); send({{__done: true}}); return; }}
                }}

                var sliceBase = base.add(sliceOff);
                var mh = sliceBase.readU32();
                var MH_MAGIC = 0xfeedface, MH_MAGIC_64 = 0xfeedfacf;
                if (mh !== MH_MAGIC && mh !== MH_MAGIC_64) {{
                    send({{__error: 'Not a Mach-O at slice offset: 0x' + mh.toString(16)}});
                    send({{__done: true}}); return;
                }}
                var is64 = (mh === MH_MAGIC_64);
                var headerSize = is64 ? 32 : 28;
                var ncmds = sliceBase.add(16).readU32();
                var lc = sliceBase.add(headerSize);
                var patched = [];
                var LC_ENCRYPTION_INFO = 0x21, LC_ENCRYPTION_INFO_64 = 0x2c;
                for (var c = 0; c < ncmds; c++) {{
                    var cmd = lc.readU32();
                    var cmdsize = lc.add(4).readU32();
                    if (cmd === LC_ENCRYPTION_INFO || cmd === LC_ENCRYPTION_INFO_64) {{
                        var cryptoff = lc.add(8).readU32();
                        var cryptsize = lc.add(12).readU32();
                        var cryptid = lc.add(16).readU32();
                        if (cryptid !== 0 && cryptsize > 0) {{
                            var memSrc = mod.base.add(cryptoff);
                            var dec = memSrc.readByteArray(cryptsize);
                            Memory.writeByteArray(sliceBase.add(cryptoff), dec);
                            lc.add(16).writeU32(0);
                            patched.push({{cryptoff: cryptoff, cryptsize: cryptsize}});
                        }}
                    }}
                    lc = lc.add(cmdsize);
                }}

                // Stream the (now-decrypted) file back
                var totalLen = mutable.length();
                var dataPtr = mutable.mutableBytes();
                var chunkSize = 4 * 1024 * 1024;
                var sent = 0;
                var idx = 0;
                while (sent < totalLen) {{
                    var size = Math.min(chunkSize, totalLen - sent);
                    var ab = dataPtr.add(sent).readByteArray(size);
                    send({{chunk: idx, size: size}}, ab);
                    sent += size;
                    idx++;
                }}
                send({{__done: true, total: totalLen, slices_patched: patched, module: modName, path: mod.path}});
            }} catch(e) {{
                send({{__error: e.message + ' :: ' + (e.stack || '')}});
                send({{__done: true}});
            }}
        }})();
        """
        result = exec_js_stream(session, js, timeout=900)
        if result["error"]:
            return {"success": False, "error": result["error"]}
        ordered = {}
        for payload, data in result["chunks"]:
            if isinstance(payload, dict) and "chunk" in payload and data is not None:
                ordered[payload["chunk"]] = data
        out_dir = os.path.dirname(os.path.abspath(output_path))
        if out_dir and not os.path.isdir(out_dir):
            os.makedirs(out_dir, exist_ok=True)
        with open(output_path, "wb") as f:
            for i in sorted(ordered):
                f.write(ordered[i])
        info = result["info"]
        return {
            "success": True,
            "output_path": output_path,
            "bytes_written": sum(len(b) for b in ordered.values()),
            "module": info.get("module"),
            "device_path": info.get("path"),
            "slices_patched": info.get("slices_patched", []),
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================
# NAMED PERSISTENT HOOKS (SSL unpin, JB bypass, crypto)
# ============================================================

def _install_named_hook(sid, session, name, js_src, max_events=500):
    if sid not in _named_hooks:
        _named_hooks[sid] = {}
    if name in _named_hooks[sid]:
        return {"success": True, "already_installed": True, "name": name}
    events = []
    ack = {"ok": False, "error": ""}
    ack_event = threading.Event()

    def on_msg(msg, data):
        if msg["type"] != "send":
            return
        p = msg["payload"]
        if isinstance(p, dict):
            if p.get("__hook_init"):
                ack["ok"] = p.get("ok", False)
                ack["error"] = p.get("error", "")
                ack_event.set()
            else:
                events.append(p)
                while len(events) > max_events:
                    events.pop(0)

    script = session.create_script(js_src)
    script.on("message", on_msg)
    script.load()
    ack_event.wait(5)
    if not ack["ok"]:
        try:
            script.unload()
        except Exception:
            pass
        return {"success": False, "error": ack["error"] or "init timeout"}
    _named_hooks[sid][name] = {"script": script, "events": events}
    return {"success": True, "installed": True, "name": name}


def _remove_named_hook(sid, name):
    if sid not in _named_hooks or name not in _named_hooks[sid]:
        return {"success": True, "already_removed": True}
    try:
        _named_hooks[sid][name]["script"].unload()
    except Exception:
        pass
    del _named_hooks[sid][name]
    return {"success": True, "removed": True, "name": name}


_SSL_UNPIN_JS = """
(function(){
    try {
        var installed = [];
        var SSLSetSessionOption = Module.findExportByName(null, 'SSLSetSessionOption');
        if (SSLSetSessionOption) {
            Interceptor.attach(SSLSetSessionOption, {
                onEnter: function(args) {
                    if (args[1].toInt32() === 0) {
                        args[2] = ptr('0x1');
                    }
                }
            });
            installed.push('SSLSetSessionOption');
        }
        var SSLCreateContext = Module.findExportByName(null, 'SSLCreateContext');
        var SSLHandshake = Module.findExportByName(null, 'SSLHandshake');
        if (SSLHandshake) {
            Interceptor.attach(SSLHandshake, {
                onLeave: function(retval) {
                    if (retval.toInt32() === -9807 || retval.toInt32() === -9808) {
                        retval.replace(0);
                    }
                }
            });
            installed.push('SSLHandshake');
        }
        var SSLSetPeerDomainName = Module.findExportByName(null, 'SSLSetPeerDomainName');
        if (SSLSetPeerDomainName) {
            Interceptor.attach(SSLSetPeerDomainName, {
                onLeave: function(retval) { retval.replace(0); }
            });
            installed.push('SSLSetPeerDomainName');
        }
        var tls_helper_create_peer_trust = Module.findExportByName(null, 'tls_helper_create_peer_trust');
        if (tls_helper_create_peer_trust) {
            Interceptor.attach(tls_helper_create_peer_trust, {
                onLeave: function(retval) { retval.replace(0); }
            });
            installed.push('tls_helper_create_peer_trust');
        }
        var nw_tls_create_peer_trust = Module.findExportByName(null, 'nw_tls_create_peer_trust');
        if (nw_tls_create_peer_trust) {
            Interceptor.attach(nw_tls_create_peer_trust, {
                onLeave: function(retval) { retval.replace(0); }
            });
            installed.push('nw_tls_create_peer_trust');
        }
        try {
            var afspName = 'AFSecurityPolicy';
            if (ObjC.classes[afspName]) {
                var setM = ObjC.classes[afspName]['- setSSLPinningMode:'];
                if (setM) {
                    Interceptor.attach(setM.implementation, {
                        onEnter: function(args) { args[2] = ptr(0); }
                    });
                    installed.push('AFSecurityPolicy.setSSLPinningMode');
                }
                var policy = ObjC.classes[afspName]['+ defaultPolicy'];
                if (policy) {
                    var evalM = ObjC.classes[afspName]['- evaluateServerTrust:forDomain:'];
                    if (evalM) {
                        Interceptor.attach(evalM.implementation, {
                            onLeave: function(retval) { retval.replace(ptr(1)); }
                        });
                        installed.push('AFSecurityPolicy.evaluateServerTrust');
                    }
                }
            }
        } catch(e) {}
        send({__hook_init: true, ok: true, installed: installed});

        Interceptor.attach(SSLHandshake || Module.findExportByName(null, 'SSL_read') || ptr(0), {
            onLeave: function(){}
        });
    } catch(e) {
        send({__hook_init: true, ok: false, error: e.message});
    }
})();
"""


_JB_BYPASS_JS = """
(function(){
    try {
        var jbPaths = ['/Applications/Cydia.app','/Applications/Sileo.app','/Applications/Zebra.app',
            '/Library/MobileSubstrate','/usr/sbin/sshd','/etc/apt','/private/var/lib/apt',
            '/private/var/lib/cydia','/private/var/stash','/usr/bin/ssh','/bin/bash','/bin/sh',
            '/usr/libexec/sftp-server','/usr/libexec/ssh-keysign','/var/cache/apt',
            '/var/lib/apt','/var/lib/cydia','/var/log/syslog','/var/tmp/cydia.log',
            '/Library/MobileSubstrate/DynamicLibraries/Veency.plist',
            '/Library/MobileSubstrate/MobileSubstrate.dylib'];
        var hits = [];

        var NSFM = ObjC.classes.NSFileManager;
        Interceptor.attach(NSFM['- fileExistsAtPath:'].implementation, {
            onEnter: function(args) {
                this.path = new ObjC.Object(args[2]).toString();
                this.match = false;
                for (var i = 0; i < jbPaths.length; i++) {
                    if (this.path.indexOf(jbPaths[i]) !== -1) { this.match = true; break; }
                }
            },
            onLeave: function(retval) {
                if (this.match) {
                    hits.push(this.path);
                    send({hook: 'jb', path: this.path, blocked: true, time: Date.now()});
                    retval.replace(ptr(0));
                }
            }
        });

        var UIApp = ObjC.classes.UIApplication;
        if (UIApp && UIApp['- canOpenURL:']) {
            Interceptor.attach(UIApp['- canOpenURL:'].implementation, {
                onEnter: function(args) {
                    var url = new ObjC.Object(args[2]).absoluteString().toString();
                    this.match = url.indexOf('cydia') === 0 || url.indexOf('sileo') === 0 || url.indexOf('zbra') === 0;
                    this.url = url;
                },
                onLeave: function(retval) {
                    if (this.match) {
                        send({hook: 'jb', scheme: this.url, blocked: true, time: Date.now()});
                        retval.replace(ptr(0));
                    }
                }
            });
        }

        var stat = Module.findExportByName(null, 'stat');
        if (stat) {
            Interceptor.attach(stat, {
                onEnter: function(args) {
                    try { this.p = args[0].readUtf8String(); }
                    catch(e) { this.p = ''; }
                    this.match = false;
                    for (var i = 0; i < jbPaths.length; i++) {
                        if (this.p && this.p.indexOf(jbPaths[i]) !== -1) { this.match = true; break; }
                    }
                },
                onLeave: function(retval) {
                    if (this.match) {
                        send({hook: 'jb', stat: this.p, blocked: true, time: Date.now()});
                        retval.replace(-1);
                    }
                }
            });
        }

        var forkFn = Module.findExportByName(null, 'fork');
        if (forkFn) {
            Interceptor.replace(forkFn, new NativeCallback(function(){ return -1; }, 'int', []));
        }

        send({__hook_init: true, ok: true});
    } catch(e) {
        send({__hook_init: true, ok: false, error: e.message});
    }
})();
"""


_CRYPTO_HOOKS_JS = """
(function(){
    try {
        function hex(buf, max) {
            if (!buf) return '';
            var u = new Uint8Array(buf);
            var lim = Math.min(u.length, max || 64);
            var out = '';
            for (var i = 0; i < lim; i++) {
                var v = u[i].toString(16);
                out += v.length < 2 ? '0' + v : v;
            }
            return u.length > lim ? out + '...' : out;
        }

        var CCCrypt = Module.findExportByName(null, 'CCCrypt');
        if (CCCrypt) {
            Interceptor.attach(CCCrypt, {
                onEnter: function(args) {
                    var op = args[0].toInt32();
                    var alg = args[1].toInt32();
                    var opts = args[2].toInt32();
                    var keyLen = args[4].toInt32();
                    var key = args[3];
                    var ivPtr = args[5];
                    var dataIn = args[6];
                    var dataInLen = args[7].toInt32();
                    var keyBuf = !key.isNull() ? key.readByteArray(keyLen) : null;
                    var ivBuf = !ivPtr.isNull() ? ivPtr.readByteArray(16) : null;
                    var inBuf = !dataIn.isNull() && dataInLen > 0 ? dataIn.readByteArray(Math.min(dataInLen, 64)) : null;
                    send({
                        hook: 'CCCrypt',
                        op: op === 0 ? 'encrypt' : 'decrypt',
                        alg: alg,
                        options: opts,
                        key_len: keyLen,
                        key_hex: hex(keyBuf, keyLen),
                        iv_hex: hex(ivBuf, 16),
                        in_preview: hex(inBuf, 64),
                        in_len: dataInLen,
                        time: Date.now()
                    });
                }
            });
        }

        var CCCryptorCreate = Module.findExportByName(null, 'CCCryptorCreate');
        if (CCCryptorCreate) {
            Interceptor.attach(CCCryptorCreate, {
                onEnter: function(args) {
                    var op = args[0].toInt32();
                    var alg = args[1].toInt32();
                    var keyLen = args[5].toInt32();
                    var key = args[4];
                    var iv = args[3];
                    var keyBuf = !key.isNull() ? key.readByteArray(keyLen) : null;
                    var ivBuf = !iv.isNull() ? iv.readByteArray(16) : null;
                    send({
                        hook: 'CCCryptorCreate',
                        op: op === 0 ? 'encrypt' : 'decrypt',
                        alg: alg,
                        key_len: keyLen,
                        key_hex: hex(keyBuf, keyLen),
                        iv_hex: hex(ivBuf, 16),
                        time: Date.now()
                    });
                }
            });
        }

        send({__hook_init: true, ok: true});
    } catch(e) {
        send({__hook_init: true, ok: false, error: e.message});
    }
})();
"""


@mcp.tool()
def flex_ssl_unpin(enable: bool = True, session_id: str = "") -> dict:
    """Install or remove an SSL pinning bypass (Secure Transport, Network.framework, AFNetworking).

    Args:
        enable: True to install, False to remove.
    """
    try:
        sid, session = _get_session(session_id)
        if enable:
            return _install_named_hook(sid, session, "ssl_unpin", _SSL_UNPIN_JS)
        return _remove_named_hook(sid, "ssl_unpin")
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_jailbreak_bypass(enable: bool = True, session_id: str = "") -> dict:
    """Hide common jailbreak indicators from the app (path checks, URL schemes, fork).

    Args:
        enable: True to install, False to remove.
    """
    try:
        sid, session = _get_session(session_id)
        if enable:
            return _install_named_hook(sid, session, "jb_bypass", _JB_BYPASS_JS)
        return _remove_named_hook(sid, "jb_bypass")
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_crypto_hooks(enable: bool = True, session_id: str = "") -> dict:
    """Hook CommonCrypto (CCCrypt, CCCryptorCreate) and buffer key/iv/data events.

    Args:
        enable: True to install, False to remove.
    """
    try:
        sid, session = _get_session(session_id)
        if enable:
            return _install_named_hook(sid, session, "crypto", _CRYPTO_HOOKS_JS, max_events=2000)
        return _remove_named_hook(sid, "crypto")
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_crypto_logs(limit: int = 100, clear: bool = False, session_id: str = "") -> dict:
    """Read captured CommonCrypto events (requires flex_crypto_hooks).

    Args:
        limit: Max events to return.
        clear: Drop returned events from the buffer.
    """
    try:
        sid, _ = _get_session(session_id)
        hook = _named_hooks.get(sid, {}).get("crypto")
        if not hook:
            return {"success": True, "events": [], "message": "Crypto hooks not installed. Call flex_crypto_hooks(true)."}
        buf = hook["events"]
        slice_ = buf[-limit:] if limit else list(buf)
        if clear:
            for _ in slice_:
                if buf:
                    buf.pop(0)
        return {"success": True, "count": len(slice_), "events": slice_}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================
# MAIN
# ============================================================

def main():
    import argparse
    parser = argparse.ArgumentParser(description="FLEX MCP Server")
    parser.add_argument("--transport", choices=["stdio", "sse"], default="stdio",
                        help="Transport: stdio (local, default) or sse (remote via HTTP)")
    parser.add_argument("--host", default="0.0.0.0", help="SSE host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8099, help="SSE port (default: 8099)")
    args = parser.parse_args()

    if args.transport == "sse":
        print(f"FLEX MCP Server running on http://{args.host}:{args.port}/sse")
        mcp.run(transport="sse", host=args.host, port=args.port)
    else:
        mcp.run()


if __name__ == "__main__":
    main()

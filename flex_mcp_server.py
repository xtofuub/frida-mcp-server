#!/usr/bin/env python3

import sys, os, re, json, time, base64, threading, frida, logging
from mcp.server.fastmcp import FastMCP

logging.basicConfig(level=logging.INFO, format="%(asctime)s [FRIDA] %(levelname)s %(message)s")
log = logging.getLogger("frida")

mcp = FastMCP("Frida iOS Debugger")
_sessions = {}
_traces = {}
_named_hooks = {}
_intercept_rules = {}
_intercept_counter = 0
_trace_counter = 0
_session_lock = threading.Lock()

# ── Device ───────────────────────────────────────────────────────────────

_device_cache = None
_device_lock = threading.Lock()

def get_usb_device():
    global _device_cache
    with _device_lock:
        if _device_cache is not None:
            try:
                _device_cache.name
                return _device_cache
            except Exception:
                _device_cache = None
        _device_cache = frida.get_usb_device(timeout=10)
        return _device_cache

# ── Session lifecycle ───────────────────────────────────────────────────

def session_alive(session):
    try:
        return not bool(session.is_detached)
    except Exception:
        return False

def _get_session(session_id=""):
    with _session_lock:
        if not _sessions:
            raise RuntimeError("No active sessions. Call connect first.")
        sid = session_id or next(iter(_sessions))
        if sid not in _sessions:
            raise RuntimeError(f"Session '{sid}' not found. Active: {list(_sessions.keys())}")
        sess = _sessions[sid]
        if not session_alive(sess):
            _cleanup_session(sid)
            try:
                sess.detach()
            except Exception:
                pass
            del _sessions[sid]
            raise RuntimeError(f"Session '{sid}' is dead. Call connect again.")
        return sid, sess

def _cleanup_session(sid):
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
    if ir:
        for key in ["net_script", "intercept_script"]:
            if ir.get(key):
                try:
                    ir[key].unload()
                except Exception:
                    pass

# ── JS execution engine ─────────────────────────────────────────────────

# Permanent-failure exceptions: bail without retrying. Names vary across frida
# versions (no InvalidStateError in 16.x), so resolve defensively.
_FRIDA_FATAL = tuple(
    cls for cls in (
        getattr(frida, "InvalidOperationError", None),
        getattr(frida, "InvalidStateError", None),
        getattr(frida, "ProcessNotFoundError", None),
    ) if cls is not None
)


def exec_js(session, js_code, timeout=20, retries=2):
    """Execute JS on mainQueue with retry support."""
    last_err = None
    for attempt in range(1 + retries):
        try:
            return _exec_js_once(session, js_code, timeout)
        except _FRIDA_FATAL:
            raise
        except Exception as e:
            last_err = e
            if attempt < retries:
                log.warning("exec_js attempt %d failed: %s — retrying", attempt + 1, e)
                time.sleep(0.3 * (attempt + 1))
    return {"ok": False, "error": f"after {1 + retries} attempts: {last_err}"}

def _exec_js_once(session, js_code, timeout):
    messages = []
    event = threading.Event()

    def on_msg(msg, data):
        if msg.get("type") == "send":
            messages.append(msg.get("payload"))
        elif msg.get("type") == "error":
            messages.append({"error": msg.get("description", str(msg))})
        event.set()

    stripped = js_code.strip()
    is_expr = not any(stripped.startswith(kw) for kw in [
        "var ", "let ", "const ", "function ", "if ", "for ", "while ",
        "switch ", "try ", "class ", "import ", "export ", "return ",
        "do ", "throw ", "debugger ", "//", "/*",
    ]) and "\n" not in stripped

    if stripped.startswith('(function') and stripped.endswith('})()'):
        body = "var __r = " + stripped + ";"
    elif is_expr:
        body = "var __r = " + js_code + ";"
    else:
        lines = [l for l in stripped.split("\n") if l.strip()]
        last = lines[-1].strip() if lines else ""
        last_is_expr = last and not any(last.startswith(kw) for kw in [
            "var ", "let ", "const ", "function ", "if ", "for ", "while ",
            "switch ", "try ", "class ", "import ", "export ", "return ",
            "do ", "throw ", "debugger ", "//", "/*", "}"
        ])
        if last_is_expr:
            body = "\n".join(lines[:-1]) + "\nvar __r = " + last.rstrip(";") + ";"
        else:
            body = js_code + "\nvar __r = 'executed';"

    wrapped = (
        'ObjC.schedule(ObjC.mainQueue, function() {\n'
        '    try {\n'
        '        ' + body.replace('\n', '\n        ') + '\n'
        '        send({ok: true, result: typeof __r !== "undefined" ? String(__r) : "undefined"});\n'
        '    } catch(e) {\n'
        '        send({ok: false, error: e.message, stack: e.stack});\n'
        '    }\n'
        '});'
    )

    s = session.create_script(wrapped)
    s.on("message", on_msg)
    s.load()
    event.wait(timeout)
    s.unload()

    if messages:
        try:
            return json.loads(messages[-1]) if isinstance(messages[-1], str) else messages[-1]
        except Exception:
            return {"ok": False, "error": "parse: " + str(messages[-1])[:200]}
    return {"ok": False, "error": "timeout (no response)"}


def exec_js_stream(session, js_code, timeout=300, on_chunk=None):
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


def exec_js_main(session, js_body, timeout=15):
    """Run Frida JS on the iOS main queue and return the stringified result."""
    script = 'if (!ObjC.available) {\n    send({__done: true, ok: false, error: "ObjC runtime unavailable"});\n} else {\n    ObjC.schedule(ObjC.mainQueue, function() {\n        try {\n            var __result = (function() {\n                ' + js_body + '\n            })();\n            send({__done: true, ok: true, result: __result !== undefined ? String(__result) : "undefined"});\n        } catch (e) {\n            send({__done: true, ok: false, error: e.message || String(e), stack: e.stack || ""});\n        }\n    });\n}'
    out = exec_js_stream(session, script, timeout=timeout)
    if out.get("error"):
        return {"ok": False, "error": out["error"]}
    info = out.get("info", {})
    if not info.get("__done"):
        return {"ok": False, "error": "timeout"}
    if not info.get("ok"):
        return {"ok": False, "error": info.get("error", "unknown"), "stack": info.get("stack", "")}
    return {"ok": True, "result": info.get("result", "undefined")}


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


# ── Connection tools ────────────────────────────────────────────────────

@mcp.tool()
def apps() -> dict:
    """List installed applications on the connected device."""
    try:
        device = get_usb_device()
        apps = device.enumerate_applications()
        return {
            "success": True, "device": device.name, "count": len(apps),
            "apps": [{"identifier": a.identifier, "name": a.name, "pid": a.pid} for a in apps],
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def connect(bundle_id: str) -> dict:
    """Attach (or spawn) the iOS app and install Frida network capture hooks.

    Args:
        bundle_id: Bundle identifier (e.g. 'com.apple.mobilesafari'). Use apps to discover.
    """
    try:
        device = get_usb_device()
        method = "attach"
        try:
            for app in device.enumerate_applications():
                if app.identifier == bundle_id and app.pid > 0:
                    session = device.attach(app.pid)
                    break
            else:
                raise Exception("not running")
        except Exception:
            pid = device.spawn([bundle_id])
            session = device.attach(pid)
            device.resume(pid)
            time.sleep(5)
            if not session_alive(session):
                try: session.detach()
                except Exception: pass
                raise RuntimeError("App crashed after spawn (session died)")
            method = "spawn"

        sid = "flex_" + bundle_id + "_" + str(int(time.time()))
        with _session_lock:
            _sessions[sid] = session

        net_ack = _install_network_capture(sid, session)
        if not net_ack.get("ok"):
            log.warning("Network capture install: %s", net_ack.get("error", "unknown"))

        return {
            "success": True, "session_id": sid, "method": method,
            "network_capture": net_ack.get("ok", False),
            "hooks_installed": net_ack.get("hooks", 0),
            "hooked_classes": net_ack.get("classes", []),
            "device": device.name, "app": bundle_id,
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def spawn(bundle_id: str) -> dict:
    """Force-restart the app fresh with Frida attached."""
    try:
        device = get_usb_device()
        pid = device.spawn([bundle_id])
        session = device.attach(pid)
        device.resume(pid)
        time.sleep(2)
        sid = "flex_" + bundle_id + "_" + str(int(time.time()))
        with _session_lock:
            _sessions[sid] = session
        return {"success": True, "session_id": sid, "pid": pid}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def sessions() -> dict:
    """List active Frida sessions."""
    alive = {}
    with _session_lock:
        for sid, sess in list(_sessions.items()):
            if session_alive(sess):
                alive[sid] = True
            else:
                _cleanup_session(sid)
                try:
                    sess.detach()
                except Exception:
                    pass
                del _sessions[sid]
    return {"success": True, "count": len(alive), "sessions": list(alive.keys())}


@mcp.tool()
def disconnect(session_id: str = "") -> dict:
    """Disconnect from app session(s)."""
    try:
        with _session_lock:
            if session_id:
                if session_id in _sessions:
                    _cleanup_session(session_id)
                    try:
                        _sessions[session_id].detach()
                    except Exception:
                        pass
                    del _sessions[session_id]
                return {"success": True, "disconnected": [session_id]}
            ids = list(_sessions.keys())
            for sid in ids:
                _cleanup_session(sid)
                try:
                    _sessions[sid].detach()
                except Exception:
                    pass
            _sessions.clear()
            return {"success": True, "disconnected": ids}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── App info ────────────────────────────────────────────────────────────

@mcp.tool()
def info(session_id: str = "") -> dict:
    """Get bundle info for the attached app."""
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


# ── Network capture (pure Frida NSURLSession hooks) ─────────────────────

_NETWORK_CAPTURE_JS = r"""
(function(){
    if (!ObjC.available) { send({__hook_init: true, ok: false, error: 'ObjC not available'}); return; }

    var transactions = [];
    var maxTxns = 5000;
    // WebSocket frames: {url, dir: 'send'|'recv', text|data_hex, time}
    var wsFrames = [];
    var wsMax = 2000;
    // Map task pointer -> txn so onEnter (request) and onLeave (response) align
    var pending = {};
    // Track tasks that have already been completed to avoid double-pushes
    // when both setState: and _didFinishWithError: fire.
    var completed = {};
    var completedKeys = [];
    var completedMax = 5000;

    function dataToStr(d) {
        if (!d || (d.isNull && d.isNull())) return '';
        try {
            var len = d.length();
            // Detect gzip magic and try the modern decompression API.
            // NSURLSession normally pre-decodes Content-Encoding, but some
            // task subclasses surface the raw body to _responseData.
            if (len >= 2) {
                try {
                    var bytes = d.bytes();
                    if (bytes && !bytes.isNull()) {
                        var b0 = Memory.readU8(bytes);
                        var b1 = Memory.readU8(bytes.add(1));
                        if (b0 === 0x1f && b1 === 0x8b) {
                            try {
                                if (d.respondsToSelector_(ObjC.selector('decompressedDataUsingAlgorithm:error:'))) {
                                    var errPtr = Memory.alloc(Process.pointerSize);
                                    Memory.writePointer(errPtr, NULL);
                                    // 3 = NSDataCompressionAlgorithmZlib (handles gzip on iOS 13+)
                                    var dec = d.decompressedDataUsingAlgorithm_error_(3, errPtr);
                                    if (dec && !dec.isNull()) {
                                        var ns2 = ObjC.classes.NSString.alloc().initWithData_encoding_(dec, 4);
                                        if (ns2) return String(ns2);
                                    }
                                }
                            } catch(e) {}
                        }
                    }
                } catch(e) {}
            }
            var ns = ObjC.classes.NSString.alloc().initWithData_encoding_(d, 4);
            if (ns) return String(ns);
            return '<binary ' + len + ' bytes>';
        } catch(e) { return '<binary>'; }
    }

    function headersToObj(h) {
        if (!h) return {};
        var out = {};
        try {
            var keys = h.allKeys();
            for (var i = 0; i < keys.count(); i++) {
                var k = String(keys.objectAtIndex_(i));
                out[k] = String(h.objectForKey_(keys.objectAtIndex_(i)));
            }
        } catch(e) {}
        return out;
    }

    function snapshotRequest(reqObj) {
        if (!reqObj) return null;
        try {
            var url = reqObj.URL();
            var body = reqObj.HTTPBody ? reqObj.HTTPBody() : null;
            return {
                url: url ? String(url.absoluteString()) : '',
                method: reqObj.HTTPMethod ? String(reqObj.HTTPMethod()) : 'GET',
                headers: reqObj.allHTTPHeaderFields ? headersToObj(reqObj.allHTTPHeaderFields()) : {},
                req_body: body ? dataToStr(body) : '',
                status: -1, resp_headers: {}, resp_body: '',
                timestamp: Date.now()
            };
        } catch(e) { return null; }
    }

    function pushTxn(txn) {
        transactions.push(txn);
        if (transactions.length > maxTxns) transactions.shift();
    }

    function completeFromTask(task, dataObj, errorObj) {
        try {
            var key = task.handle.toString();
            // Skip if this task was already fully completed.
            if (completed[key]) {
                // Optionally refresh response on second pass.
                var existing = completed[key];
                try {
                    var resp2 = task.response ? task.response() : null;
                    if (resp2 && !resp2.isNull()) {
                        if (existing.status === -1 && resp2.respondsToSelector_(ObjC.selector('statusCode'))) {
                            existing.status = resp2.statusCode();
                        }
                        if ((!existing.resp_headers || !Object.keys(existing.resp_headers).length) &&
                            resp2.respondsToSelector_(ObjC.selector('allHeaderFields'))) {
                            existing.resp_headers = headersToObj(resp2.allHeaderFields());
                        }
                    }
                } catch(e) {}
                if (dataObj && !dataObj.isNull() && !existing.resp_body) {
                    existing.resp_body = dataToStr(dataObj);
                }
                return;
            }
            var txn = pending[key];
            var wasInPending = !!txn;
            if (!txn) {
                var req = task.currentRequest ? task.currentRequest() : null;
                if (!req && task.originalRequest) req = task.originalRequest();
                txn = snapshotRequest(req) || {url: '', method: '', headers: {}, req_body: '',
                    status: -1, resp_headers: {}, resp_body: '', timestamp: Date.now()};
            }
            try {
                var resp = task.response ? task.response() : null;
                if (resp && !resp.isNull()) {
                    if (resp.respondsToSelector_(ObjC.selector('statusCode'))) {
                        txn.status = resp.statusCode();
                    }
                    if (resp.respondsToSelector_(ObjC.selector('allHeaderFields'))) {
                        txn.resp_headers = headersToObj(resp.allHeaderFields());
                    }
                }
            } catch(e) {}
            if (dataObj && !dataObj.isNull()) txn.resp_body = dataToStr(dataObj);
            if (errorObj && !errorObj.isNull()) {
                try { txn.error = String(errorObj.localizedDescription()); } catch(e) {}
            }
            txn.duration_ms = Date.now() - txn.timestamp;
            if (!wasInPending) pushTxn(txn);
            // Mark completed (with bounded size to avoid leaks).
            completed[key] = txn;
            completedKeys.push(key);
            if (completedKeys.length > completedMax) {
                var old = completedKeys.shift();
                delete completed[old];
            }
            delete pending[key];
        } catch(e) {}
    }

    var hookCount = 0;
    var hookedClasses = [];

    // Hook -[NSURLSessionTask resume] on every concrete task subclass.
    // resume() is the universal entry point for foreground, background,
    // upload, download, websocket, and stream tasks.
    function hookResumeOnSubclasses() {
        try {
            var seenImps = {};
            var classes = ObjC.classes;
            for (var name in classes) {
                if (name.indexOf('Task') === -1) continue;
                if (name.indexOf('URL') === -1 && name.indexOf('NSCF') === -1 && name.indexOf('Session') === -1) continue;
                try {
                    var cls = classes[name];
                    var sel = cls['- resume'];
                    if (!sel) continue;
                    var imp = sel.implementation.toString();
                    if (seenImps[imp]) continue;
                    seenImps[imp] = true;
                    Interceptor.attach(sel.implementation, {
                        onEnter: function(args) {
                            try {
                                var task = new ObjC.Object(args[0]);
                                var key = task.handle.toString();
                                if (pending[key]) return;
                                var req = null;
                                try { req = task.currentRequest ? task.currentRequest() : null; } catch(e) {}
                                if (!req || (req.isNull && req.isNull())) {
                                    try { req = task.originalRequest ? task.originalRequest() : null; } catch(e) {}
                                }
                                var txn = snapshotRequest(req);
                                if (txn) {
                                    pushTxn(txn);
                                    pending[key] = txn;
                                }
                            } catch(e) {}
                        }
                    });
                    hookCount++;
                    hookedClasses.push(name);
                } catch(e) {}
            }
        } catch(e) {}
    }

    // Hook setState: on every concrete task subclass (deduped by IMP).
    // Subclasses like __NSCFLocalDataTask and NWURLSessionTask override
    // setState:, so a hook on the abstract base never fires for them.
    function hookTaskCompletion() {
        try {
            var seenImps = {};
            var classes = ObjC.classes;
            for (var name in classes) {
                if (name.indexOf('Task') === -1) continue;
                if (name.indexOf('URL') === -1 && name.indexOf('NSCF') === -1 && name.indexOf('Session') === -1) continue;
                try {
                    var cls = classes[name];
                    var sel = cls['- setState:'];
                    if (!sel) continue;
                    var imp = sel.implementation.toString();
                    if (seenImps[imp]) continue;
                    seenImps[imp] = true;
                    Interceptor.attach(sel.implementation, {
                        onEnter: function(args) {
                            try {
                                this.task = new ObjC.Object(args[0]);
                                // args[2] is a NativePointer; the state is its low 32 bits.
                                this.newState = parseInt(args[2].toString());
                            } catch(e) {}
                        },
                        onLeave: function(retval) {
                            try {
                                // NSURLSessionTaskStateCompleted = 2
                                if (this.newState !== 2) return;
                                var task = this.task;
                                if (!task) return;
                                var data = null;
                                try {
                                    if (task.respondsToSelector_(ObjC.selector('_responseData'))) {
                                        data = task['- _responseData']();
                                    }
                                } catch(e) {}
                                var err = null;
                                try {
                                    if (task.error) err = task.error();
                                } catch(e) {}
                                completeFromTask(task, data, err);
                            } catch(e) {}
                        }
                    });
                    hookCount++;
                } catch(e) {}
            }
        } catch(e) {}
    }

    // Wrap NSURLSession completion-handler entry points. Captures the
    // task pointer for response correlation and (when a completion block
    // is present) wraps it to grab the actual response body.
    function wrapCompletionAPI(selector) {
        try {
            var cls = ObjC.classes.NSURLSession;
            var m = cls[selector];
            if (!m) return;
            // Selector ending in ":" count signals how many args the method takes.
            // For "...completionHandler:" the block is the LAST objc arg.
            var hasCompletion = selector.indexOf('completionHandler:') !== -1;
            Interceptor.attach(m.implementation, {
                onEnter: function(args) {
                    try {
                        var maybeReq = new ObjC.Object(args[2]);
                        var className = maybeReq.$className || '';
                        var req = null;
                        if (className.indexOf('Request') !== -1) {
                            req = maybeReq;
                        } else if (className.indexOf('URL') !== -1) {
                            req = ObjC.classes.NSURLRequest.requestWithURL_(maybeReq);
                        }
                        this.snapshot = snapshotRequest(req);
                    } catch(e) {}
                },
                onLeave: function(retval) {
                    try {
                        if (!retval || retval.isNull()) return;
                        var task = new ObjC.Object(retval);
                        if (this.snapshot) {
                            pending[task.handle.toString()] = this.snapshot;
                        }
                    } catch(e) {}
                }
            });
            hookCount++;
        } catch(e) {}
    }

    // Accumulate response body via delegate callback. NSURLSessionDataDelegate
    // implementations forward chunks via -URLSession:dataTask:didReceiveData:.
    // We hook every class that implements this and append to the txn for
    // the corresponding task pointer.
    function hookDelegateData() {
        try {
            var seenImps = {};
            var classes = ObjC.classes;
            var sels = [
                '- URLSession:dataTask:didReceiveData:',
                '- URLSession:dataTask:didReceiveResponse:completionHandler:',
                '- URLSession:task:didCompleteWithError:'
            ];
            for (var name in classes) {
                var cls = classes[name];
                for (var s = 0; s < sels.length; s++) {
                    var selName = sels[s];
                    try {
                        var sel = cls[selName];
                        if (!sel) continue;
                        var imp = sel.implementation.toString();
                        if (seenImps[imp]) continue;
                        seenImps[imp] = true;
                        if (selName === '- URLSession:dataTask:didReceiveData:') {
                            Interceptor.attach(sel.implementation, {
                                onEnter: function(args) {
                                    try {
                                        var task = new ObjC.Object(args[3]);
                                        var data = new ObjC.Object(args[4]);
                                        var key = task.handle.toString();
                                        var txn = pending[key];
                                        if (!txn) return;
                                        if (data && !data.isNull()) {
                                            var chunk = dataToStr(data);
                                            if (chunk && chunk.indexOf('<binary') === -1) {
                                                txn.resp_body = (txn.resp_body || '') + chunk;
                                            }
                                        }
                                    } catch(e) {}
                                }
                            });
                            hookCount++;
                        } else if (selName === '- URLSession:dataTask:didReceiveResponse:completionHandler:') {
                            Interceptor.attach(sel.implementation, {
                                onEnter: function(args) {
                                    try {
                                        var task = new ObjC.Object(args[3]);
                                        var resp = new ObjC.Object(args[4]);
                                        var key = task.handle.toString();
                                        var txn = pending[key];
                                        if (!txn) return;
                                        if (resp && !resp.isNull()) {
                                            if (resp.respondsToSelector_(ObjC.selector('statusCode'))) {
                                                txn.status = resp.statusCode();
                                            }
                                            if (resp.respondsToSelector_(ObjC.selector('allHeaderFields'))) {
                                                txn.resp_headers = headersToObj(resp.allHeaderFields());
                                            }
                                        }
                                    } catch(e) {}
                                }
                            });
                            hookCount++;
                        } else if (selName === '- URLSession:task:didCompleteWithError:') {
                            Interceptor.attach(sel.implementation, {
                                onEnter: function(args) {
                                    try {
                                        var task = new ObjC.Object(args[3]);
                                        var err = (args[4] && !args[4].isNull()) ? new ObjC.Object(args[4]) : null;
                                        completeFromTask(task, null, err);
                                    } catch(e) {}
                                }
                            });
                            hookCount++;
                        }
                    } catch(e) {}
                }
            }
        } catch(e) {}
    }

    // Last-resort completion fallback: hook -[*Task _didFinishWithError:]
    // when present. Catches tasks whose setState: hook doesn't fire (e.g.
    // Network.framework subclasses).
    function hookDidFinishWithError() {
        try {
            var seenImps = {};
            var classes = ObjC.classes;
            var selectors = ['- _didFinishWithError:', '- didFinishWithError:'];
            for (var name in classes) {
                if (name.indexOf('Task') === -1) continue;
                if (name.indexOf('URL') === -1 && name.indexOf('NSCF') === -1 && name.indexOf('Session') === -1) continue;
                var cls = classes[name];
                for (var s = 0; s < selectors.length; s++) {
                    try {
                        var sel = cls[selectors[s]];
                        if (!sel) continue;
                        var imp = sel.implementation.toString();
                        if (seenImps[imp]) continue;
                        seenImps[imp] = true;
                        Interceptor.attach(sel.implementation, {
                            onEnter: function(args) {
                                try {
                                    var task = new ObjC.Object(args[0]);
                                    var errPtr = args[2];
                                    var err = (errPtr && !errPtr.isNull()) ? new ObjC.Object(errPtr) : null;
                                    var data = null;
                                    try {
                                        if (task.respondsToSelector_(ObjC.selector('_responseData'))) {
                                            data = task['- _responseData']();
                                        }
                                    } catch(e) {}
                                    completeFromTask(task, data, err);
                                } catch(e) {}
                            }
                        });
                        hookCount++;
                    } catch(e) {}
                }
            }
        } catch(e) {}
    }

    // FLEX-equivalent universal capture: register a custom NSURLProtocol
    // subclass and inject it into every NSURLSessionConfiguration so
    // +canInitWithRequest: fires for every outbound request — including
    // requests that go through task subclasses our other hooks miss.
    function installProtocolObserver() {
        try {
            if (ObjC.classes.FlexCaptureProtocol) return;
            var marker = '_flex_observed';
            var FlexCaptureProtocol = ObjC.registerClass({
                name: 'FlexCaptureProtocol',
                super: ObjC.classes.NSURLProtocol,
                methods: {
                    '+ canInitWithRequest:': {
                        retType: 'bool',
                        argTypes: ['object'],
                        implementation: function(req) {
                            try {
                                var nsreq = new ObjC.Object(req);
                                // Avoid recursion: skip if we've already observed this one.
                                if (nsreq.valueForHTTPHeaderField_(marker)) return false;
                                var snap = snapshotRequest(nsreq);
                                if (snap) pushTxn(snap);
                            } catch(e) {}
                            return false; // observe-only, never actually handle
                        }
                    },
                    '+ canonicalRequestForRequest:': {
                        retType: 'object',
                        argTypes: ['object'],
                        implementation: function(req) { return req; }
                    },
                    '+ requestIsCacheEquivalent:toRequest:': {
                        retType: 'bool',
                        argTypes: ['object', 'object'],
                        implementation: function() { return false; }
                    },
                    '- startLoading': {
                        retType: 'void',
                        argTypes: [],
                        implementation: function() {}
                    },
                    '- stopLoading': {
                        retType: 'void',
                        argTypes: [],
                        implementation: function() {}
                    }
                }
            });

            // Register globally for NSURLConnection-style traffic.
            try { ObjC.classes.NSURLProtocol.registerClass_(FlexCaptureProtocol); } catch(e) {}

            // Swizzle -[NSURLSessionConfiguration protocolClasses] so every
            // session configuration includes our protocol at index 0.
            try {
                var cfgCls = ObjC.classes.NSURLSessionConfiguration;
                if (cfgCls) {
                    var sel = cfgCls['- protocolClasses'];
                    if (sel) {
                        var orig = sel.implementation;
                        Interceptor.attach(orig, {
                            onLeave: function(retval) {
                                try {
                                    if (!retval || retval.isNull()) return;
                                    var arr = new ObjC.Object(retval);
                                    var mut = arr.mutableCopy();
                                    mut.insertObject_atIndex_(FlexCaptureProtocol, 0);
                                    retval.replace(mut);
                                } catch(e) {}
                            }
                        });
                        hookCount++;
                    }
                }
            } catch(e) {}
        } catch(e) {}
    }

    function installAll() {
        hookResumeOnSubclasses();
        hookTaskCompletion();
        hookDidFinishWithError();
        hookDelegateData();
        installProtocolObserver();
        wrapCompletionAPI('- dataTaskWithRequest:completionHandler:');
        wrapCompletionAPI('- dataTaskWithURL:completionHandler:');
        wrapCompletionAPI('- uploadTaskWithRequest:fromData:completionHandler:');
        wrapCompletionAPI('- uploadTaskWithRequest:fromFile:completionHandler:');
        wrapCompletionAPI('- downloadTaskWithRequest:completionHandler:');
        wrapCompletionAPI('- downloadTaskWithURL:completionHandler:');
        wrapCompletionAPI('- dataTaskWithRequest:');
        wrapCompletionAPI('- dataTaskWithURL:');

        // WebSocket frame capture (iOS 13+).
        try {
            var wsCls = ObjC.classes.NSURLSessionWebSocketTask;
            if (wsCls) {
                function wsUrl(task) {
                    try {
                        var req = task.currentRequest ? task.currentRequest() : null;
                        if (!req && task.originalRequest) req = task.originalRequest();
                        if (req && req.URL) return String(req.URL().absoluteString());
                    } catch(e) {}
                    return '';
                }
                function wsPushFrame(f) {
                    wsFrames.push(f);
                    if (wsFrames.length > wsMax) wsFrames.shift();
                }
                function readMessage(msgPtr, dir, url) {
                    try {
                        var m = new ObjC.Object(msgPtr);
                        var t = m.type ? m.type() : 0; // 0=data, 1=string
                        var f = {url: url, dir: dir, time: Date.now()};
                        if (t === 1 && m.string) {
                            var s = m.string();
                            f.text = s ? String(s) : '';
                        } else if (m.data) {
                            var d = m.data();
                            if (d && !d.isNull()) {
                                f.size = d.length();
                                var s2 = ObjC.classes.NSString.alloc().initWithData_encoding_(d, 4);
                                if (s2) f.text = String(s2);
                            }
                        }
                        wsPushFrame(f);
                    } catch(e) {}
                }
                var sendSel = wsCls['- sendMessage:completionHandler:'];
                if (sendSel) {
                    Interceptor.attach(sendSel.implementation, {
                        onEnter: function(args) {
                            try {
                                var task = new ObjC.Object(args[0]);
                                readMessage(args[2], 'send', wsUrl(task));
                            } catch(e) {}
                        }
                    });
                    hookCount++;
                }
                var recvSel = wsCls['- receiveMessageWithCompletionHandler:'];
                if (recvSel) {
                    Interceptor.attach(recvSel.implementation, {
                        onEnter: function(args) {
                            try { this.task = new ObjC.Object(args[0]); } catch(e) {}
                        }
                    });
                    hookCount++;
                }
            }
        } catch(e) {}

        // Legacy NSURLConnection paths
        try {
            var conn = ObjC.classes.NSURLConnection;
            if (conn) {
                var sync = conn['+ sendSynchronousRequest:returningResponse:error:'];
                if (sync) {
                    Interceptor.attach(sync.implementation, {
                        onEnter: function(args) {
                            try { this.snap = snapshotRequest(new ObjC.Object(args[2])); } catch(e) {}
                        },
                        onLeave: function(retval) {
                            try {
                                if (!this.snap) return;
                                if (retval && !retval.isNull()) {
                                    this.snap.resp_body = dataToStr(new ObjC.Object(retval));
                                }
                                pushTxn(this.snap);
                            } catch(e) {}
                        }
                    });
                    hookCount++;
                }
                var async = conn['+ sendAsynchronousRequest:queue:completionHandler:'];
                if (async) {
                    Interceptor.attach(async.implementation, {
                        onEnter: function(args) {
                            try {
                                var snap = snapshotRequest(new ObjC.Object(args[2]));
                                if (snap) pushTxn(snap);
                            } catch(e) {}
                        }
                    });
                    hookCount++;
                }
            }
        } catch(e) {}
    }

    ObjC.schedule(ObjC.mainQueue, function() {
        try {
            installAll();
            send({__hook_init: true, ok: hookCount > 0, hooks: hookCount, classes: hookedClasses.slice(0, 20)});
        } catch(e) {
            send({__hook_init: true, ok: false, error: e.message});
        }
    });

    rpc.exports = {
        getTransactions: function(count) {
            var c = Math.min(count || 50, transactions.length);
            return transactions.slice(-c);
        },
        clearTransactions: function() { transactions = []; pending = {}; completed = {}; completedKeys = []; return true; },
        getWsFrames: function(count) {
            var c = Math.min(count || 100, wsFrames.length);
            return wsFrames.slice(-c);
        },
        clearWsFrames: function() { wsFrames = []; return true; },
        stats: function() {
            return {
                captured: transactions.length,
                pending: Object.keys(pending).length,
                ws_frames: wsFrames.length
            };
        }
    };
})();
"""


def _install_network_capture(sid, session):
    state = _intercept_rules.get(sid, {})
    if state.get("net_script"):
        return {"ok": True}
    if not session_alive(session):
        return {"ok": False, "error": "session dead before hook install"}
    ack_event = threading.Event()
    ack = {"ok": False, "error": ""}

    def on_msg(msg, data):
        if msg["type"] != "send":
            return
        p = msg["payload"]
        if isinstance(p, dict) and p.get("__hook_init"):
            ack["ok"] = p.get("ok", False)
            ack["error"] = p.get("error", "")
            ack["hooks"] = p.get("hooks", 0)
            ack["classes"] = p.get("classes", [])
            ack_event.set()

    for attempt in range(3):
        try:
            script = session.create_script(_NETWORK_CAPTURE_JS)
            script.on("message", on_msg)
            script.load()
            ack_event.wait(10)
            if ack.get("ok"):
                _intercept_rules.setdefault(sid, {})["net_script"] = script
                return ack
            if ack.get("error"):
                try: script.unload()
                except Exception: pass
                log.warning("net hook attempt %d: %s", attempt + 1, ack.get("error"))
                if attempt < 2:
                    time.sleep(1)
                    continue
                return ack
            try: script.unload()
            except Exception: pass
        except Exception as e:
            log.warning("net hook attempt %d exception: %s", attempt + 1, e)
            if attempt < 2:
                time.sleep(1)
                continue
            return {"ok": False, "error": str(e)}
    return {"ok": False, "error": "all attempts failed"}


# ── Network tools ───────────────────────────────────────────────────────

@mcp.tool()
def requests(count: int = 50, session_id: str = "") -> dict:
    """List captured network requests."""
    try:
        sid, session = _get_session(session_id)
        state = _intercept_rules.get(sid, {})
        net_script = state.get("net_script")
        if not net_script:
            return {"success": False, "error": "Network capture not active. Re-connect."}
        txns = net_script.exports_sync.get_transactions(int(count))
        result = []
        for i, t in enumerate(txns):
            result.append({
                "index": i,
                "method": t.get("method", "?"),
                "url": t.get("url", "?"),
                "status": t.get("status", -1),
                "timestamp": t.get("timestamp", 0),
            })
        return {"success": True, "count": len(result), "transactions": result}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def request(index: int, max_body_bytes: int = 16384, session_id: str = "") -> dict:
    """Full request + response details."""
    try:
        sid, session = _get_session(session_id)
        state = _intercept_rules.get(sid, {})
        net_script = state.get("net_script")
        if not net_script:
            return {"success": False, "error": "Network capture not active."}
        txns = net_script.exports_sync.get_transactions(index + 1)
        if index >= len(txns):
            return {"success": False, "error": "Index " + str(index) + " out of range (have " + str(len(txns)) + ")"}
        t = txns[index]
        return {
            "success": True,
            "index": index,
            "request": {
                "method": t.get("method", ""),
                "url": t.get("url", ""),
                "headers": t.get("headers", {}),
                "body": safe_str(t.get("req_body", ""), max_body_bytes),
            },
            "response": {
                "status": t.get("status", -1),
                "headers": t.get("resp_headers", {}),
                "body": safe_str(t.get("resp_body", ""), max_body_bytes),
            },
            "timestamp": t.get("timestamp", 0),
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def monitor(session_id: str = "") -> dict:
    """Return new transactions since the last call."""
    try:
        sid, session = _get_session(session_id)
        state = _intercept_rules.get(sid, {})
        net_script = state.get("net_script")
        if not net_script:
            return {"success": False, "error": "Network capture not active."}
        txns = net_script.exports_sync.get_transactions(5000)
        current = len(txns)
        old = getattr(_sessions[sid], "_last_net_count", None)
        if old is None:
            _sessions[sid]._last_net_count = current
            return {"success": True, "new_transactions": 0, "total": current, "message": "Baseline set"}
        if current > old:
            new_txns = []
            for t in txns[old:]:
                new_txns.append({
                    "index": len(new_txns),
                    "method": t.get("method", "?"),
                    "url": t.get("url", "?"),
                    "status": t.get("status", -1),
                })
            _sessions[sid]._last_net_count = current
            return {"success": True, "new_transactions": len(new_txns), "total": current, "transactions": new_txns}
        return {"success": True, "new_transactions": 0, "total": current}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def search(keyword: str, search_bodies: bool = False, session_id: str = "") -> dict:
    """Search captured requests by keyword."""
    try:
        sid, session = _get_session(session_id)
        state = _intercept_rules.get(sid, {})
        net_script = state.get("net_script")
        if not net_script:
            return {"success": False, "error": "Network capture not active."}
        txns = net_script.exports_sync.get_transactions(5000)
        kw = keyword.lower()
        matches = []
        for i, t in enumerate(txns):
            matched = None
            if kw in (t.get("url") or "").lower():
                matched = "url"
            if not matched and search_bodies and kw in (t.get("resp_body") or "").lower():
                matched = "response_body"
            if not matched and kw in (t.get("req_body") or "").lower():
                matched = "request_body"
            if matched:
                matches.append({"index": i, "url": t.get("url", ""), "method": t.get("method", ""), "matched_in": matched})
        return {"success": True, "count": len(matches), "matches": matches}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── Request replay ──────────────────────────────────────────────────────


def _get_captured_txn(sid, idx):
    """Fetch a captured transaction by index. Returns (txn_dict, error_str)."""
    state = _intercept_rules.get(sid, {})
    net_script = state.get("net_script")
    if not net_script:
        return None, "Network capture not active. Re-connect."
    txns = net_script.exports_sync.get_transactions(max(idx + 1, 1))
    if idx < 0 or idx >= len(txns):
        return None, f"Index {idx} out of range (have {len(txns)})"
    return txns[idx], None


def _build_replay_js(method, url, headers, body, timeout_sec):
    """Generate an NSURLSession replay snippet that sends the request and posts
    a {__done: true, result: <json>} message on completion. Shared by replay,
    replay_as, and race."""
    method_j = json.dumps(method or "GET")
    url_j = json.dumps(url or "")
    headers_j = json.dumps(headers or {})
    body_j = json.dumps(body or "")
    return "\n".join([
        "(function(){ try {",
        "var result = {}; var sem = ObjC.classes.dispatch_semaphore_create(0);",
        "var reqUrl = " + url_j + ";",
        "var reqMethod = " + method_j + ";",
        "var reqHeaders = " + headers_j + ";",
        "var reqBody = " + body_j + ";",
        "if (!reqUrl) { send({__done: true, result: JSON.stringify({error:'url required'})}); return; }",
        "var t0 = Date.now();",
        "var nsurl = ObjC.classes.NSURL.URLWithString_(reqUrl);",
        "var request = ObjC.classes.NSMutableURLRequest.requestWithURL_(nsurl);",
        "request.setHTTPMethod_(reqMethod);",
        "for (var k in reqHeaders) { request.setValue_forHTTPHeaderField_(reqHeaders[k], k); }",
        "if (reqBody) { var bd = ObjC.classes.NSString.stringWithString_(reqBody).dataUsingEncoding_(4); request.setHTTPBody_(bd); }",
        "var session = ObjC.classes.NSURLSession.sharedSession();",
        "session.dataTaskWithRequest_completionHandler_(request, function(data, response, error) {",
        "try { if (response && !response.isNull()) { var resp = new ObjC.Object(response); result.status = resp.statusCode(); var ah = resp.allHeaderFields(); if (ah) { result.headers = {}; var keys = ah.allKeys(); for (var i = 0; i < keys.count(); i++) { result.headers[String(keys.objectAtIndex_(i))] = String(ah.objectForKey_(keys.objectAtIndex_(i))); } } } } catch(e) {}",
        "try { if (data && !data.isNull()) { var d = new ObjC.Object(data); var s = ObjC.classes.NSString.alloc().initWithData_encoding_(d, 4); result.body = s ? String(s) : '<binary>'; result.body_size = d.length(); } } catch(e) {}",
        "try { if (error && !error.isNull()) { result.error = String(new ObjC.Object(error)); } } catch(e) {}",
        "result.duration_ms = Date.now() - t0;",
        "ObjC.classes.dispatch_semaphore_signal(sem);",
        "}).resume();",
        "ObjC.classes.dispatch_semaphore_wait(sem, " + str(int(timeout_sec * 1000000000)) + ");",
        "send({__done: true, result: JSON.stringify(result)});",
        "} catch(e) { send({__done: true, result: JSON.stringify({error: e.message})}); }",
        "})();",
    ])


def _run_replay(session, method, url, headers, body, timeout_sec):
    """Execute a single replay and return parsed result dict."""
    js = _build_replay_js(method, url, headers, body, timeout_sec)
    out = exec_js_stream(session, js, timeout=timeout_sec + 10)
    if out["error"]:
        return {"error": out["error"]}
    info = out.get("info", {})
    if not info.get("result"):
        return {"error": "no response"}
    try:
        return json.loads(info["result"])
    except Exception:
        return {"raw": info["result"]}


@mcp.tool()
def replay(
    index: int = -1, method: str = "", url: str = "",
    headers: dict = None, body: str = "", timeout: int = 30, session_id: str = "",
) -> dict:
    """Replay a captured request, optionally overriding fields.

    If index >= 0, the captured request is loaded as a base and any explicit
    method/url/headers/body arguments override its values.
    """
    try:
        sid, session = _get_session(session_id)
        idx = int(index)
        base = {"method": "", "url": "", "headers": {}, "body": ""}
        if idx >= 0:
            txn, err = _get_captured_txn(sid, idx)
            if err:
                return {"success": False, "error": err}
            base["method"] = txn.get("method", "GET")
            base["url"] = txn.get("url", "")
            base["headers"] = txn.get("headers", {}) or {}
            base["body"] = txn.get("req_body", "") or ""
        eff_method = method or base["method"] or "GET"
        eff_url = url or base["url"]
        eff_headers = dict(base["headers"])
        if headers:
            eff_headers.update(headers)
        eff_body = body if body else base["body"]
        if not eff_url:
            return {"success": False, "error": "url required (pass index to load a captured request, or url=...)"}
        result = _run_replay(session, eff_method, eff_url, eff_headers, eff_body, timeout)
        if "error" in result and len(result) == 1:
            return {"success": False, "error": result["error"]}
        return {"success": True, **result}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def replay_as(
    index: int, auth: str = "", cookie: str = "",
    extra_headers: dict = None, timeout: int = 30, session_id: str = "",
) -> dict:
    """Replay a captured request with swapped credentials.

    Use for IDOR / BOLA testing: replay user A's request as user B by
    overriding Authorization and / or Cookie. Other headers and the body
    are preserved verbatim.

    Args:
        index: Index of the captured request to base the replay on.
        auth: Replacement value for the Authorization header (e.g. "Bearer <token>").
        cookie: Replacement value for the Cookie header.
        extra_headers: Additional headers to set or override.
    """
    try:
        sid, session = _get_session(session_id)
        idx = int(index)
        txn, err = _get_captured_txn(sid, idx)
        if err:
            return {"success": False, "error": err}
        method = txn.get("method", "GET")
        url = txn.get("url", "")
        headers = dict(txn.get("headers", {}) or {})
        body = txn.get("req_body", "") or ""
        # Case-insensitive override of Authorization / Cookie.
        if auth:
            for k in list(headers.keys()):
                if k.lower() == "authorization":
                    del headers[k]
            headers["Authorization"] = auth
        if cookie:
            for k in list(headers.keys()):
                if k.lower() == "cookie":
                    del headers[k]
            headers["Cookie"] = cookie
        if extra_headers:
            headers.update(extra_headers)
        result = _run_replay(session, method, url, headers, body, timeout)
        if "error" in result and len(result) == 1:
            return {"success": False, "error": result["error"]}
        return {
            "success": True,
            "original": {"method": method, "url": url, "status": txn.get("status", -1)},
            "replay": result,
            "swapped": {
                "authorization": bool(auth),
                "cookie": bool(cookie),
                "extra_headers": list((extra_headers or {}).keys()),
            },
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def race(
    index: int, n: int = 10, delay_ms: int = 0,
    timeout: int = 30, session_id: str = "",
) -> dict:
    """Fire N concurrent replays of a captured request.

    Useful for business-logic abuse where the same operation should only
    succeed once (coupon redemption, account creation, double-spend, etc.).
    Sends all N requests from a single Frida script with a tight loop and
    a shared semaphore, then summarizes the resulting status codes.

    Args:
        index: Captured request to race.
        n: Number of concurrent requests (capped at 50).
        delay_ms: Optional stagger between launches in milliseconds.
    """
    try:
        sid, session = _get_session(session_id)
        idx = int(index)
        txn, err = _get_captured_txn(sid, idx)
        if err:
            return {"success": False, "error": err}
        n = max(1, min(int(n), 50))
        delay_ms = max(0, int(delay_ms))
        method = txn.get("method", "GET")
        url = txn.get("url", "")
        headers = txn.get("headers", {}) or {}
        body = txn.get("req_body", "") or ""
        if not url:
            return {"success": False, "error": "captured request has no url"}
        method_j = json.dumps(method)
        url_j = json.dumps(url)
        headers_j = json.dumps(headers)
        body_j = json.dumps(body)
        per_timeout_ns = int(timeout * 1_000_000_000)
        js = "\n".join([
            "(function(){ try {",
            "var N = " + str(n) + ";",
            "var DELAY = " + str(delay_ms) + ";",
            "var reqUrl = " + url_j + ";",
            "var reqMethod = " + method_j + ";",
            "var reqHeaders = " + headers_j + ";",
            "var reqBody = " + body_j + ";",
            "var results = new Array(N);",
            "var done = 0;",
            "var sem = ObjC.classes.dispatch_semaphore_create(0);",
            "function launch(i) {",
            "  var t0 = Date.now();",
            "  var nsurl = ObjC.classes.NSURL.URLWithString_(reqUrl);",
            "  var request = ObjC.classes.NSMutableURLRequest.requestWithURL_(nsurl);",
            "  request.setHTTPMethod_(reqMethod);",
            "  for (var k in reqHeaders) { request.setValue_forHTTPHeaderField_(reqHeaders[k], k); }",
            "  if (reqBody) { var bd = ObjC.classes.NSString.stringWithString_(reqBody).dataUsingEncoding_(4); request.setHTTPBody_(bd); }",
            "  ObjC.classes.NSURLSession.sharedSession().dataTaskWithRequest_completionHandler_(request, function(data, response, error) {",
            "    var r = {i: i, status: -1, duration_ms: Date.now() - t0};",
            "    try { if (response && !response.isNull()) r.status = (new ObjC.Object(response)).statusCode(); } catch(e) {}",
            "    try { if (data && !data.isNull()) { var d = new ObjC.Object(data); r.body_size = d.length(); var s = ObjC.classes.NSString.alloc().initWithData_encoding_(d, 4); if (s) r.body_preview = String(s).substring(0, 200); } } catch(e) {}",
            "    try { if (error && !error.isNull()) r.error = String(new ObjC.Object(error)); } catch(e) {}",
            "    results[i] = r;",
            "    done++;",
            "    if (done === N) ObjC.classes.dispatch_semaphore_signal(sem);",
            "  }).resume();",
            "}",
            "for (var i = 0; i < N; i++) {",
            "  launch(i);",
            "  if (DELAY > 0 && i < N - 1) {",
            "    var until = Date.now() + DELAY;",
            "    while (Date.now() < until) {}",
            "  }",
            "}",
            "ObjC.classes.dispatch_semaphore_wait(sem, " + str(per_timeout_ns) + ");",
            "send({__done: true, result: JSON.stringify(results)});",
            "} catch(e) { send({__done: true, result: JSON.stringify({error: e.message})}); }",
            "})();",
        ])
        out = exec_js_stream(session, js, timeout=timeout + 15)
        if out["error"]:
            return {"success": False, "error": out["error"]}
        info = out.get("info", {})
        if not info.get("result"):
            return {"success": False, "error": "no response"}
        try:
            results = json.loads(info["result"])
        except Exception:
            return {"success": False, "error": "parse: " + info["result"][:200]}
        if isinstance(results, dict) and "error" in results:
            return {"success": False, "error": results["error"]}
        # Summarize.
        by_status = {}
        for r in results:
            if not r:
                continue
            s = str(r.get("status", -1))
            by_status[s] = by_status.get(s, 0) + 1
        return {
            "success": True,
            "fired": len(results),
            "by_status": by_status,
            "results": results,
            "request": {"method": method, "url": url},
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def _diff_dict(a, b):
    """Return added/removed/changed keys between two dicts (case-insensitive)."""
    al = {k.lower(): (k, v) for k, v in (a or {}).items()}
    bl = {k.lower(): (k, v) for k, v in (b or {}).items()}
    added, removed, changed = {}, {}, {}
    for k in bl:
        if k not in al:
            added[bl[k][0]] = bl[k][1]
        elif al[k][1] != bl[k][1]:
            changed[bl[k][0]] = {"a": al[k][1], "b": bl[k][1]}
    for k in al:
        if k not in bl:
            removed[al[k][0]] = al[k][1]
    return {"added": added, "removed": removed, "changed": changed}


def _diff_body(a, b):
    """JSON-aware body diff. Falls back to a unified-style line summary."""
    a = a or ""
    b = b or ""
    if a == b:
        return {"equal": True}
    # Try JSON.
    try:
        ja = json.loads(a) if a else None
        jb = json.loads(b) if b else None
        if isinstance(ja, dict) and isinstance(jb, dict):
            return {"equal": False, "json": _diff_dict(ja, jb)}
    except Exception:
        pass
    # Line diff (truncated).
    al = a.splitlines()
    bl = b.splitlines()
    only_a = [l for l in al if l not in bl][:30]
    only_b = [l for l in bl if l not in al][:30]
    return {
        "equal": False,
        "size_a": len(a),
        "size_b": len(b),
        "only_in_a": only_a,
        "only_in_b": only_b,
    }


@mcp.tool()
def diff(a_index: int, b_index: int, session_id: str = "") -> dict:
    """Diff two captured transactions.

    Compares status, headers (added/removed/changed), and body (JSON-aware
    when both sides parse). Useful for one-call IDOR / BOLA confirmation:
    replay as a different identity, then diff the captured pair.
    """
    try:
        sid, _ = _get_session(session_id)
        ai, bi = int(a_index), int(b_index)
        a, err = _get_captured_txn(sid, ai)
        if err:
            return {"success": False, "error": "a: " + err}
        b, err = _get_captured_txn(sid, bi)
        if err:
            return {"success": False, "error": "b: " + err}
        return {
            "success": True,
            "a": {"index": ai, "method": a.get("method"), "url": a.get("url"), "status": a.get("status")},
            "b": {"index": bi, "method": b.get("method"), "url": b.get("url"), "status": b.get("status")},
            "status_changed": a.get("status") != b.get("status"),
            "url_changed": a.get("url") != b.get("url"),
            "method_changed": a.get("method") != b.get("method"),
            "request_headers": _diff_dict(a.get("headers", {}), b.get("headers", {})),
            "response_headers": _diff_dict(a.get("resp_headers", {}), b.get("resp_headers", {})),
            "request_body": _diff_body(a.get("req_body", ""), b.get("req_body", "")),
            "response_body": _diff_body(a.get("resp_body", ""), b.get("resp_body", "")),
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── In-flight request interception ──────────────────────────────────────

_INTERCEPT_JS = r"""
(function(){
    var rules = [];
    var log = [];
    var maxLog = 2000;

    function matchesRule(url, method, rule) {
        if (rule.method_filter && rule.method_filter !== method.toUpperCase()) return false;
        if (rule.regex) { try { return new RegExp(rule.regex).test(url); } catch(e) { return false; } }
        return rule.pattern && url.indexOf(rule.pattern) !== -1;
    }

    function applyRule(reqIn, rule) {
        var req = reqIn.mutableCopy();
        if (rule.set_url) req.setURL_(ObjC.classes.NSURL.URLWithString_(rule.set_url));
        if (rule.set_method) req.setHTTPMethod_(rule.set_method);
        if (rule.remove_headers && rule.remove_headers.length) {
            for (var i = 0; i < rule.remove_headers.length; i++) req.setValue_forHTTPHeaderField_(null, rule.remove_headers[i]);
        }
        if (rule.set_headers) { for (var k in rule.set_headers) req.setValue_forHTTPHeaderField_(rule.set_headers[k], k); }
        if (rule.add_headers) { for (var k2 in rule.add_headers) req.addValue_forHTTPHeaderField_(rule.add_headers[k2], k2); }
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
                                rule_id: rule.id, hook: selector,
                                original: {url: url, method: method},
                                modified: {url: String(mutated.URL().absoluteString()), method: String(mutated.HTTPMethod())},
                                time: Date.now()
                            });
                            if (log.length > maxLog) log.shift();
                            break;
                        }
                    } catch(e) { log.push({error: 'intercept onEnter: ' + e.message, time: Date.now()}); }
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
        addRule: function(rule) { rules.push(rule); return rules.length; },
        removeRule: function(id) { var before = rules.length; rules = rules.filter(function(r){ return r.id !== id; }); return before - rules.length; },
        listRules: function() { return rules; },
        getLogs: function(limit, clear) { var slice = limit > 0 ? log.slice(-limit) : log.slice(); if (clear) log = []; return slice; },
        setEnabled: function(id, enabled) { for (var i = 0; i < rules.length; i++) { if (rules[i].id === id) { rules[i].enabled = !!enabled; return true; } } return false; }
    };

    send({__hook_init: true, ok: true, hooked: hooked});
})();
"""


def _ensure_intercept_installed(sid, session):
    state = _intercept_rules.get(sid, {})
    if state.get("intercept_script"):
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
    _intercept_rules[sid]["intercept_script"] = script
    _intercept_rules[sid]["hooked"] = ack["hooked"]
    return _intercept_rules[sid]


@mcp.tool()
def intercept(
    pattern: str = "", regex: str = "", method_filter: str = "",
    set_url: str = "", set_method: str = "", set_headers: dict = None,
    add_headers: dict = None, remove_headers: list = None,
    set_body: str = "", session_id: str = "",
) -> dict:
    """Install a rule that modifies in-flight NSURLSession requests matching pattern or regex."""
    global _intercept_counter
    try:
        sid, session = _get_session(session_id)
        state = _ensure_intercept_installed(sid, session)
        if not pattern and not regex:
            return {"success": False, "error": "pattern or regex required"}
        _intercept_counter += 1
        rule_id = "rule_" + str(_intercept_counter)
        rule = {
            "id": rule_id, "enabled": True,
            "pattern": pattern, "regex": regex,
            "method_filter": method_filter.upper() if method_filter else "",
            "set_url": set_url, "set_method": set_method,
            "set_headers": set_headers or {}, "add_headers": add_headers or {},
            "remove_headers": remove_headers or [], "set_body": set_body,
        }
        state["intercept_script"].exports_sync.add_rule(rule)
        return {"success": True, "rule_id": rule_id, "hooked": state.get("hooked", [])}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def intercepts(session_id: str = "") -> dict:
    """List active interception rules in the session."""
    try:
        sid, _ = _get_session(session_id)
        state = _intercept_rules.get(sid, {})
        if not state.get("intercept_script"):
            return {"success": True, "rules": [], "message": "Interception not installed yet."}
        rules = state["intercept_script"].exports_sync.list_rules()
        return {"success": True, "count": len(rules), "rules": rules, "hooked": state.get("hooked", [])}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def intercept_rm(rule_id: str = "", session_id: str = "") -> dict:
    """Remove a single rule. Empty rule_id removes all rules and uninstalls the hook."""
    try:
        sid, _ = _get_session(session_id)
        state = _intercept_rules.get(sid, {})
        if not state.get("intercept_script"):
            return {"success": True, "message": "Nothing to remove."}
        if rule_id:
            removed = state["intercept_script"].exports_sync.remove_rule(rule_id)
            return {"success": True, "removed": removed}
        try:
            state["intercept_script"].unload()
        except Exception:
            pass
        state.pop("intercept_script", None)
        return {"success": True, "uninstalled": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def intercept_toggle(rule_id: str, enabled: bool, session_id: str = "") -> dict:
    """Enable or disable a rule without removing it."""
    try:
        sid, _ = _get_session(session_id)
        state = _intercept_rules.get(sid, {})
        if not state.get("intercept_script"):
            return {"success": False, "error": "Interception not installed."}
        ok = state["intercept_script"].exports_sync.set_enabled(rule_id, enabled)
        return {"success": ok, "rule_id": rule_id, "enabled": enabled if ok else None}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def intercept_logs(limit: int = 100, clear: bool = False, session_id: str = "") -> dict:
    """Get records of intercepted requests (which rule fired, what was changed)."""
    try:
        sid, _ = _get_session(session_id)
        state = _intercept_rules.get(sid, {})
        if not state.get("intercept_script"):
            return {"success": True, "events": [], "message": "Interception not installed yet."}
        events = state["intercept_script"].exports_sync.get_logs(int(limit), bool(clear))
        return {"success": True, "count": len(events), "events": events}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── Vulnerability scan ──────────────────────────────────────────────────

_API_KEY_PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Stripe Live Key", re.compile(r"sk_live_[0-9a-zA-Z]{24,}")),
    ("GitHub Token", re.compile(r"gh[pousr]_[0-9a-zA-Z]{36}")),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("Private Key Block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]

_STACK_TRACE_SIGS = [
    "at java.", "at com.", "Traceback (most recent call last)",
    "NullPointerException", " at /", "/node_modules/",
    "undefined method `", "system.web.", "Microsoft.AspNetCore.",
]

_CRED_QS_KEYS = ["token", "access_token", "id_token", "api_key", "apikey", "auth", "password", "secret"]


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
    req_headers = {k.lower(): v for k, v in (req.get("headers") or {}).items()}
    resp_headers = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
    resp_body = resp.get("body", "") or ""
    status = resp.get("status", -1)
    try:
        status = int(status)
    except (ValueError, TypeError):
        status = -1

    if url.lower().startswith("http://"):
        findings.append({"severity": "high", "issue": "Plaintext HTTP", "detail": "Request sent over unencrypted HTTP."})

    low_url = url.lower()
    for key in _CRED_QS_KEYS:
        if "?" + key + "=" in low_url or "&" + key + "=" in low_url:
            findings.append({"severity": "high", "issue": "Credential in URL query string", "detail": "`" + key + "` parameter visible in URL."})

    auth = req_headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        hdr = _decode_jwt_header(auth.split(" ", 1)[1].strip())
        if hdr:
            alg = (hdr.get("alg") or "").lower()
            if alg == "none":
                findings.append({"severity": "critical", "issue": "JWT alg=none", "detail": "Token has unsigned algorithm."})
            elif alg.startswith("hs"):
                findings.append({"severity": "info", "issue": "JWT uses HMAC (" + alg + ")", "detail": "Verify server secret."})
    if auth.lower().startswith("basic "):
        findings.append({"severity": "medium", "issue": "HTTP Basic auth", "detail": "Base64-encoded credentials sent every request."})

    if url.lower().startswith("https://") and "strict-transport-security" not in resp_headers:
        findings.append({"severity": "low", "issue": "Missing HSTS", "detail": "Response served over HTTPS without Strict-Transport-Security."})
    if resp_headers.get("access-control-allow-origin") == "*":
        findings.append({"severity": "medium", "issue": "Permissive CORS", "detail": "Access-Control-Allow-Origin: *"})

    server = resp_headers.get("server", "")
    if server and any(c.isdigit() for c in server):
        findings.append({"severity": "info", "issue": "Server version disclosure", "detail": "Server: " + server})

    if status >= 500:
        for sig in _STACK_TRACE_SIGS:
            if sig in resp_body:
                findings.append({"severity": "medium", "issue": "Stack trace in error response", "detail": "Matched: " + repr(sig)})
                break

    for name, pat in _API_KEY_PATTERNS:
        m = pat.search(resp_body)
        if m:
            findings.append({"severity": "critical", "issue": "Possible " + name + " leak", "detail": "Sample: " + m.group()[:40] + "..."})

    return findings


@mcp.tool()
def scan(count: int = 100, session_id: str = "") -> dict:
    """Scan captured network traffic for common security issues."""
    try:
        idx_list = requests(count=count, session_id=session_id)
        if not idx_list.get("success"):
            return idx_list
        results = []
        severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for t in idx_list.get("transactions", []):
            details = request(index=t["index"], max_body_bytes=65536, session_id=session_id)
            if not details.get("success"):
                continue
            findings = _scan_single(details)
            if not findings:
                continue
            for f in findings:
                severity_count[f["severity"]] = severity_count.get(f["severity"], 0) + 1
            results.append({"index": t["index"], "method": t.get("method"), "url": t.get("url"), "status": t.get("status"), "findings": findings})
        return {"success": True, "scanned": len(idx_list.get("transactions", [])), "with_findings": len(results),
                "severity_summary": severity_count, "results": results}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── Fuzzing ─────────────────────────────────────────────────────────────

_FUZZ_PAYLOADS = {
    "sqli": ["'", "''", "' OR '1'='1", "' OR 1=1--", "1' UNION SELECT NULL--", "1; DROP TABLE users--", "' AND SLEEP(5)--"],
    "xss": ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>", "javascript:alert(1)", "'\"><svg onload=alert(1)>", "{{7*7}}"],
    "path_traversal": ["../etc/passwd", "../../etc/passwd", "../../../etc/passwd", "%2e%2e%2fetc%2fpasswd", "..\\..\\windows\\win.ini"],
    "cmd_inj": ["; id", "| id", "|| id", "`id`", "$(id)", ";ping -c1 127.0.0.1"],
    "nosql": ["{\"$gt\":\"\"}", "{\"$ne\":null}", "{\"$regex\":\".*\"}"],
    "idor_numeric": ["0", "1", "2", "100", "999999999", "-1"],
    "auth_bypass": ["", "null", "undefined", "[]", "{}", "0", "false", "Bearer null", "Bearer undefined"],
    "buffer_overflow": ["A" * 256, "A" * 1024, "A" * 4096],
}

_SQL_ERROR_SIGS = ["SQL syntax", "sqlite3.OperationalError", "ORA-", "PostgreSQL", "SQLSTATE"]
_TRAVERSAL_SIGS = ["root:x:", "[boot loader]", "/bin/bash"]
_CMD_INJ_SIGS = ["uid=", "gid=", "groups=", "Linux ", "DarwinKernel"]


def _detect_anomalies(payload, body, status, baseline):
    flags = []
    try:
        status = int(status)
    except (ValueError, TypeError):
        status = -1
    bl_status = baseline.get("status", -1)
    try:
        bl_status = int(bl_status)
    except (ValueError, TypeError):
        bl_status = -1
    bl_size = baseline.get("body_size", 0)
    if status != bl_status and status != -1:
        flags.append("status changed " + str(bl_status) + "->" + str(status))
    if bl_size > 0 and abs(len(body) - bl_size) > max(50, bl_size * 0.3):
        flags.append("body size delta (" + str(bl_size) + "->" + str(len(body)) + ")")
    if any(sig in body for sig in _SQL_ERROR_SIGS):
        flags.append("SQL error signature")
    if any(sig in body for sig in _TRAVERSAL_SIGS):
        flags.append("path traversal success")
    if any(sig in body for sig in _CMD_INJ_SIGS):
        flags.append("command injection signature")
    if payload and payload in body and len(payload) > 4:
        flags.append("payload reflected (possible XSS)")
    if status >= 500:
        flags.append("server error " + str(status))
    return flags


@mcp.tool()
def fuzz(index: int, target: str, payloads: list = None, payload_set: str = "",
                      timeout_per: int = 10, max_payloads: int = 50, session_id: str = "") -> dict:
    """Fuzz a captured request by mutating one field through a list of payloads."""
    try:
        if payloads is None:
            payloads = _FUZZ_PAYLOADS.get(payload_set or "", [])
        if not payloads:
            return {"success": False, "error": "no payloads"}
        payloads = payloads[:max_payloads]

        base = request(index=index, max_body_bytes=4096, session_id=session_id)
        if not base.get("success"):
            return {"success": False, "error": "could not fetch baseline: " + str(base.get("error"))}
        orig_url = base["request"]["url"]
        orig_method = base["request"]["method"]
        orig_headers = dict(base["request"].get("headers") or {})
        orig_body = base["request"].get("body", "")

        baseline_replay = replay(index=index, timeout=timeout_per, session_id=session_id)
        baseline_summary = {"status": baseline_replay.get("status", -1), "body_size": baseline_replay.get("body_size", 0)}

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
                new_qs = []
                replaced = False
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
                return {"success": False, "error": "unknown target: " + target}

            r = replay(index=-1, method=orig_method, url=override.get("url", orig_url),
                                    headers=override.get("headers", orig_headers),
                                    body=override.get("body", orig_body),
                                    timeout=timeout_per, session_id=session_id)
            body_text = r.get("body", "") or ""
            anomalies = _detect_anomalies(payload, body_text, r.get("status", -1), baseline_summary)
            results.append({"payload": payload[:200], "status": r.get("status", -1), "body_size": r.get("body_size", 0),
                            "elapsed_ms": r.get("elapsed_ms"), "anomalies": anomalies,
                            "body_preview": body_text[:200] if anomalies else ""})

        interesting = [r for r in results if r["anomalies"]]
        return {"success": True, "baseline": baseline_summary, "target": target, "payload_set": payload_set,
                "tried": len(results), "interesting": len(interesting), "results": results}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── Endpoints map ───────────────────────────────────────────────────────

@mcp.tool()
def endpoints(count: int = 500, session_id: str = "") -> dict:
    """Group captured traffic by host + path template."""
    try:
        idx_list = requests(count=count, session_id=session_id)
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
                endpoint = bucket.setdefault(path, {"methods": set(), "statuses": {}, "count": 0, "has_auth_call": False})
                endpoint["methods"].add(t.get("method", "?"))
                s = t.get("status", -1)
                endpoint["statuses"][s] = endpoint["statuses"].get(s, 0) + 1
                endpoint["count"] += 1
            except Exception:
                continue
        out = []
        for host, endpoints in hosts.items():
            out.append({"host": host, "endpoint_count": len(endpoints), "endpoints": sorted([
                {"path": p, "methods": sorted(e["methods"]), "count": e["count"], "statuses": e["statuses"], "has_auth_call": e["has_auth_call"]}
                for p, e in endpoints.items()], key=lambda x: -x["count"])})
        out.sort(key=lambda x: -x["endpoint_count"])
        return {"success": True, "host_count": len(out), "hosts": out}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── URL schemes & deep links ────────────────────────────────────────────

@mcp.tool()
def schemes(session_id: str = "") -> dict:
    """List URL schemes the app handles."""
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
                for (var j = 0; j < schemes.count(); j++) schArr.push(String(schemes.objectAtIndex_(j)));
            }
            out.push({name: name ? String(name) : '', schemes: schArr});
        }
    }
    return JSON.stringify({url_types: out});
})()
""")
        if r.get("ok"):
            return {"success": True, **json.loads(r["result"])}
        return {"success": False, "error": str(r)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def open_url(url: str, session_id: str = "") -> dict:
    """Open a URL inside the app via UIApplication.openURL."""
    try:
        _, session = _get_session(session_id)
        u = json.dumps(url)
        js = (
            "(function(){"
            "var nsurl = ObjC.classes.NSURL.URLWithString_(" + u + ");"
            "if (!nsurl) return JSON.stringify({ok: false, error: 'invalid URL'});"
            "var app = ObjC.classes.UIApplication.sharedApplication();"
            "if (app['- openURL:options:completionHandler:']) {"
            "  var empty = ObjC.classes.NSDictionary.dictionary();"
            "  app.openURL_options_completionHandler_(nsurl, empty, null);"
            "} else {"
            "  app.openURL_(nsurl);"
            "}"
            "return JSON.stringify({ok: true, opened: " + u + "});"
            "})()"
        )
        r = exec_js(session, js, timeout=10)
        if r.get("ok"):
            data = json.loads(r["result"])
            return {"success": data.get("ok", False), **data}
        return {"success": False, "error": str(r)}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── Entitlements ────────────────────────────────────────────────────────

_KNOWN_ENTITLEMENTS = [
    "application-identifier", "com.apple.developer.team-identifier",
    "com.apple.developer.associated-domains", "com.apple.security.application-groups",
    "keychain-access-groups", "aps-environment",
    "com.apple.developer.icloud-services", "com.apple.developer.in-app-payments",
    "com.apple.developer.networking.networkextension", "com.apple.developer.networking.vpn.api",
    "com.apple.developer.healthkit", "com.apple.developer.homekit",
    "com.apple.developer.siri", "com.apple.security.get-task-allow",
]


@mcp.tool()
def entitlements(session_id: str = "") -> dict:
    """Dump the app's entitlements."""
    try:
        _, session = _get_session(session_id)
        keys_j = json.dumps(_KNOWN_ENTITLEMENTS)
        r = exec_js(session, """
(function(){
    var SecTaskCreateFromSelf = new NativeFunction(
        Module.findExportByName('Security', 'SecTaskCreateFromSelf'), 'pointer', ['pointer']);
    var SecTaskCopyValueForEntitlement = new NativeFunction(
        Module.findExportByName('Security', 'SecTaskCopyValueForEntitlement'), 'pointer', ['pointer', 'pointer', 'pointer']);
    var task = SecTaskCreateFromSelf(ptr(0));
    if (task.isNull()) return JSON.stringify({error: 'SecTaskCreateFromSelf failed'});
    var keys = """ + keys_j + R""";
    var out = {};
    for (var i = 0; i < keys.length; i++) {
        var keyStr = ObjC.classes.NSString.stringWithString_(keys[i]);
        var val = SecTaskCopyValueForEntitlement(task, keyStr.handle, ptr(0));
        if (!val.isNull()) {
            try { out[keys[i]] = String(new ObjC.Object(val)); } catch(e) { out[keys[i]] = '<unreadable>'; }
        }
    }
    return JSON.stringify(out);
})()
""", timeout=15)
        if r.get("ok"):
            data = json.loads(r["result"])
            if "error" in data:
                return {"success": False, "error": data["error"]}
            return {"success": True, "count": len(data), "entitlements": data}
        return {"success": False, "error": str(r)}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── Pasteboard ──────────────────────────────────────────────────────────

@mcp.tool()
def pasteboard(session_id: str = "") -> dict:
    """Read the system pasteboard."""
    try:
        _, session = _get_session(session_id)
        r = exec_js(session, """
(function(){
    var pb = ObjC.classes.UIPasteboard.generalPasteboard();
    return JSON.stringify({
        string: pb.string() ? String(pb.string()) : null,
        has_url: !!pb.URL(), url: pb.URL() ? String(pb.URL()) : null,
        has_image: pb.image() ? true : false, num_items: pb.numberOfItems()
    });
})()
""")
        if r.get("ok"):
            return {"success": True, **json.loads(r["result"])}
        return {"success": False, "error": str(r)}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── Memory scan ─────────────────────────────────────────────────────────

@mcp.tool()
def memory(pattern: str, encoding: str = "ascii", max_hits: int = 50, session_id: str = "") -> dict:
    """Scan writable memory regions for a byte pattern."""
    try:
        _, session = _get_session(session_id)
        if encoding == "hex":
            hex_str = pattern.replace(" ", "").replace("0x", "")
            if len(hex_str) % 2 != 0:
                return {"success": False, "error": "hex pattern must have even length"}
            frida_pattern = " ".join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
        else:
            frida_pattern = " ".join(format(ord(c), "02x") for c in pattern)
        fp = json.dumps(frida_pattern)
        ctx_size = max(16, min(len(pattern) * 2 + 16, 64))
        r = exec_js(session, """
(function(){
    var ranges = Process.enumerateRanges({protection: 'rw-', coalesce: true});
    var hits = [];
    for (var i = 0; i < ranges.length && hits.length < """ + str(int(max_hits)) + R"""; i++) {
        var r = ranges[i];
        try {
            Memory.scanSync(r.base, r.size, """ + fp + R""").forEach(function(m) {
                if (hits.length >= """ + str(int(max_hits)) + R""") return;
                var ctx;
                try { ctx = m.address.readByteArray(""" + str(ctx_size) + R"""); } catch(e) { ctx = null; }
                var hex = '';
                if (ctx) {
                    var u = new Uint8Array(ctx);
                    for (var k = 0; k < u.length; k++) hex += (u[k] < 16 ? '0' : '') + u[k].toString(16);
                }
                hits.push({address: m.address.toString(), region_base: r.base.toString(), region_size: r.size, context_hex: hex});
            });
        } catch(e) {}
    }
    return JSON.stringify(hits);
})()
""", timeout=60)
        if r.get("ok"):
            hits = json.loads(r["result"])
            return {"success": True, "count": len(hits), "hits": hits}
        return {"success": False, "error": str(r)}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── Strings extraction ──────────────────────────────────────────────────

@mcp.tool()
def strings(path: str, min_length: int = 6, max_results: int = 1000, search: str = "", local: bool = False, session_id: str = "") -> dict:
    """Extract printable ASCII strings from a binary file."""
    try:
        if local:
            with open(path, "rb") as f:
                data = f.read()
        else:
            pull = pull(device_path=path, output_path=path.replace("/", "_") + ".tmp", session_id=session_id)
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


# ── Logs ─────────────────────────────────────────────────────────────────

_LOG_HOOK_JS = r"""
(function(){
    var log = [];
    var maxLog = 2000;
    function record(prefix, text) { log.push({src: prefix, text: text, time: Date.now()}); if (log.length > maxLog) log.shift(); }
    try {
        var nslog = Module.findExportByName(null, 'NSLogv');
        if (nslog) {
            Interceptor.attach(nslog, { onEnter: function(args) { try { record('NSLog', String(new ObjC.Object(args[0])).substring(0, 500)); } catch(e) {} } });
        }
    } catch(e) {}
    try {
        var oslog = Module.findExportByName(null, '_os_log_impl');
        if (oslog) {
            Interceptor.attach(oslog, { onEnter: function(args) { try { record('os_log', (args[2].readUtf8String() || '').substring(0, 500)); } catch(e) {} } });
        }
    } catch(e) {}
    rpc.exports = { drain: function(limit, clear) { var slice = limit > 0 ? log.slice(-limit) : log.slice(); if (clear) log = []; return slice; } };
    send({__hook_init: true, ok: true});
})();
"""


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


@mcp.tool()
def logs(enable: bool = True, session_id: str = "") -> dict:
    """Capture NSLog and os_log calls."""
    try:
        sid, session = _get_session(session_id)
        if not enable:
            return _remove_named_hook(sid, "logs")
        return _install_named_hook(sid, session, "logs", _LOG_HOOK_JS)
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def logs_drain(limit: int = 100, clear: bool = False, session_id: str = "") -> dict:
    """Drain captured log events."""
    try:
        sid, _ = _get_session(session_id)
        h = _named_hooks.get(sid, {}).get("logs")
        if not h:
            return {"success": True, "events": [], "message": "Log capture not installed."}
        events = h["script"].exports_sync.drain(int(limit), bool(clear))
        return {"success": True, "count": len(events), "events": events}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── JWT decoder ─────────────────────────────────────────────────────────

@mcp.tool()
def jwt(token: str) -> dict:
    """Decode a JWT and flag weak/missing security properties."""
    try:
        token = token.strip()
        if token.lower().startswith("bearer "):
            token = token[7:].strip()
        parts = token.split(".")
        if len(parts) < 2:
            return {"success": False, "error": "not a JWT"}

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
            warnings.append({"severity": "info", "issue": "HMAC (" + alg + ") — server secret must be strong"})
        if "kid" in header:
            warnings.append({"severity": "info", "issue": "kid=" + header["kid"] + " — possible kid injection"})
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
        return {"success": True, "header": header, "payload": payload,
                "signature_present": len(parts) == 3 and bool(parts[2]), "warnings": warnings}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── Storage: UserDefaults ───────────────────────────────────────────────

@mcp.tool()
def defaults(search: str = "", session_id: str = "") -> dict:
    """Browse NSUserDefaults."""
    try:
        _, session = _get_session(session_id)
        sj = json.dumps(search)
        r = exec_js(session, """
(function(){
    var ud = ObjC.classes.NSUserDefaults.standardUserDefaults();
    var dict = ud.dictionaryRepresentation();
    var keys = dict.allKeys();
    var entries = [];
    var filter = """ + sj + R""";
    for (var i = 0; i < keys.count(); i++) {
        try {
            var key = String(keys.objectAtIndex_(i));
            if (!filter || key.toLowerCase().indexOf(filter.toLowerCase()) !== -1) {
                var val = dict.objectForKey_(keys.objectAtIndex_(i));
                var valStr = val ? String(val) : 'nil';
                if (valStr.length > 300) valStr = valStr.substring(0, 300);
                entries.push({key: key, value: valStr});
            }
        } catch(e) {}
    }
    return JSON.stringify(entries);
})()
""")
        if r.get("ok"):
            return {"success": True, "entries": json.loads(r["result"])}
        return {"success": False, "error": str(r)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def defaults_set(key: str, value: str, session_id: str = "") -> dict:
    """Set a value in NSUserDefaults."""
    try:
        _, session = _get_session(session_id)
        k, v = json.dumps(key), json.dumps(value)
        exec_js(session, """
(function(){
    var ud = ObjC.classes.NSUserDefaults.standardUserDefaults();
    ud.setObject_forKey_(ObjC.classes.NSString.stringWithString_(""" + v + R"""), """ + k + R""");
    ud.synchronize();
    return 'ok';
})()
""")
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── Storage: Keychain ───────────────────────────────────────────────────

@mcp.tool()
def keychain(session_id: str = "") -> dict:
    """Dump generic password keychain items."""
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
        Module.findExportByName('Security', 'SecItemCopyMatching'), 'int', ['pointer', 'pointer']);
    var resPtr = Memory.alloc(Process.pointerSize);
    var status = copyMatch(q.handle, resPtr);
    if (status !== 0) return JSON.stringify({error: 'SecItemCopyMatching status ' + status});
    var arr = new ObjC.Object(Memory.readPointer(resPtr));
    var out = [];
    for (var i = 0; i < arr.count(); i++) {
        var item = arr.objectAtIndex_(i);
        out.push({
            service: item.objectForKey_('svce') ? String(item.objectForKey_('svce')) : '',
            account: item.objectForKey_('acct') ? String(item.objectForKey_('acct')) : '',
            value: item.objectForKey_('v_Data') ? (function(){ try { return String(ObjC.classes.NSString.alloc().initWithData_encoding_(item.objectForKey_('v_Data'), 4)); } catch(e) { return '<binary>'; }})() : ''
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


# ── Storage: Cookies ────────────────────────────────────────────────────

@mcp.tool()
def cookies(session_id: str = "") -> dict:
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
            out.push({name: String(c.name()), value: String(c.value()), domain: String(c.domain()),
                      path: String(c.path()), secure: c.isSecure() ? true : false,
                      http_only: c.isHTTPOnly() ? true : false});
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


# ── File system ─────────────────────────────────────────────────────────

@mcp.tool()
def files(path: str = "", session_id: str = "") -> dict:
    """List files in the app sandbox."""
    try:
        _, session = _get_session(session_id)
        p = json.dumps(path)
        r = exec_js(session, """
(function(){
    var fm = ObjC.classes.NSFileManager.defaultManager();
    var path = """ + p + R""";
    if (!path || path === '') { path = String(ObjC.classes.NSProcessInfo.processInfo().environment().objectForKey_('HOME')); }
    var err = Memory.alloc(Process.pointerSize);
    var contents = fm.contentsOfDirectoryAtPath_error_(path, err);
    if (!contents) return JSON.stringify({error: 'Cannot read directory', path: path});
    var out = [];
    for (var i = 0; i < contents.count(); i++) {
        var name = String(contents.objectAtIndex_(i));
        var full = path + '/' + name;
        var isDirBuf = Memory.alloc(1);
        fm.fileExistsAtPath_isDirectory_(full, isDirBuf);
        var attrs = fm.attributesOfItemAtPath_error_(full, err);
        var size = -1;
        if (attrs) { var s = attrs.objectForKey_('NSFileSize'); if (s) size = s.longLongValue(); }
        out.push({name: name, path: full, is_dir: Memory.readU8(isDirBuf) !== 0, size: size});
    }
    return JSON.stringify({path: path, entries: out});
})()
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
def read(path: str, max_bytes: int = 65536, session_id: str = "") -> dict:
    """Read a file from the device as UTF-8."""
    try:
        _, session = _get_session(session_id)
        p = json.dumps(path)
        r = exec_js(session, """
(function(){
    var data = ObjC.classes.NSData.dataWithContentsOfFile_(""" + p + R""");
    if (!data) return JSON.stringify({error: 'Cannot read file'});
    var len = data.length();
    var mb = Math.min(len, """ + str(int(max_bytes)) + R""");
    var slice = len > mb ? data.subdataWithRange_([0, mb]) : data;
    var s = ObjC.classes.NSString.alloc().initWithData_encoding_(slice, 4);
    return JSON.stringify({size: len, truncated: len > mb, content: s ? String(s) : null, binary: !s});
})()
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
def pull(device_path: str, output_path: str, max_size: int = 0, session_id: str = "") -> dict:
    """Pull a file from the device sandbox to a local path (binary-safe, chunked)."""
    try:
        _, session = _get_session(session_id)
        p = json.dumps(device_path)
        cap = int(max_size)
        js = """(function(){
    try {
        var data = ObjC.classes.NSData.dataWithContentsOfFile_(""" + p + R"""");
        if (!data) { send({__error: 'Cannot read'}); send({__done: true}); return; }
        var len = data.length();
        var total = (""" + str(cap) + R""" > 0 && """ + str(cap) + R""" < len) ? """ + str(cap) + R""" : len;
        var sent = 0, idx = 0, basePtr = data.bytes();
        while (sent < total) {
            var size = Math.min(4*1024*1024, total - sent);
            send({chunk: idx, size: size}, basePtr.add(sent).readByteArray(size));
            sent += size; idx++;
        }
        send({__done: true, total: total, file_size: len});
    } catch(e) { send({__error: e.message}); send({__done: true}); }
})();"""
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
        return {"success": True, "output_path": output_path,
                "bytes_written": sum(len(b) for b in ordered.values()),
                "file_size_on_device": result["info"].get("file_size", -1)}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── SQLite ──────────────────────────────────────────────────────────────

@mcp.tool()
def sqlite(session_id: str = "") -> dict:
    """Find SQLite databases in the app sandbox."""
    try:
        _, session = _get_session(session_id)
        r = exec_js(session, """
(function(){
    var fm = ObjC.classes.NSFileManager.defaultManager();
    var home = String(ObjC.classes.NSProcessInfo.processInfo().environment().objectForKey_('HOME'));
    var enumerator = fm.enumeratorAtPath_(home);
    var out = []; var p;
    while ((p = enumerator.nextObject()) !== null) {
        var name = String(p).toLowerCase();
        if (name.endsWith('.sqlite') || name.endsWith('.sqlite3') || name.endsWith('.db')) {
            var full = home + '/' + String(p);
            var err = Memory.alloc(Process.pointerSize);
            var attrs = fm.attributesOfItemAtPath_error_(full, err);
            var size = -1;
            if (attrs) { var s = attrs.objectForKey_('NSFileSize'); if (s) size = s.longLongValue(); }
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
def sqlite_query(path: str, sql: str, limit: int = 100, session_id: str = "") -> dict:
    """Run a SQL query against a SQLite database in the app sandbox."""
    try:
        _, session = _get_session(session_id)
        p, q, lim = json.dumps(path), json.dumps(sql), int(limit)
        r = exec_js(session, """
(function(){
    function findFn(name) { return Module.findExportByName('libsqlite3.dylib', name) || Module.findExportByName(null, name); }
    var openFn = new NativeFunction(findFn('sqlite3_open'),'int',['pointer','pointer']);
    var prep = new NativeFunction(findFn('sqlite3_prepare_v2'),'int',['pointer','pointer','int','pointer','pointer']);
    var step = new NativeFunction(findFn('sqlite3_step'),'int',['pointer']);
    var ncol = new NativeFunction(findFn('sqlite3_column_count'),'int',['pointer']);
    var cnam = new NativeFunction(findFn('sqlite3_column_name'),'pointer',['pointer','int']);
    var ctxt = new NativeFunction(findFn('sqlite3_column_text'),'pointer',['pointer','int']);
    var fin  = new NativeFunction(findFn('sqlite3_finalize'),'int',['pointer']);
    var clos = new NativeFunction(findFn('sqlite3_close'),'int',['pointer']);
    var errm = new NativeFunction(findFn('sqlite3_errmsg'),'pointer',['pointer']);
    var dbPtr = Memory.alloc(Process.pointerSize);
    var pathPtr = Memory.allocUtf8String(""" + p + R""");
    if (openFn(pathPtr, dbPtr) !== 0) return JSON.stringify({error: 'open failed'});
    var db = Memory.readPointer(dbPtr);
    var stmtPtr = Memory.alloc(Process.pointerSize);
    var sqlPtr = Memory.allocUtf8String(""" + q + R""");
    if (prep(db, sqlPtr, -1, stmtPtr, ptr(0)) !== 0) { var msg = errm(db).readUtf8String(); clos(db); return JSON.stringify({error: 'prepare: ' + msg}); }
    var stmt = Memory.readPointer(stmtPtr);
    var ncols = ncol(stmt);
    var cols = [];
    for (var i = 0; i < ncols; i++) cols.push(cnam(stmt, i).readUtf8String());
    var rows = [];
    while (rows.length < """ + str(lim) + R""") {
        var rc = step(stmt);
        if (rc !== 100) break;
        var row = {};
        for (var i = 0; i < ncols; i++) { var p2 = ctxt(stmt, i); row[cols[i]] = p2.isNull() ? null : p2.readUtf8String(); }
        rows.push(row);
    }
    fin(stmt); clos(db);
    return JSON.stringify({columns: cols, rows: rows});
})()
""", timeout=30)
        if r.get("ok"):
            data = json.loads(r["result"])
            if "error" in data:
                return {"success": False, "error": data["error"]}
            return {"success": True, **data}
        return {"success": False, "error": str(r)}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── Runtime introspection ───────────────────────────────────────────────

@mcp.tool()
def exec(js_code: str, session_id: str = "") -> dict:
    """Execute arbitrary JavaScript in the app via Frida."""
    try:
        _, session = _get_session(session_id)
        r = exec_js(session, js_code, timeout=30)
        return {"success": r.get("ok", False), "result": r}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def modules(session_id: str = "") -> dict:
    """List loaded Mach-O modules."""
    try:
        _, session = _get_session(session_id)
        r = exec_js(session, """
(function(){
    var mods = Process.enumerateModules();
    return JSON.stringify(mods.map(function(m){ return {name: m.name, base: m.base.toString(), size: m.size, path: m.path}; }));
})()
""")
        if r.get("ok"):
            data = json.loads(r["result"])
            return {"success": True, "count": len(data), "modules": data}
        return {"success": False, "error": str(r)}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── Persistent hooks (SSL unpin, JB bypass, crypto) ─────────────────────

_SSL_UNPIN_JS = r"""
(function(){
    try {
        var installed = [];
        var SSLSetSessionOption = Module.findExportByName(null, 'SSLSetSessionOption');
        if (SSLSetSessionOption) { Interceptor.attach(SSLSetSessionOption, { onEnter: function(args) { if (args[1].toInt32() === 0) args[2] = ptr('0x1'); } }); installed.push('SSLSetSessionOption'); }
        var SSLHandshake = Module.findExportByName(null, 'SSLHandshake');
        if (SSLHandshake) { Interceptor.attach(SSLHandshake, { onLeave: function(retval) { if (retval.toInt32() === -9807 || retval.toInt32() === -9808) retval.replace(0); } }); installed.push('SSLHandshake'); }
        var SSLSetPeerDomainName = Module.findExportByName(null, 'SSLSetPeerDomainName');
        if (SSLSetPeerDomainName) { Interceptor.attach(SSLSetPeerDomainName, { onLeave: function(retval) { retval.replace(0); } }); installed.push('SSLSetPeerDomainName'); }
        var tls_helper = Module.findExportByName(null, 'tls_helper_create_peer_trust');
        if (tls_helper) { Interceptor.attach(tls_helper, { onLeave: function(retval) { retval.replace(0); } }); installed.push('tls_helper_create_peer_trust'); }
        ObjC.schedule(ObjC.mainQueue, function() {
            if (ObjC.classes.AFSecurityPolicy) {
                var evalM = ObjC.classes.AFSecurityPolicy['- evaluateServerTrust:forDomain:'];
                if (evalM) { Interceptor.attach(evalM.implementation, { onLeave: function(retval) { retval.replace(ptr(1)); } }); installed.push('AFSecurityPolicy'); }
            }
        });
        send({__hook_init: true, ok: true, installed: installed});
    } catch(e) { send({__hook_init: true, ok: false, error: e.message}); }
})();
"""


_JB_BYPASS_JS = r"""
(function(){
    ObjC.schedule(ObjC.mainQueue, function() {
    try {
        var jbPaths = ['/Applications/Cydia.app','/Applications/Sileo.app','/Applications/Zebra.app',
            '/Library/MobileSubstrate','/usr/sbin/sshd','/etc/apt','/private/var/lib/apt',
            '/private/var/lib/cydia','/private/var/stash','/usr/bin/ssh','/bin/bash','/bin/sh',
            '/var/cache/apt','/var/lib/apt','/var/lib/cydia','/var/log/syslog',
            '/Library/MobileSubstrate/MobileSubstrate.dylib'];
        var NSFM = ObjC.classes.NSFileManager;
        Interceptor.attach(NSFM['- fileExistsAtPath:'].implementation, {
            onEnter: function(args) { this.path = new ObjC.Object(args[2]).toString(); this.match = jbPaths.some(function(p){ return this.path.indexOf(p) !== -1; }.bind(this)); },
            onLeave: function(retval) { if (this.match) retval.replace(ptr(0)); }
        });
        var UIApp = ObjC.classes.UIApplication;
        if (UIApp && UIApp['- canOpenURL:']) { Interceptor.attach(UIApp['- canOpenURL:'].implementation, {
            onEnter: function(args) { var url = new ObjC.Object(args[2]).absoluteString().toString(); this.match = url.indexOf('cydia') === 0 || url.indexOf('sileo') === 0; },
            onLeave: function(retval) { if (this.match) retval.replace(ptr(0)); }
        }); }
        var stat = Module.findExportByName(null, 'stat');
        if (stat) { Interceptor.attach(stat, {
            onEnter: function(args) { try { this.p = args[0].readUtf8String(); } catch(e) { this.p = ''; } this.match = jbPaths.some(function(p){ return this.p && this.p.indexOf(p) !== -1; }.bind(this)); },
            onLeave: function(retval) { if (this.match) retval.replace(-1); }
        }); }
        var forkFn = Module.findExportByName(null, 'fork');
        if (forkFn) Interceptor.replace(forkFn, new NativeCallback(function(){ return -1; }, 'int', []));
        send({__hook_init: true, ok: true});
    } catch(e) { send({__hook_init: true, ok: false, error: e.message}); }
    });
})();
"""


@mcp.tool()
def ssl_unpin(enable: bool = True, session_id: str = "") -> dict:
    """Install or remove SSL pinning bypass."""
    try:
        sid, session = _get_session(session_id)
        if enable:
            return _install_named_hook(sid, session, "ssl_unpin", _SSL_UNPIN_JS)
        return _remove_named_hook(sid, "ssl_unpin")
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def jb_bypass(enable: bool = True, session_id: str = "") -> dict:
    """Hide common jailbreak indicators."""
    try:
        sid, session = _get_session(session_id)
        if enable:
            return _install_named_hook(sid, session, "jb_bypass", _JB_BYPASS_JS)
        return _remove_named_hook(sid, "jb_bypass")
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── Main ─────────────────────────────────────────────────────────────────



# ── Crypto Hooks ────────────────────────────────────────────────────────

_CRYPTO_HOOKS_JS = r"""(function(){try{function h(b,m){if(!b)return'';var u=new Uint8Array(b),l=Math.min(u.length,m||64),o='';for(var i=0;i<l;i++){var v=u[i].toString(16);o+=v.length<2?'0'+v:v;}return u.length>l?o+'...':o;}var c=Module.findExportByName(null,'CCCrypt');if(c){Interceptor.attach(c,{onEnter:function(a){send({hook:'CCCrypt',op:a[0].toInt32()===0?'encrypt':'decrypt',alg:a[1].toInt32(),key_hex:h(a[3].isNull()?null:a[3].readByteArray(a[4].toInt32())),iv_hex:h(a[5].isNull()?null:a[5].readByteArray(16)),in_len:a[7].toInt32(),time:Date.now()});}});}send({__hook_init:true,ok:true});}catch(e){send({__hook_init:true,ok:false,error:e.message});}})();"""

@mcp.tool()
def crypto(enable: bool = True, session_id: str = "") -> dict:
    """Hook CommonCrypto (CCCrypt) and buffer key/IV events."""
    try:
        sid, session = _get_session(session_id)
        if enable:
            return _install_named_hook(sid, session, "crypto", _CRYPTO_HOOKS_JS, max_events=2000)
        return _remove_named_hook(sid, "crypto")
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def crypto_logs(limit: int = 100, clear: bool = False, session_id: str = "") -> dict:
    """Read captured CommonCrypto events."""
    try:
        sid, _ = _get_session(session_id)
        hook = _named_hooks.get(sid, {}).get("crypto")
        if not hook:
            return {"success": True, "events": [], "message": "Crypto hooks not installed."}
        buf = hook["events"]
        slice_ = buf[-limit:] if limit else list(buf)
        if clear:
            for _ in slice_:
                if buf:
                    buf.pop(0)
        return {"success": True, "count": len(slice_), "events": slice_}
    except Exception as e:
        return {"success": False, "error": str(e)}



# ── Binary Dump ────────────────────────────────────────────────────────

@mcp.tool()
def dump(output_path: str, module_name: str = "", session_id: str = "") -> dict:
    """Dump the decrypted main Mach-O binary (frida-ios-dump style)."""
    try:
        _, session = _get_session(session_id)
        mn = json.dumps(module_name)
        js = "(function(){try{var mn=" + mn + ";if(!mn){var ep=String(ObjC.classes.NSBundle.mainBundle().executablePath());mn=ep.split('/').pop();} var mod=Process.findModuleByName(mn);if(!mod){send({__error:'not found'});send({__done:true});return;} var nsd=ObjC.classes.NSData.dataWithContentsOfFile_(mod.path);if(!nsd){send({__error:'cant read'});send({__done:true});return;} var m=ObjC.classes.NSMutableData.dataWithData_(nsd);var base=m.mutableBytes();var so=0;var mg=base.readU32();var FM=0xcafebabe,FC=0xbebafeca,FM4=0xcafebabf,FC4=0xbffabaca;function rb(p){return p.readU8()*16777216+p.add(1).readU8()*65536+p.add(2).readU8()*256+p.add(3).readU8();} if([FM,FC,FM4,FC4].indexOf(mg)>=0){var nf=rb(base.add(4)),i64=mg===FM4||mg===FC4,lm=mod.base.readU32();for(var k=0;k<nf;k++){var e=base.add(8+k*(i64?32:20)),o=i64?rb(e.add(8))*4294967296+rb(e.add(12)):rb(e.add(8));if(base.add(o).readU32()===lm){so=o;break;}}} var sb=base.add(so),mh=sb.readU32(),i64=mh===0xfeedfacf,hs=i64?32:28,nc=sb.add(16).readU32(),lc=sb.add(hs);var LE=0x21,LE4=0x2c;for(var c=0;c<nc;c++){var cmd=lc.readU32(),sz=lc.add(4).readU32();if(cmd===LE||cmd===LE4){var off=lc.add(8).readU32(),cs=lc.add(12).readU32(),ci=lc.add(16).readU32();if(ci!==0&&cs>0){Memory.writeByteArray(sb.add(off),mod.base.add(off).readByteArray(cs));lc.add(16).writeU32(0);}}lc=lc.add(sz);} var tl=m.length(),dp=m.mutableBytes(),s=0,ix=0;while(s<tl){var sz2=Math.min(4*1024*1024,tl-s);send({chunk:ix,size:sz2},dp.add(s).readByteArray(sz2));s+=sz2;ix++;} send({__done:true,total:tl,module:mn,path:mod.path});}catch(e){send({__error:e.message});send({__done:true});}})();"
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
        return {"success": True, "output_path": output_path, "bytes_written": sum(len(b) for b in ordered.values()), "module": result["info"].get("module")}
    except Exception as e:
        return {"success": False, "error": str(e)}



# ── ObjC Runtime ────────────────────────────────────────────────────────

@mcp.tool()
def classes(search: str = "", limit: int = 100, session_id: str = "") -> dict:
    """Search loaded Objective-C classes by substring."""
    try:
        _, session = _get_session(session_id)
        lim = int(limit)
        sj = json.dumps(search)
        r = exec_js(session, "(function(){ var ks=Object.keys(ObjC.classes); var ms=[]; var fl=" + sj + "; for(var i=0;i<ks.length;i++){ if(!fl||ks[i].indexOf(fl)!==-1){ var c=ObjC.classes[ks[i]]; ms.push({name:ks[i],methods:c&&c.$ownMethods?c.$ownMethods.length:0}); if(ms.length>=" + str(lim) + ")break; } } return JSON.stringify({matches:ms,total:ks.length}); })()", timeout=30)
        if r.get("ok"):
            data = json.loads(r["result"])
            return {"success": True, "count": len(data["matches"]), "total_classes": data["total"], "classes": data["matches"]}
        return {"success": False, "error": str(r)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def methods(class_name: str, include_inherited: bool = False, session_id: str = "") -> dict:
    """List methods of an ObjC class."""
    try:
        _, session = _get_session(session_id)
        cn = json.dumps(class_name)
        prop = "$methods" if include_inherited else "$ownMethods"
        r = exec_js(session, "(function(){ var c=ObjC.classes[" + cn + "]; if(!c)return JSON.stringify({error:'class not found'}); return JSON.stringify({methods:c." + prop + ",superclass:c.$superClass?c.$superClass.$className:null}); })()", timeout=20)
        if r.get("ok"):
            data = json.loads(r["result"])
            if "error" in data:
                return {"success": False, "error": data["error"]}
            return {"success": True, "count": len(data["methods"]), "superclass": data["superclass"], "methods": data["methods"]}
        return {"success": False, "error": str(r)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def instances(class_name: str, limit: int = 20, session_id: str = "") -> dict:
    """Find live instances of a class on the heap."""
    try:
        _, session = _get_session(session_id)
        cn = json.dumps(class_name)
        lim = int(limit)
        r = exec_js(session, "(function(){ var c=ObjC.classes[" + cn + "]; if(!c)return JSON.stringify({error:'class not found'}); var is=ObjC.chooseSync(c); var o=[]; for(var i=0;i<is.length&&i<" + str(lim) + ";i++){ try{o.push({address:is[i].handle.toString(),description:String(is[i]).substring(0,200)});}catch(e){} } return JSON.stringify({total:is.length,returned:o.length,instances:o}); })()", timeout=30)
        if r.get("ok"):
            data = json.loads(r["result"])
            if "error" in data:
                return {"success": False, "error": data["error"]}
            return {"success": True, **data}
        return {"success": False, "error": str(r)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def inspect(target: str, session_id: str = "") -> dict:
    """Inspect an instance or class: class name, description, ivars."""
    try:
        _, session = _get_session(session_id)
        tj = json.dumps(target)
        r = exec_js(session, "(function(){ var t=" + tj + "; var o; if(t.indexOf('0x')===0){o=new ObjC.Object(ptr(t));}else{o=ObjC.classes[t];if(!o)return JSON.stringify({error:'class not found'});} var i={cls:o.$className||'<class>',desc:String(o).substring(0,300),ivars:{},methods:o.$ownMethods?o.$ownMethods.length:0}; if(o.$ivars){var c=0;for(var k in o.$ivars){if(c++>=50)break;try{var v=o.$ivars[k];i.ivars[k]=v!==null&&v!==undefined?String(v).substring(0,200):'nil';}catch(e){i.ivars[k]='<err>';}}} return JSON.stringify(i); })()", timeout=20)
        if r.get("ok"):
            data = json.loads(r["result"])
            if "error" in data:
                return {"success": False, "error": data["error"]}
            return {"success": True, **data}
        return {"success": False, "error": str(r)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def call(target: str, selector: str, args: list = None, session_id: str = "") -> dict:
    """Invoke an ObjC selector on a class or instance."""
    try:
        _, session = _get_session(session_id)
        tj = json.dumps(target)
        sj = json.dumps(selector)
        aj = json.dumps(args or [])
        r = exec_js(session, "(function(){ var t=" + tj + "; var o; if(t.indexOf('0x')===0){o=new ObjC.Object(ptr(t));}else{o=ObjC.classes[t];if(!o)return JSON.stringify({error:'class not found'});} var sel=" + sj + "; var fn=o[sel]; if(!fn)return JSON.stringify({error:'sel not found'}); var ra=" + aj + "; var cv=ra.map(function(a){if(a===null||a===undefined)return null;if(typeof a==='string')return ObjC.classes.NSString.stringWithString_(a);if(typeof a==='number')return ObjC.classes.NSNumber.numberWithDouble_(a);return a;}); var res; try{res=fn.apply(o,cv);}catch(e){return JSON.stringify({error:e.message});} if(res===undefined||res===null)return JSON.stringify({result:null}); var addr=null; try{addr=res.handle?res.handle.toString():null;}catch(e){} return JSON.stringify({result:String(res).substring(0,2000),address:addr,cls:res.$className||typeof res}); })()", timeout=20)
        if r.get("ok"):
            data = json.loads(r["result"])
            if "error" in data:
                return {"success": False, "error": data["error"]}
            return {"success": True, **data}
        return {"success": False, "error": str(r)}
    except Exception as e:
        return {"success": False, "error": str(e)}



# ── Method Tracing ──────────────────────────────────────────────────────

@mcp.tool()
def trace(class_name: str, selector: str, session_id: str = "") -> dict:
    """Hook an ObjC method and buffer call/return events."""
    global _trace_counter
    try:
        sid, session = _get_session(session_id)
        _trace_counter += 1
        hook_id = "hook_" + str(_trace_counter)
        events = []
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
        cn = json.dumps(class_name)
        sel = json.dumps(selector)
        hid = json.dumps(hook_id)
        js = "(function(){ try { var cls=ObjC.classes[" + cn + "]; if(!cls){send({__trace_init:true,ok:false,error:'class not found'});return;} var m=cls[" + sel + "]||cls['- '+ " + sel + ".replace(/_/g,':')]; if(!m){send({__trace_init:true,ok:false,error:'sel not found'});return;} var ac=m.argumentTypes||[]; var n=Math.max(0,ac.length-2); Interceptor.attach(m.implementation,{onEnter:function(a){var ai=[];for(var i=0;i<n&&i<8;i++){try{ai.push(String(ObjC.Object(a[i+2])).substring(0,200));}catch(e){ai.push('<'+a[i+2]+'>');}} send({hook_id:" + hid + ",type:'call',args:ai,time:Date.now()});},onLeave:function(rv){var r;try{r=String(ObjC.Object(rv)).substring(0,200);}catch(e){r='<'+rv+'>';} send({hook_id:" + hid + ",type:'return',retval:r,time:Date.now()});}}); send({__trace_init:true,ok:true}); }catch(e){send({__trace_init:true,ok:false,error:e.message});} })();"
        script = session.create_script(js)
        script.on("message", on_msg)
        script.load()
        ack_event.wait(5)
        if not init_ack["ok"]:
            try:
                script.unload()
            except Exception:
                pass
            return {"success": False, "error": init_ack["error"] or "init timeout"}
        _traces.setdefault(sid, {})[hook_id] = {"script": script, "events": events, "class": class_name, "method": selector}
        return {"success": True, "hook_id": hook_id, "class": class_name, "method": selector}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def trace_logs(hook_id: str = "", limit: int = 100, clear: bool = False, session_id: str = "") -> dict:
    """Read buffered trace events."""
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
def traces(session_id: str = "") -> dict:
    """List active trace hooks."""
    try:
        sid, _ = _get_session(session_id)
        hooks = _traces.get(sid, {})
        return {"success": True, "hooks": [{"hook_id": hid, "class": h["class"], "method": h["method"], "buffered_events": len(h["events"])} for hid, h in hooks.items()]}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def trace_stop(hook_id: str = "", session_id: str = "") -> dict:
    """Stop a trace hook. Empty stops all."""
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


# ── WebSocket frames ────────────────────────────────────────────────────

@mcp.tool()
def ws_frames(count: int = 100, clear: bool = False, session_id: str = "") -> dict:
    """List captured WebSocket frames (NSURLSessionWebSocketTask).

    Captures send / receive payloads. Hooks are installed automatically by
    connect; iOS 13+ targets only.
    """
    try:
        sid, _ = _get_session(session_id)
        net_script = _intercept_rules.get(sid, {}).get("net_script")
        if not net_script:
            return {"success": False, "error": "Network capture not active. Re-connect."}
        frames = net_script.exports_sync.get_ws_frames(int(count))
        if clear:
            try: net_script.exports_sync.clear_ws_frames()
            except Exception: pass
        return {"success": True, "count": len(frames), "frames": frames}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── WebViews ────────────────────────────────────────────────────────────

_WEBVIEWS_JS = r"""(function(){try{
    var out = [];
    var seen = {};
    function pushView(v, kind) {
        try {
            var addr = v.handle.toString();
            if (seen[addr]) return;
            seen[addr] = true;
            var url = '';
            try { var u = v.URL ? v.URL() : null; if (u && !u.isNull()) url = String(u.absoluteString()); } catch(e) {}
            if (!url) { try { var r = v.request ? v.request() : null; if (r && !r.isNull()) url = String(r.URL().absoluteString()); } catch(e) {} }
            var title = '';
            try { var t = v.title ? v.title() : null; if (t) title = String(t); } catch(e) {}
            out.push({addr: addr, kind: kind, class: v.$className, url: url, title: title});
        } catch(e) {}
    }
    ObjC.choose(ObjC.classes.WKWebView, {
        onMatch: function(v) { pushView(v, 'WKWebView'); },
        onComplete: function() {}
    });
    if (ObjC.classes.UIWebView) {
        try {
            ObjC.choose(ObjC.classes.UIWebView, {
                onMatch: function(v) { pushView(v, 'UIWebView'); },
                onComplete: function() {}
            });
        } catch(e) {}
    }
    return JSON.stringify(out);
}catch(e){return JSON.stringify({error: e.message});}})()"""


@mcp.tool()
def webviews(session_id: str = "") -> dict:
    """List live WKWebView / UIWebView instances with their current URL and title."""
    try:
        _, session = _get_session(session_id)
        r = exec_js(session, _WEBVIEWS_JS, timeout=20)
        if not r.get("ok"):
            return {"success": False, "error": str(r)}
        try:
            data = json.loads(r["result"])
        except Exception:
            return {"success": False, "error": "parse: " + str(r["result"])[:200]}
        if isinstance(data, dict) and "error" in data:
            return {"success": False, "error": data["error"]}
        return {"success": True, "count": len(data), "webviews": data}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def webview_eval(js: str, address: str = "", session_id: str = "") -> dict:
    """Evaluate JavaScript inside a WKWebView via evaluateJavaScript:completionHandler:.

    If address is empty, the first discovered WKWebView is used. Returns the
    string representation of the JS result (or the NSError description).
    """
    try:
        _, session = _get_session(session_id)
        addr_j = json.dumps(address or "")
        js_j = json.dumps(js)
        wrapper = (
            "(function(){ try {"
            "var addr = " + addr_j + ";"
            "var target = null;"
            "if (addr) { try { target = new ObjC.Object(ptr(addr)); } catch(e) { send({__done:true, result: JSON.stringify({error:'bad address: ' + e.message})}); return; } }"
            "if (!target) {"
            "  ObjC.choose(ObjC.classes.WKWebView, { onMatch: function(v){ if (!target) target = v; }, onComplete: function(){} });"
            "}"
            "if (!target) { send({__done:true, result: JSON.stringify({error:'no WKWebView found'})}); return; }"
            "var sem = ObjC.classes.dispatch_semaphore_create(0);"
            "var out = {result: null, error: null};"
            "ObjC.schedule(ObjC.mainQueue, function(){"
            "  try {"
            "    target.evaluateJavaScript_completionHandler_(" + js_j + ", function(res, err) {"
            "      try { if (res && !res.isNull()) out.result = String(new ObjC.Object(res)); } catch(e) {}"
            "      try { if (err && !err.isNull()) out.error = String((new ObjC.Object(err)).localizedDescription()); } catch(e) {}"
            "      ObjC.classes.dispatch_semaphore_signal(sem);"
            "    });"
            "  } catch(e) { out.error = e.message; ObjC.classes.dispatch_semaphore_signal(sem); }"
            "});"
            "ObjC.classes.dispatch_semaphore_wait(sem, " + str(20 * 1_000_000_000) + ");"
            "send({__done:true, result: JSON.stringify(out)});"
            "} catch(e) { send({__done:true, result: JSON.stringify({error: e.message})}); } })();"
        )
        out = exec_js_stream(session, wrapper, timeout=30)
        if out["error"]:
            return {"success": False, "error": out["error"]}
        info = out.get("info", {})
        if not info.get("result"):
            return {"success": False, "error": "no response"}
        try:
            data = json.loads(info["result"])
        except Exception:
            return {"success": False, "error": "parse"}
        if data.get("error"):
            return {"success": False, "error": data["error"]}
        return {"success": True, "result": data.get("result")}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def jsbridge(session_id: str = "") -> dict:
    """Enumerate WKScriptMessageHandler channels and JSContext exports.

    Lists message handler names registered on any WKWebView's user content
    controller, plus the keys exported on every live JSContext. These are
    common native-bridge auth bypass surfaces.
    """
    try:
        _, session = _get_session(session_id)
        js = r"""(function(){try{
            var bridges = [];
            var contexts = [];
            ObjC.choose(ObjC.classes.WKWebView, {
                onMatch: function(v) {
                    try {
                        var cfg = v.configuration ? v.configuration() : null;
                        var ucc = cfg ? cfg.userContentController() : null;
                        if (!ucc) return;
                        var handlers = ucc.valueForKey_('_userScriptMessageHandlers') || ucc.valueForKey_('userScriptMessageHandlers');
                        var entry = {webview: v.handle.toString(), handlers: [], scripts: []};
                        if (handlers) {
                            try {
                                var keys = handlers.allKeys ? handlers.allKeys() : null;
                                if (keys) for (var i = 0; i < keys.count(); i++) entry.handlers.push(String(keys.objectAtIndex_(i)));
                            } catch(e) {}
                        }
                        try {
                            var scripts = ucc.userScripts();
                            if (scripts) {
                                for (var j = 0; j < scripts.count(); j++) {
                                    var s = scripts.objectAtIndex_(j);
                                    var src = s.source ? String(s.source()) : '';
                                    entry.scripts.push(src.substring(0, 200));
                                }
                            }
                        } catch(e) {}
                        bridges.push(entry);
                    } catch(e) {}
                },
                onComplete: function(){}
            });
            try {
                ObjC.choose(ObjC.classes.JSContext, {
                    onMatch: function(c) {
                        try {
                            var keys = [];
                            var globalObj = c.globalObject();
                            if (globalObj) {
                                var props = globalObj.toDictionary ? globalObj.toDictionary() : null;
                                if (props) {
                                    var ks = props.allKeys();
                                    for (var i = 0; i < Math.min(ks.count(), 50); i++) keys.push(String(ks.objectAtIndex_(i)));
                                }
                            }
                            contexts.push({addr: c.handle.toString(), keys: keys});
                        } catch(e) {}
                    },
                    onComplete: function(){}
                });
            } catch(e) {}
            return JSON.stringify({bridges: bridges, contexts: contexts});
        }catch(e){return JSON.stringify({error: e.message});}})()"""
        r = exec_js(session, js, timeout=20)
        if not r.get("ok"):
            return {"success": False, "error": str(r)}
        try:
            data = json.loads(r["result"])
        except Exception:
            return {"success": False, "error": "parse"}
        if "error" in data:
            return {"success": False, "error": data["error"]}
        return {"success": True, **data}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── Swift runtime ───────────────────────────────────────────────────────

@mcp.tool()
def swift_modules(session_id: str = "") -> dict:
    """List Swift modules visible to Frida (Swift.available required)."""
    try:
        _, session = _get_session(session_id)
        r = exec_js(session,
            "(function(){ if (typeof Swift === 'undefined' || !Swift.available) return JSON.stringify({error:'Swift runtime not available'}); var mods = Object.keys(Swift.modules || {}); return JSON.stringify({modules: mods}); })()",
            timeout=15)
        if not r.get("ok"):
            return {"success": False, "error": str(r)}
        data = json.loads(r["result"])
        if "error" in data:
            return {"success": False, "error": data["error"]}
        return {"success": True, **data}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def swift_classes(search: str = "", module: str = "", limit: int = 100, session_id: str = "") -> dict:
    """Search Swift classes (optionally filtered by module name)."""
    try:
        _, session = _get_session(session_id)
        sj = json.dumps(search or "")
        mj = json.dumps(module or "")
        lj = str(int(limit))
        js = (
            "(function(){ if (typeof Swift === 'undefined' || !Swift.available) return JSON.stringify({error:'Swift runtime not available'}); "
            "var s = " + sj + "; var mod = " + mj + "; var lim = " + lj + "; var out = []; "
            "var modules = Swift.modules || {}; "
            "for (var name in modules) { if (mod && name.indexOf(mod) === -1) continue; "
            "  var m = modules[name]; if (!m || !m.classes) continue; "
            "  for (var cn in m.classes) { if (s && cn.toLowerCase().indexOf(s.toLowerCase()) === -1) continue; "
            "    out.push({module: name, name: cn}); if (out.length >= lim) return JSON.stringify({classes: out, truncated: true}); } } "
            "return JSON.stringify({classes: out, truncated: false}); })()"
        )
        r = exec_js(session, js, timeout=20)
        if not r.get("ok"):
            return {"success": False, "error": str(r)}
        data = json.loads(r["result"])
        if "error" in data:
            return {"success": False, "error": data["error"]}
        return {"success": True, **data}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def swift_methods(class_name: str, module: str = "", session_id: str = "") -> dict:
    """List methods of a Swift class. Pass module for disambiguation."""
    try:
        _, session = _get_session(session_id)
        cn = json.dumps(class_name)
        mj = json.dumps(module or "")
        js = (
            "(function(){ if (typeof Swift === 'undefined' || !Swift.available) return JSON.stringify({error:'Swift runtime not available'}); "
            "var name = " + cn + "; var mod = " + mj + "; var found = null; var foundMod = null; "
            "var modules = Swift.modules || {}; "
            "for (var mn in modules) { if (mod && mn !== mod) continue; var m = modules[mn]; if (!m || !m.classes) continue; "
            "  if (m.classes[name]) { found = m.classes[name]; foundMod = mn; break; } } "
            "if (!found) return JSON.stringify({error: 'class not found'}); "
            "var methods = []; try { for (var k in found.methods || {}) methods.push(k); } catch(e) {} "
            "var fields = []; try { for (var k2 in found.fields || {}) fields.push(k2); } catch(e) {} "
            "return JSON.stringify({module: foundMod, class: name, methods: methods, fields: fields}); })()"
        )
        r = exec_js(session, js, timeout=20)
        if not r.get("ok"):
            return {"success": False, "error": str(r)}
        data = json.loads(r["result"])
        if "error" in data:
            return {"success": False, "error": data["error"]}
        return {"success": True, **data}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── File push (host -> device) ──────────────────────────────────────────

@mcp.tool()
def push(local_path: str, device_path: str, session_id: str = "") -> dict:
    """Upload a file from the host to the device sandbox.

    Streams the local file in base64 chunks and writes it on the device via
    NSData writeToFile:atomically:. Existing files at device_path are
    overwritten.
    """
    try:
        _, session = _get_session(session_id)
        if not os.path.isfile(local_path):
            return {"success": False, "error": "local file not found: " + local_path}
        size = os.path.getsize(local_path)
        with open(local_path, "rb") as f:
            raw = f.read()
        b64 = base64.b64encode(raw).decode("ascii")
        # Chunk at 256 KB of base64 to keep RPC payloads sane.
        chunk_size = 256 * 1024
        chunks = [b64[i:i + chunk_size] for i in range(0, len(b64), chunk_size)] or [""]
        # Open a long-lived script that accumulates chunks and writes once.
        path_j = json.dumps(device_path)
        js = (
            "var __chunks = [];\n"
            "rpc.exports = {\n"
            "  pushChunk: function(s) { __chunks.push(s); return __chunks.length; },\n"
            "  pushFinish: function() {\n"
            "    try {\n"
            "      var b64 = __chunks.join('');\n"
            "      var dataB64 = ObjC.classes.NSString.stringWithString_(b64);\n"
            "      var nsdata = ObjC.classes.NSData.alloc().initWithBase64EncodedString_options_(dataB64, 0);\n"
            "      if (!nsdata) return {ok:false, error:'base64 decode failed'};\n"
            "      var ok = nsdata.writeToFile_atomically_(" + path_j + ", true);\n"
            "      __chunks = [];\n"
            "      return {ok: !!ok, bytes: nsdata.length()};\n"
            "    } catch(e) { return {ok:false, error: e.message}; }\n"
            "  }\n"
            "};\n"
            "send({__ready: true});\n"
        )
        ready = threading.Event()
        def on_msg(msg, data):
            if msg.get("type") == "send" and isinstance(msg.get("payload"), dict) and msg["payload"].get("__ready"):
                ready.set()
        script = session.create_script(js)
        script.on("message", on_msg)
        script.load()
        ready.wait(5)
        try:
            for c in chunks:
                script.exports_sync.push_chunk(c)
            result = script.exports_sync.push_finish()
        finally:
            try: script.unload()
            except Exception: pass
        if not result.get("ok"):
            return {"success": False, "error": result.get("error", "write failed")}
        return {
            "success": True,
            "device_path": device_path,
            "local_size": size,
            "device_size": result.get("bytes", size),
            "chunks": len(chunks),
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── HAR export ──────────────────────────────────────────────────────────

@mcp.tool()
def har_export(output_path: str, count: int = 500, session_id: str = "") -> dict:
    """Export captured requests as a HAR 1.2 archive (host-side file)."""
    try:
        sid, _ = _get_session(session_id)
        net_script = _intercept_rules.get(sid, {}).get("net_script")
        if not net_script:
            return {"success": False, "error": "Network capture not active."}
        txns = net_script.exports_sync.get_transactions(int(count))

        def to_har_headers(d):
            return [{"name": str(k), "value": str(v)} for k, v in (d or {}).items()]

        def parse_url_query(url):
            try:
                from urllib.parse import urlsplit, parse_qsl
                q = urlsplit(url).query
                return [{"name": k, "value": v} for k, v in parse_qsl(q, keep_blank_values=True)]
            except Exception:
                return []

        entries = []
        for t in txns:
            ts_ms = t.get("timestamp", 0) or 0
            started = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ts_ms / 1000.0)) + ".000Z" if ts_ms else "1970-01-01T00:00:00.000Z"
            url = t.get("url", "")
            method = t.get("method", "GET")
            req_body = t.get("req_body", "") or ""
            resp_body = t.get("resp_body", "") or ""
            entry = {
                "startedDateTime": started,
                "time": int(t.get("duration_ms", 0) or 0),
                "request": {
                    "method": method,
                    "url": url,
                    "httpVersion": "HTTP/1.1",
                    "cookies": [],
                    "headers": to_har_headers(t.get("headers")),
                    "queryString": parse_url_query(url),
                    "headersSize": -1,
                    "bodySize": len(req_body.encode("utf-8", "ignore")),
                },
                "response": {
                    "status": int(t.get("status", -1) or -1),
                    "statusText": "",
                    "httpVersion": "HTTP/1.1",
                    "cookies": [],
                    "headers": to_har_headers(t.get("resp_headers")),
                    "content": {
                        "size": len(resp_body.encode("utf-8", "ignore")),
                        "mimeType": (t.get("resp_headers", {}) or {}).get("Content-Type", ""),
                        "text": resp_body,
                    },
                    "redirectURL": "",
                    "headersSize": -1,
                    "bodySize": len(resp_body.encode("utf-8", "ignore")),
                },
                "cache": {},
                "timings": {"send": 0, "wait": int(t.get("duration_ms", 0) or 0), "receive": 0},
            }
            if method != "GET" and req_body:
                entry["request"]["postData"] = {
                    "mimeType": (t.get("headers", {}) or {}).get("Content-Type", "application/octet-stream"),
                    "text": req_body,
                }
            entries.append(entry)
        har = {
            "log": {
                "version": "1.2",
                "creator": {"name": "frida-mcp-server", "version": "1.1.0"},
                "entries": entries,
            }
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(har, f, indent=2)
        return {"success": True, "output_path": output_path, "entries": len(entries)}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── Intercept dry-run ───────────────────────────────────────────────────

@mcp.tool()
def intercept_match(
    pattern: str = "", regex: str = "", method_filter: str = "",
    count: int = 200, session_id: str = "",
) -> dict:
    """Test which captured requests an intercept rule would match without
    installing it. Useful for verifying patterns before going live."""
    try:
        sid, _ = _get_session(session_id)
        net_script = _intercept_rules.get(sid, {}).get("net_script")
        if not net_script:
            return {"success": False, "error": "Network capture not active."}
        txns = net_script.exports_sync.get_transactions(int(count))
        rx = None
        if regex:
            try:
                rx = re.compile(regex)
            except re.error as e:
                return {"success": False, "error": "bad regex: " + str(e)}
        mf = (method_filter or "").upper()
        matches = []
        for i, t in enumerate(txns):
            url = t.get("url", "") or ""
            method = (t.get("method", "") or "").upper()
            if mf and method != mf:
                continue
            if rx is not None:
                if not rx.search(url):
                    continue
            elif pattern:
                if pattern not in url:
                    continue
            else:
                continue
            matches.append({"index": i, "method": method, "url": url, "status": t.get("status", -1)})
        return {
            "success": True,
            "pattern": pattern, "regex": regex, "method_filter": method_filter,
            "count": len(matches),
            "matches": matches,
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Frida MCP Server v2")
    parser.add_argument("--transport", choices=["stdio", "sse"], default="stdio",
                        help="Transport: stdio (local) or sse (remote via HTTP)")
    parser.add_argument("--host", default="0.0.0.0", help="SSE host")
    parser.add_argument("--port", type=int, default=8099, help="SSE port")
    args = parser.parse_args()

    if args.transport == "sse":
        settings = getattr(mcp, "settings", None)
        if settings is not None:
            settings.host = args.host
            settings.port = args.port
        log.info("Frida MCP Server running on http://%s:%d/sse", args.host, args.port)
        mcp.run(transport="sse")
    else:
        log.info("Frida MCP Server running on stdio")
        mcp.run()


if __name__ == "__main__":
    main()

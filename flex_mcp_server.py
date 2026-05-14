#!/usr/bin/env python3
"""
FLEX MCP Server - Control FLEX debugger on iOS devices via Frida.
Works with FLEXing tweak installed on jailbroken device.
Usage: python flex_mcp_server.py
"""

import sys, json, time, threading, frida
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("FLEX iOS Debugger")
_sessions = {}

def get_usb_device():
    try:
        return frida.get_usb_device(timeout=5)
    except Exception as e:
        raise RuntimeError(f"No USB device found: {e}")

def get_or_spawn(bundle_id="com.wobo.mobile"):
    """Try attach, spawn if not found."""
    device = get_usb_device()
    try:
        session = device.attach(bundle_id)
        return session, "attach"
    except:
        pid = device.spawn([bundle_id])
        session = device.attach(pid)
        device.resume(pid)
        time.sleep(3)
        return session, "spawn"

def exec_js(session, js_code, timeout=15):
    """Execute JavaScript in the app via Frida and return result."""
    messages = []
    event = threading.Event()
    def on_msg(msg, data):
        if msg["type"] == "send":
            messages.append(msg["payload"])
        elif msg["type"] == "error":
            messages.append({"error": msg.get("description", str(msg))})
        event.set()
    wrapped = f"""
    (function() {{
        try {{
            var result = {js_code};
            send(JSON.stringify({{ok: true, result: result !== undefined ? String(result) : 'undefined'}}));
        }} catch(e) {{
            send(JSON.stringify({{ok: false, error: e.message, stack: e.stack}}));
        }}
    }})();
    """
    s = session.create_script(wrapped)
    s.on("message", on_msg)
    s.load()
    event.wait(timeout)
    s.unload()
    if messages:
        try: return json.loads(messages[-1])
        except: return {"ok": False, "error": f"parse: {messages[-1]}"}
    return {"ok": False, "error": "timeout"}

def safe_str(s, maxlen=500):
    """Safely convert to string, handling unicode."""
    if not s:
        return ""
    try:
        s = str(s)
        if len(s) > maxlen:
            s = s[:maxlen] + "..."
        return s
    except:
        return "<binary data>"

# ============================================================
# MCP TOOLS
# ============================================================

@mcp.tool()
def flex_connect(bundle_id: str = "com.wobo.mobile") -> dict:
    """Connect to the target iOS app via Frida.
    
    Args:
        bundle_id: Bundle identifier (default: com.wobo.mobile)
    """
    try:
        session, method = get_or_spawn(bundle_id)
        sid = f"flex_{bundle_id}_{int(time.time())}"
        _sessions[sid] = session
        
        # Check if FLEX is available
        r = exec_js(session, "!!ObjC.classes.FLEXManager")
        flex_ok = r.get("result") == "true"
        
        # Check FLEXNetworkRecorder
        r2 = exec_js(session, "!!ObjC.classes.FLEXNetworkRecorder")
        recorder_ok = r2.get("result") == "true"
        
        # Enable network debug if FLEX loaded
        if flex_ok:
            exec_js(session, "ObjC.classes.FLEXManager.sharedManager().setNetworkDebuggingEnabled_(true)")
        
        return {
            "success": True,
            "session_id": sid,
            "method": method,
            "flex_loaded": flex_ok,
            "recorder_available": recorder_ok,
            "device": get_usb_device().name,
            "app": bundle_id
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_show(session_id: str) -> dict:
    """Show FLEX explorer toolbar on the device (async dispatch).
    
    Args:
        session_id: Session ID from flex_connect
    """
    try:
        if session_id not in _sessions:
            return {"success": False, "error": "Session not found"}
        r = exec_js(_sessions[session_id],
            "ObjC.classes.FLEXManager.sharedManager().performSelectorOnMainThread_withObject_waitUntilDone_("
            "ObjC.selector('showExplorer'), null, false); 'dispatched'")
        return {"success": True, "result": r}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_hide(session_id: str) -> dict:
    """Hide FLEX explorer toolbar.
    
    Args:
        session_id: Session ID
    """
    try:
        r = exec_js(_sessions[session_id],
            "ObjC.classes.FLEXManager.sharedManager().performSelectorOnMainThread_withObject_waitUntilDone_("
            "ObjC.selector('hideExplorer'), null, false); 'dispatched'")
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_network(enable: bool = True, session_id: str = "") -> dict:
    """Enable or disable FLEX network debugging.
    
    Args:
        enable: True to enable, False to disable
        session_id: Optional session ID
    """
    sessions_to_use = [sid for sid in _sessions] if not session_id else [session_id]
    results = []
    for sid in sessions_to_use:
        try:
            val = "true" if enable else "false"
            r = exec_js(_sessions[sid],
                f"ObjC.classes.FLEXManager.sharedManager().setNetworkDebuggingEnabled_({val}); "
                f"String(ObjC.classes.FLEXManager.sharedManager().isNetworkDebuggingEnabled())")
            results.append({"session": sid, "enabled": r.get("result")})
        except Exception as e:
            results.append({"session": sid, "error": str(e)})
    return {"success": True, "results": results}


@mcp.tool()
def flex_requests(count: int = 50, session_id: str = "") -> dict:
    """Get captured network requests from FLEX.
    
    Args:
        count: Max transactions to return (default: 50)
        session_id: Optional session ID (uses first if empty)
    """
    try:
        sid = session_id or next(iter(_sessions))
        session = _sessions[sid]
        
        r = exec_js(session, f"""
        (function(){{
            var recorder = ObjC.classes.FLEXNetworkRecorder.defaultRecorder();
            var txns = recorder.HTTPTransactions();
            var result = [];
            for (var i = 0; i < txns.count() && i < {count}; i++) {{
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
def flex_request_body(index: int, session_id: str = "") -> dict:
    """Get the cached response body of a specific transaction.
    
    Args:
        index: Transaction index from flex_requests
        session_id: Optional session ID
    """
    try:
        sid = session_id or next(iter(_sessions))
        session = _sessions[sid]
        
        r = exec_js(session, f"""
        (function(){{
            var recorder = ObjC.classes.FLEXNetworkRecorder.defaultRecorder();
            var txns = recorder.HTTPTransactions();
            if ({index} >= txns.count()) return JSON.stringify({{error: 'Index out of range'}});
            var txn = txns.objectAtIndex_({index});
            var req = txn.request();
            var url = req ? String(req.URL().absoluteString()) : '?';
            var body = recorder.cachedResponseBodyForTransaction_(txn);
            var bodyStr = '';
            if (body) {{
                try {{
                    var str = ObjC.classes.NSString.alloc().initWithData_encoding_(body, 4);
                    if (str) bodyStr = str.toString();
                }} catch(e) {{ bodyStr = '<binary ' + body.length() + ' bytes>'; }}
            }}
            return JSON.stringify({{url: url, body: bodyStr}});
        }})()
        """)
        if r.get("ok"):
            data = json.loads(r["result"])
            return {"success": True, "url": data["url"], "body": safe_str(data.get("body", ""), 10000)}
        return {"success": False, "error": str(r)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_search_requests(keyword: str, session_id: str = "") -> dict:
    """Search captured requests for a keyword in URL or response body.
    
    Args:
        keyword: Search term (e.g. 'credit', 'balance', 'subscription')
        session_id: Optional session ID
    """
    try:
        sid = session_id or next(iter(_sessions))
        session = _sessions[sid]
        
        # First get all transaction URLs
        r = exec_js(session, f"""
        (function(){{
            var recorder = ObjC.classes.FLEXNetworkRecorder.defaultRecorder();
            var txns = recorder.HTTPTransactions();
            var matches = [];
            var kw = '{keyword}'.toLowerCase();
            for (var i = 0; i < txns.count(); i++) {{
                try {{
                    var t = txns.objectAtIndex_(i);
                    var req = t.request();
                    var url = String(req.URL().absoluteString()).toLowerCase();
                    if (url.indexOf(kw) !== -1) {{
                        matches.push({{
                            index: i,
                            url: String(req.URL().absoluteString()),
                            method: String(req.HTTPMethod()),
                            matchType: 'url'
                        }});
                    }}
                }} catch(e) {{}}
            }}
            return JSON.stringify(matches);
        }})()
        """)
        if r.get("ok"):
            matches = json.loads(r["result"])
            return {"success": True, "count": len(matches), "matches": matches}
        return {"success": False, "error": str(r)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_userdefaults(search: str = "", session_id: str = "") -> dict:
    """Browse NSUserDefaults.
    
    Args:
        search: Optional filter key
        session_id: Optional session ID
    """
    try:
        sid = session_id or next(iter(_sessions))
        session = _sessions[sid]
        search_term = json.dumps(search)
        
        r = exec_js(session, f"""
        (function(){{
            var ud = ObjC.classes.NSUserDefaults.standardUserDefaults();
            var dict = ud.dictionaryRepresentation();
            var keys = dict.allKeys();
            var entries = [];
            for (var i = 0; i < keys.count(); i++) {{
                try {{
                    var key = String(keys.objectAtIndex_(i));
                    var filter = {search_term};
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
            entries = json.loads(r["result"])
            return {"success": True, "count": len(entries), "entries": entries}
        return {"success": False, "error": str(r)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_set_userdefault(key: str, value: str, session_id: str = "") -> dict:
    """Set a value in NSUserDefaults.
    
    Args:
        key: UserDefaults key
        value: Value to set
        session_id: Optional session ID
    """
    try:
        sid = session_id or next(iter(_sessions))
        session = _sessions[sid]
        k = json.dumps(key)
        v = json.dumps(value)
        r = exec_js(session, f"""
        (function(){{
            var ud = ObjC.classes.NSUserDefaults.standardUserDefaults();
            ud.setObject_forKey_(ObjC.classes.NSString.stringWithString_({v}), {k});
            ud.synchronize();
            return 'ok';
        }})()
        """)
        return {"success": True, "result": r}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_execute(js_code: str, session_id: str = "") -> dict:
    """Execute arbitrary JavaScript via Frida in the app.
    
    Args:
        js_code: JavaScript code to execute
        session_id: Optional session ID
    """
    try:
        sid = session_id or next(iter(_sessions))
        session = _sessions[sid]
        r = exec_js(session, js_code, timeout=30)
        return {"success": r.get("ok", False), "result": r}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_list_classes(search: str = "", session_id: str = "") -> dict:
    """List Objective-C classes matching a search.
    
    Args:
        search: Optional class name filter
        session_id: Optional session ID
    """
    try:
        sid = session_id or next(iter(_sessions))
        session = _sessions[sid]
        s = json.dumps(search)
        js_code = (
            "(function(){"
            "var classes = Object.keys(ObjC.classes);"
            "var matches = [];"
            "var filter = " + s + ";"
            "for (var i = 0; i < classes.length; i++) {"
            "if (!filter || classes[i].indexOf(filter) !== -1) {"
            "var cls = ObjC.classes[classes[i]];"
            "var m = cls && cls.$ownMethods ? cls.$ownMethods.length : 0;"
            "matches.push({name: classes[i], methods: m});"
            "}"
            "if (matches.length >= 100) break;"
            "}"
            "return JSON.stringify(matches);"
            "})()"
        )
        r = exec_js(session, js_code, timeout=30)
        if r.get("ok"):
            matches = json.loads(r["result"])
            return {"success": True, "count": len(matches), "classes": matches}
        return {"success": False, "error": str(r)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_monitor(interval: int = 2, session_id: str = "") -> dict:
    """Start monitoring for new network transactions.
    Returns new transactions discovered since last check.
    
    Args:
        interval: Poll interval in seconds (default: 2)
        session_id: Optional session ID
    """
    try:
        sid = session_id or next(iter(_sessions))
        session = _sessions[sid]
        
        # Get current count
        r = exec_js(session, "String(ObjC.classes.FLEXNetworkRecorder.defaultRecorder().HTTPTransactions().count())")
        current_count = int(r.get("result", "0"))
        
        # Store in session state
        if not hasattr(_sessions[sid], '_last_count'):
            _sessions[sid]._last_count = current_count
            return {"success": True, "new_transactions": 0, "total": current_count, "message": f"Monitoring started at {current_count} transactions. Poll every {interval}s."}
        
        old_count = _sessions[sid]._last_count
        new_count = current_count
        
        if new_count > old_count:
            # Get new transactions
            r2 = exec_js(session, f"""
            (function(){{
                var recorder = ObjC.classes.FLEXNetworkRecorder.defaultRecorder();
                var txns = recorder.HTTPTransactions();
                var result = [];
                for (var i = {old_count}; i < txns.count(); i++) {{
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
            _sessions[sid]._last_count = new_count
            return {"success": True, "new_transactions": len(new_txns), "total": new_count, "transactions": new_txns}
        else:
            _sessions[sid]._last_count = new_count
            return {"success": True, "new_transactions": 0, "total": new_count}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_disconnect(session_id: str = "") -> dict:
    """Disconnect from the app.
    
    Args:
        session_id: Optional session ID (empty = disconnect all)
    """
    try:
        if session_id:
            if session_id in _sessions:
                _sessions[session_id].detach()
                del _sessions[session_id]
            return {"success": True, "disconnected": [session_id]}
        else:
            ids = list(_sessions.keys())
            for sid in ids:
                _sessions[sid].detach()
            _sessions.clear()
            return {"success": True, "disconnected": ids}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def flex_spawn(bundle_id: str = "com.wobo.mobile") -> dict:
    """Spawn (force restart) the app fresh.
    
    Args:
        bundle_id: Bundle identifier
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
def flex_find_credits(session_id: str = "") -> dict:
    """Search ALL captured requests for credit-related endpoints and data.
    
    Args:
        session_id: Optional session ID
    """
    try:
        sid = session_id or next(iter(_sessions))
        session = _sessions[sid]
        
        # Search URLs for credit-related keywords
        keywords = ['credit', 'balance', 'coin', 'wallet', 'payment', 'purchase', 
                    'token', 'premium', 'subscription', 'entitle', 'stripe', 'billing',
                    'invoice', 'transaction', 'payout', 'fund', 'cash', 'money']
        
        r = exec_js(session, f"""
        (function(){{
            var recorder = ObjC.classes.FLEXNetworkRecorder.defaultRecorder();
            var txns = recorder.HTTPTransactions();
            var keywords = {json.dumps(keywords)};
            var results = [];
            for (var i = 0; i < txns.count(); i++) {{
                try {{
                    var t = txns.objectAtIndex_(i);
                    var req = t.request();
                    var url = String(req.URL().absoluteString()).toLowerCase();
                    for (var k = 0; k < keywords.length; k++) {{
                        if (url.indexOf(keywords[k]) !== -1) {{
                            results.push({{
                                index: i,
                                method: String(req.HTTPMethod()),
                                url: String(req.URL().absoluteString()),
                                matched: keywords[k]
                            }});
                            break;
                        }}
                    }}
                }} catch(e) {{}}
            }}
            return JSON.stringify(results);
        }})()
        """)
        
        url_matches = json.loads(r["result"]) if r.get("ok") else []
        
        # Also search response bodies for "credit" in all transactions
        r2 = exec_js(session, """
        (function(){
            var recorder = ObjC.classes.FLEXNetworkRecorder.defaultRecorder();
            var txns = recorder.HTTPTransactions();
            var results = [];
            for (var i = 0; i < txns.count(); i++) {
                try {
                    var t = txns.objectAtIndex_(i);
                    var body = recorder.cachedResponseBodyForTransaction_(t);
                    if (body) {
                        try {
                            var str = String(ObjC.classes.NSString.alloc().initWithData_encoding_(body, 4));
                            var lower = str.toLowerCase();
                            if (lower.indexOf('credit') !== -1 || lower.indexOf('balance') !== -1 || lower.indexOf('subscription') !== -1) {
                                var req = t.request();
                                results.push({
                                    index: i,
                                    url: String(req.URL().absoluteString()),
                                    snippet: str.substring(0, 100).replace(/\\n/g, ' ')
                                });
                            }
                        } catch(e) {}
                    }
                } catch(e) {}
            }
            return JSON.stringify(results);
        })()
        """)
        
        body_matches = json.loads(r2["result"]) if r2.get("ok") else []
        
        return {
            "success": True,
            "url_matches": url_matches,
            "body_matches": body_matches,
            "total_url_matches": len(url_matches),
            "total_body_matches": len(body_matches)
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


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
        print("Connect via SSH tunnel or directly if on same network")
        mcp.run(transport="sse", host=args.host, port=args.port)
    else:
        mcp.run()

if __name__ == "__main__":
    main()

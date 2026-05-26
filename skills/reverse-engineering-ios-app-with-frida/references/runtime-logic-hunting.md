# Runtime Logic & Boolean-Flip Hunting

How to find client-side trust decisions in an iOS app and test whether flipping
them at runtime grants unauthorized capability. This is the "interesting stuff"
the network/storage phases miss: auth gates, feature gates, jailbreak/integrity
checks, license validation — anything the app decides locally that the server
should be deciding.

All `mcp__frida__*`. Target is always supplied; never hardcode an app.

## 1. Find candidate gate methods

```
classes(search="App")                 # app-owned namespaces (skip UIKit/Foundation)
methods(class_name="LoginManager")     # list selectors
swift_classes(search="App"); swift_methods(class_name="...")   # Swift side
```

Flag selectors whose **name and return type** smell like a local decision —
typically `BOOL`-returning:

| Pattern | Examples |
|---------|----------|
| `is*` | `isAuthenticated`, `isPremium`, `isPro`, `isSubscribed`, `isJailbroken`, `isUnlocked`, `isValid`, `isLoggedIn` |
| `has*` | `hasValidLicense`, `hasAccess`, `hasActiveSubscription` |
| `should* / can* / may*` | `shouldAllowAccess`, `canPurchase`, `canBypass` |
| `verify* / validate* / check*` | `verifyReceipt`, `validateToken`, `checkEntitlement` |
| `*enabled / *allowed / *granted` | `featureEnabled`, `accessAllowed` |

## 2. Confirm it fires on the real flow (human-in-the-loop)

The MCP has **no UI control** — it cannot tap buttons. To see which gate governs a
flow, hook first, then have the human drive the app:

```
trace(class_name="LoginManager", method="isAuthenticated")
# -> tell the user EXACTLY what to do:
#    "In the app, tap 'Log In' and submit. Tell me when done."
# wait for confirmation, then:
trace_logs(<hook_id>)                  # did it fire? args? return value?
```

Only the methods that actually fire during the target action are worth flipping.

## 3. Flip the return and re-test

Force the decision with `exec` (raw Frida JS). ObjC `BOOL` lives in the low byte
of the return register; `retval.replace(ptr(1))` = YES, `ptr(0)` = NO:

```js
// exec(js_code=...)
var cls = ObjC.classes.LoginManager;
Interceptor.attach(cls['- isAuthenticated'].implementation, {
  onLeave: function (retval) { retval.replace(ptr(1)); }   // force YES
});
console.log('[+] isAuthenticated pinned to YES');
```

Force a value for **every instance** of a selector, or target one live object via
`instances` + `inspect` + `call` when only a specific object should be flipped:

```
instances(class_name="LoginManager")   # heap-walk live objects
inspect(target=<ptr>)                   # read ivars (tokens, flags)
call(target=<ptr>, selector="isAuthenticated")   # invoke directly, see real value
```

Then **re-drive the flow with the human** (step 2 protocol) and observe: does the
gated screen open? does the premium feature unlock? does the jailbreak warning
disappear? That observed behavior change is the finding — or its absence proves
the check is server-enforced (good).

### Swift note
Swift is name-mangled and often not in the ObjC runtime. Prefer hooking the ObjC
bridge method if one exists. Otherwise locate the symbol via `swift_methods` /
`modules` + `Module.enumerateExports`, then `Interceptor.attach` by address in
`exec`. Swift `Bool` returns in the low byte of x0 the same way.

## 4. Classify the result

- **Bypassable + capability gained** → client-side authorization flaw. Map to
  MASVS **AUTH** / **RESILIENCE**. Severity scales with what unlocked (paid
  feature = medium; account/data access = high/critical).
- **Bypassable but server re-checks** → defense-in-depth gap only; note it, low/info.
- **Not bypassable** → check is server-side; report as a positive control in coverage.

## Tier
Tracing and flipping alter app behavior — treat `trace`, `exec`, `call`, and any
return-flip as **BYPASS tier**: confirm with the user before running unless in
`yolo` mode.

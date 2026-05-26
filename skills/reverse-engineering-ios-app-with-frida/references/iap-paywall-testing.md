# IAP / Paywall & Entitlement Testing

How to test whether an iOS app's paid features are actually enforced, or just
gated client-side. The security question (MASVS-AUTH / server-side trust): **does
the server validate the purchase, or does the app decide locally?** If a local
flip unlocks the feature and the backend still serves paid data, that's the
finding — weak/absent server-side receipt validation (CWE-284 / improper access
control on a monetized resource).

Authorized engagements only. All techniques here are **ACTIVE / BYPASS tier** —
confirm before running unless in `yolo`. All `mcp__frida__*`; target is supplied,
never hardcoded.

## Order of attack (cheapest first)

### 1. Local entitlement state — plist / NSUserDefaults / Keychain
Many apps cache "is purchased" in writable storage. Find it, flip it.

```
defaults(search="premium")          # also: pro, purchase, subscri, entitle, unlock, credit
files(path="$HOME/Library/Preferences")    # <bundle>.plist
read(path="<...>.plist")             # inspect cached flags
keychain                             # purchase tokens / entitlement blobs
```
Flip and re-check the gated feature (drive the UI yourself — MCP can't tap):
```
defaults_set(key="isPremium", value="true")
defaults_set(key="purchasedProducts", value="[\"com.app.pro\"]")
```
If the feature unlocks and stays unlocked across a relaunch with no server
re-check → local-only entitlement (finding).

### 2. Boolean gate flip (the in-code decision)
Use `gates` to find the app's own purchase/entitlement decision methods — by type
encoding, not guessed names — then flip and verify.
```
gates(app_only=True)                 # look for isPremium/hasActiveSubscription/canAccess* and siblings sharing a backing_ivar
trace(class_name="<EntitlementMgr>", method="isPremium")   # confirm it fires on the paywall
exec(js_code="Interceptor.attach(ObjC.classes.<Cls>['- isPremium'].implementation,{onLeave:function(r){r.replace(ptr(1));}});")
```
See [runtime-logic-hunting.md](runtime-logic-hunting.md) for the full flip+verify loop.

### 3. StoreKit transaction state
Apps that trust `SKPaymentTransaction` state without server verification can be
fooled by forcing the state. `SKPaymentTransactionStatePurchased = 1`.
```
classes(search="Payment"); methods(class_name="SKPaymentTransaction")
exec(js_code="Interceptor.attach(ObjC.classes.SKPaymentTransaction['- transactionState'].implementation,{onLeave:function(r){r.replace(ptr(1));}});")
```
Also inspect the app's `-paymentQueue:updatedTransactions:` observer and how it
records the unlock. StoreKit 2 (`Transaction.currentEntitlements`, Swift) is
async/JWS-signed — hook the app's handler that consumes it, not StoreKit itself.

### 4. On-device receipt validation
If the app parses `Bundle.main.appStoreReceiptURL` locally (libs: TPInAppReceipt,
RMStore, custom ASN.1) instead of calling Apple's server, the validation routine
is a client-side check you can defeat:
```
strings(local=True, search="appStoreReceipt")   # and: receipt, verifyReceipt, PKCS7
gates(search="Receipt")                          # find the verify method
exec(...)                                         # force the verify method's BOOL to YES
```
A crafted/tampered receipt or a forced-true validator that unlocks features proves
the app does not do server-side validation via the App Store Server API.

### 5. Third-party entitlement SDKs (RevenueCat, Adapty, Glassfy)
Common pattern: SDK caches entitlements locally and the app reads `isActive`.
```
modules(search="RevenueCat")         # or Purchases / Adapty / Glassfy
defaults(search="revenuecat")        # cached CustomerInfo JSON in NSUserDefaults
files(path="$HOME/Library/Caches")   # cached entitlement files
classes(search="Entitlement"); methods(class_name="<RCEntitlementInfo-like>")
exec(...)                            # force the entitlement "isActive"/"active" accessor true
```
Editing the cached entitlement JSON (`defaults_set` / writing the cache file) and
relaunching tests whether the SDK and backend re-verify against the store.

### 6. Network: intercept the entitlement response
If the app asks a server "is this user premium?" and trusts the answer, rewrite it.
```
requests; search(keyword="premium")           # find the entitlement/validation call
intercept_match(pattern="*/entitlements*", set_body="{\"premium\":true,\"active\":[\"pro\"]}")
replay(index=N, ...)                            # or replay a purchase-confirm with another account/id (IDOR on receipts)
```
Also test: replay a purchase-validation request with a **different** user's id /
receipt → does the server bind the purchase to the account? (BOLA on entitlements.)

## Verdict

| Observation | Meaning |
|---|---|
| Local flip unlocks feature, server still serves paid data | **Finding** — no/weak server-side enforcement (MASVS-AUTH, CWE-284) |
| Local flip unlocks UI but server returns 402/empty for paid data | Defense-in-depth gap only; low/info |
| Flip has no effect; server re-checks every paid request | Properly enforced — note as a positive control |

Document: exact flip (key/selector/endpoint), evidence the paid resource was
served, reproduction calls, and the fix (validate via App Store Server API /
RevenueCat server-side, bind entitlement to the authenticated account).

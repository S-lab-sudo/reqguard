# Release Notes - ReqGuard v1.0.1
**Release Date:** 2025-12-25
**Priority:** 🚨 CRITICAL SECURITY UPDATE

## Summary
This release addresses critical vulnerabilities identified by the Architecture Review Board, specifically targeting bypasses in the filesystem and network shields. All users are strongly advised to upgrade immediately.

## 🛡️ Critical Security Fixes

### 1. FileSystem Shield Hardening (`fs.promises`)
- **Vulnerability:** Previous versions only intercepted synchronous `fs` methods (e.g., `readFileSync`) and callback-based methods. Attackers could bypass restrictions using `fs.promises.readFile`.
- **Fix:** ReqGuard now monkey-patches `fs.promises.readFile`, `fs.promises.open`, and `fs.promises.opendir`.
- **Impact:** Complete blocking of sensitive file access regardless of the API used (Sync, Callback, or Promise).

### 2. Network Shield Evasion Refactor (`IPv6` & `fetch`)
- **Vulnerability:**
    - Attackers could bypass blocked IPs using IPv4-mapped IPv6 addresses (e.g., `::ffff:169.254.169.254`).
    - The `global.fetch` API (Node 18+) was not intercepted, allowing network requests to bypass `net.Socket` patches.
- **Fix:**
    - Added detection for IPv6 mapped addresses and Link-Local (`fe80::`) ranges.
    - Implemented a shim for `global.fetch` to validate URLs against the blocklist before execution.

## ✅ Verification
This release has passed a hardened verification suite (22 tests) covering all new attack vectors.

## Credits
Special thanks to the **Architecture Review Board** for the comprehensive security audit and recommendations.

# 🛡️ ReqGuard

**Runtime Dependency Guard for Node.js**

ReqGuard is a zero-dependency runtime security layer that intercepts Node.js module loading to block malicious or unwanted dependencies before they execute.

[![npm version](https://img.shields.io/npm/v/reqguard.svg)](https://www.npmjs.com/package/reqguard)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## ✨ Features

- **🚀 Zero Runtime Dependencies** — The core uses only Node.js built-ins
- **🔒 CJS Interception** — Hooks into `Module.prototype.require` to validate every module load
- **📋 Configurable Policies** — Allow/Block/Warn lists with wildcard pattern support
- **🛑 Restricted Built-ins** — Block dangerous modules like `child_process` or `vm`
- **⚡ Lightweight** — Minimal performance overhead with in-memory checks
- **🧪 Well Tested** — Comprehensive test suite with 30+ passing tests

---

## 📦 Installation

```bash
npm install reqguard
```

---

## 🚀 Quick Start

Add ReqGuard at the very top of your application's entry point:

```javascript
const reqguard = require('reqguard');

// Initialize with your security policy
reqguard.init({
  mode: 'enforce',  // 'enforce' | 'warn' | 'audit'
  packages: {
    block: [
      { name: 'malicious-pkg', reason: 'Known malware' },
      { name: 'event-stream', reason: 'Compromised package' },
    ],
    allow: [
      { name: 'express' },
      { name: 'lodash' },
    ],
    warn: [
      { name: 'deprecated-pkg', reason: 'Consider migrating' },
    ],
  },
  builtins: {
    allow: true,
    restricted: ['child_process', 'vm'],  // Block dangerous built-ins
  },
});

// Now your app is protected!
const express = require('express');  // ✅ Allowed
const cp = require('child_process'); // ❌ Throws: [reqguard] Blocked
```

---

## 📖 Configuration

### Policy Schema

```typescript
interface ReqGuardPolicy {
  // Behavior mode
  mode: 'enforce' | 'warn' | 'audit';
  
  // Package rules
  packages: {
    allow: PackageRule[];   // Always allowed
    block: PackageRule[];   // Always blocked (throws in enforce mode)
    warn: PackageRule[];    // Allowed with warning log
  };
  
  // Built-in module handling
  builtins: {
    allow: boolean;         // Allow all built-ins (default: true)
    restricted: string[];   // Specific built-ins to block
  };
  
  // Relative imports (./foo, ../bar)
  relativeImports: {
    analyze: boolean;       // Default: false (always allow)
  };
  
  // Logging
  logging: {
    level: 'silent' | 'error' | 'warn' | 'info' | 'debug';
  };
}

interface PackageRule {
  name: string;      // Package name or pattern (e.g., 'lodash', '@scope/*')
  version?: string;  // Semver range (not enforced in v0.1)
  reason?: string;   // Human-readable reason
}
```

### Pattern Matching

ReqGuard supports wildcard patterns:

| Pattern | Matches |
|---------|---------|
| `lodash` | Exact match only |
| `lodash*` | `lodash`, `lodash-es`, `lodash.get` |
| `@scope/*` | `@scope/foo`, `@scope/bar` |
| `node:*` | `node:fs`, `node:path`, etc. |

---

## 🔧 API

### `init(config)`

Initialize ReqGuard with a policy configuration.

```javascript
reqguard.init({
  mode: 'enforce',
  packages: { block: [{ name: 'bad-pkg' }] }
});
```

### `shutdown()`

Disable ReqGuard and restore original `require()` behavior.

```javascript
reqguard.shutdown();
```

### `isActive()`

Check if ReqGuard is currently active.

```javascript
if (reqguard.isActive()) {
  console.log('Protected!');
}
```

### `getEngine()`

Get the PolicyEngine instance for advanced use cases.

```javascript
const engine = reqguard.getEngine();
const decision = engine.evaluate('some-pkg', '/path/to/module');
console.log(decision.action); // 'allow' | 'block' | 'warn' | 'analyze'
```

---

## 🎯 Use Cases

### 1. Block Known Malicious Packages

```javascript
reqguard.init({
  packages: {
    block: [
      { name: 'event-stream', reason: 'Cryptocurrency stealer' },
      { name: 'flatmap-stream', reason: 'Malicious payload' },
      { name: 'ua-parser-js', version: '0.7.29', reason: 'Compromised version' },
    ]
  }
});
```

### 2. Restrict Shell Access

```javascript
reqguard.init({
  builtins: {
    allow: true,
    restricted: ['child_process', 'cluster', 'worker_threads']
  }
});
```

### 3. Allowlist-Only Mode

```javascript
reqguard.init({
  builtins: { allow: false, restricted: [] },
  packages: {
    allow: [
      { name: 'express' },
      { name: 'fs' },  // Explicitly allow fs
    ],
    block: [],
    warn: []
  }
});
// Only express and fs can be loaded, everything else is blocked
```

---

## ⚠️ Caveats & Limitations

> [!WARNING]
> **ESM Imports Not Yet Supported**  
> ReqGuard v0.1 only intercepts CommonJS `require()` calls. ES Module `import` statements are **not intercepted**. If your project uses ESM, consider using CJS for your entry point or wait for v0.2.

> [!NOTE]
> **Heuristic Scanning Coming in v0.2**  
> The current version uses policy-based blocking only. Dynamic heuristic analysis (detecting suspicious patterns in module source code) is planned for v0.2.

### Current Limitations

| Feature | Status |
|---------|--------|
| CJS `require()` interception | ✅ Supported |
| ESM `import` interception | ❌ Planned for v0.2 |
| Allow/Block/Warn lists | ✅ Supported |
| Wildcard patterns | ✅ Supported |
| Heuristic code scanning | ❌ Planned for v0.2 |
| Vulnerability DB lookup | ❌ Planned for v0.2 |
| Lockfile integrity checks | ❌ Planned for v0.3 |

---

## 🧪 Development

```bash
# Install dependencies
npm install

# Run tests
npm test

# Run demo
npx ts-node demo.ts

# Build
npm run build
```

---

## 📄 License

MIT © 2024

---

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines before submitting a PR.

---

## 🔗 Related Projects

- [socket.dev](https://socket.dev) — Supply chain security platform
- [snyk](https://snyk.io) — Vulnerability scanning
- [npm audit](https://docs.npmjs.com/cli/v8/commands/npm-audit) — Built-in npm security

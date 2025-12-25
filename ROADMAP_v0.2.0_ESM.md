# v0.2.0 Roadmap: ESM Loader Support

## Priority: High

## Background

ReqGuard v0.1.0 only intercepts CommonJS `require()` calls. Modern Node.js applications increasingly use ES Modules (`import` statements), which bypass the current protection entirely.

## Objective

Implement ESM interception using the Node.js Loaders API to provide full coverage across both module systems.

## Technical Approach

### Option 1: Custom Loader (Recommended)

Create an ESM loader that users register via CLI:

```bash
node --loader reqguard/loader app.js
```

**Implementation:**
```javascript
// src/core/esm-loader.mjs
export async function resolve(specifier, context, nextResolve) {
  const decision = await reqguard.analyzeESM(specifier);
  if (decision.blocked) {
    throw new Error(`[reqguard] Blocked ESM: ${specifier}`);
  }
  return nextResolve(specifier, context);
}

export async function load(url, context, nextLoad) {
  // Optional: Analyze source code
  return nextLoad(url, context);
}
```

### Option 2: Register API (Node.js 20.6+)

Use `module.register()` for programmatic loader registration:

```javascript
import { register } from 'node:module';
register('./esm-loader.mjs', import.meta.url);
```

**Limitation:** Requires Node.js 20.6+ and only affects subsequent imports.

## Tasks

- [ ] Research current Node.js Loaders API stability
- [ ] Implement `src/core/esm-loader.mjs`
- [ ] Add `resolve` hook for specifier interception
- [ ] Add `load` hook for source code analysis (optional)
- [ ] Update PolicyEngine for async evaluation
- [ ] Create integration tests with ESM imports
- [ ] Update README with ESM usage instructions
- [ ] Document Node.js version requirements

## Acceptance Criteria

1. ESM `import` statements are intercepted before execution
2. Block/Allow/Warn policies work for ESM imports
3. Dynamic `import()` calls are also intercepted
4. Clear documentation on how to enable ESM protection

## Dependencies

- Node.js 18.6+ (Loaders API)
- Node.js 20.6+ for `module.register()` (optional enhancement)

## References

- [Node.js ESM Loaders Documentation](https://nodejs.org/api/esm.html#loaders)
- [Node.js Module Customization Hooks](https://nodejs.org/api/module.html#customization-hooks)

---

**Target Version:** v0.2.0  
**Estimated Effort:** 3-5 days  
**Priority:** High (addresses major functional gap)

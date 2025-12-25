/**
 * ReqGuard ESM Loader
 * Node.js ESM loader hooks for intercepting ES module imports.
 * Use with: node --import ./loader.mjs app.js
 * 
 * Zero-dependency runtime security.
 */

// Note: This file is .mjs to work as an ESM loader
// It must use dynamic import for the TypeScript modules

let policyEngine = null;
let securityErrorClass = null;
let initialized = false;

/**
 * Initialize the loader by loading the PolicyEngine.
 * This is done lazily on first hook call.
 */
async function ensureInitialized() {
    if (initialized) return;

    try {
        // Dynamic import of the compiled policy engine
        const policyModule = await import('./policy-engine.js');
        const errorModule = await import('./SecurityError.js');

        policyEngine = policyModule.PolicyEngine.getInstance();
        securityErrorClass = errorModule.SecurityError;
        initialized = true;
    } catch (error) {
        // If modules aren't compiled yet, run in passthrough mode
        console.warn('[reqguard] ESM Loader: Policy engine not available, running in passthrough mode');
    }
}

/** Hard-coded dangerous modules that are always blocked */
const DANGEROUS_MODULES = new Set([
    'child_process',
    'node:child_process',
    'vm',
    'node:vm',
    'worker_threads',
    'node:worker_threads',
]);

/**
 * ESM resolve hook.
 * Called when Node.js resolves an import specifier.
 * 
 * @param {string} specifier - The module specifier being imported
 * @param {Object} context - Resolution context
 * @param {Function} nextResolve - The next resolve function in the chain
 * @returns {Promise<{url: string, shortCircuit?: boolean}>}
 */
export async function resolve(specifier, context, nextResolve) {
    // FAST PATH 1: Relative imports pass through
    if (specifier.startsWith('./') || specifier.startsWith('../') || specifier.startsWith('/')) {
        return nextResolve(specifier, context);
    }

    // FAST PATH 2: File URLs pass through
    if (specifier.startsWith('file://')) {
        return nextResolve(specifier, context);
    }

    // FAST PATH 3: Check hard-coded dangerous modules (no async needed)
    if (DANGEROUS_MODULES.has(specifier)) {
        throw new Error(`[reqguard] Security Violation: Module '${specifier}' is blocked by security policy`);
    }

    // Initialize policy engine if needed
    await ensureInitialized();

    // Check against policy engine if available
    if (policyEngine && securityErrorClass) {
        try {
            const allowed = policyEngine.check(specifier);
            if (!allowed) {
                throw new securityErrorClass(`Module '${specifier}' is blocked by security policy`);
            }
        } catch (error) {
            // Re-throw security errors
            if (error.name === 'SecurityError' || error.message.includes('[reqguard]')) {
                throw error;
            }
        }
    }

    // Continue with normal resolution
    return nextResolve(specifier, context);
}

/**
 * ESM load hook.
 * Called after resolution to load the module source.
 * 
 * @param {string} url - The resolved URL of the module
 * @param {Object} context - Load context
 * @param {Function} nextLoad - The next load function in the chain
 * @returns {Promise<{format: string, source: string|ArrayBuffer, shortCircuit?: boolean}>}
 */
export async function load(url, context, nextLoad) {
    // For now, we do all security checks in resolve()
    // This hook is here for future extensibility (source scanning, etc.)
    return nextLoad(url, context);
}

/**
 * Initialize hook (Node.js 20.6+)
 * Called once when the loader is registered.
 */
export async function initialize(data) {
    // Pre-initialize the policy engine
    await ensureInitialized();

    if (data?.config && policyEngine) {
        // Apply any configuration passed during registration
        const { PolicyEngine } = await import('./policy-engine.js');
        PolicyEngine.configure(data.config);
    }
}

/**
 * ReqGuard CJS Interceptor
 * Patches Module.prototype.require to intercept all CommonJS module loads.
 * Zero-dependency runtime security.
 */

import Module from 'node:module';
import { PolicyEngine } from './policy-engine';
import { SecurityError } from './SecurityError';

// Store original require for restoration
let originalRequire: ((this: Module, id: string) => unknown) | null = null;
let isHooked = false;

// Recursion guard to prevent infinite loops
let isChecking = false;

/** Callback type for module analysis */
export type AnalyzeCallback = (moduleId: string, resolvedPath: string) => void;

// Optional analyzer callback for additional checks (e.g., typosquatting)
let analyzerCallback: AnalyzeCallback | null = null;

/**
 * Hook into Node.js Module.prototype.require.
 * Intercepts all CommonJS require() calls and checks against PolicyEngine.
 * 
 * @param analyzer Optional callback for additional analysis (typosquatting, etc.)
 */
export function hookRequire(analyzer?: AnalyzeCallback): void {
    if (isHooked) {
        // Already hooked, just update analyzer if provided
        if (analyzer) {
            analyzerCallback = analyzer;
        }
        return;
    }

    if (analyzer) {
        analyzerCallback = analyzer;
    }

    // Store original
    originalRequire = Module.prototype.require;

    // Patch require
    Module.prototype.require = function patchedRequire(this: Module, id: string): unknown {
        // FAST PATH 1: Recursion guard
        if (isChecking) {
            return originalRequire!.call(this, id);
        }

        // FAST PATH 2: Relative imports skip policy check (user's own code)
        if (id.startsWith('./') || id.startsWith('../')) {
            return originalRequire!.call(this, id);
        }

        // FAST PATH 3: Node protocol prefix - extract module name
        const moduleId = id.startsWith('node:') ? id.substring(5) : id;

        try {
            isChecking = true;

            // Get PolicyEngine singleton
            const engine = PolicyEngine.getInstance();

            // Check if module is allowed
            const allowed = engine.check(id);

            if (!allowed) {
                // In non-enforce mode, check() returns false but doesn't throw
                // We should still block the require
                throw new SecurityError(`Module '${id}' is blocked by security policy`);
            }

            // Optional: Run additional analyzer (e.g., typosquatting check)
            if (analyzerCallback) {
                try {
                    // Resolve path for analyzer
                    const resolvedPath = (Module as unknown as {
                        _resolveFilename: (request: string, parent: Module, isMain: boolean) => string;
                    })._resolveFilename(id, this, false);

                    analyzerCallback(moduleId, resolvedPath);
                } catch (analyzerError) {
                    // Analyzer errors shouldn't block require
                    // unless it's a SecurityError
                    if (analyzerError instanceof SecurityError) {
                        throw analyzerError;
                    }
                }
            }
        } catch (error) {
            // Re-throw SecurityError
            if (error instanceof SecurityError) {
                throw error;
            }
            // Re-throw errors with our prefix
            if (error instanceof Error && error.message.startsWith('[reqguard]')) {
                throw error;
            }
            // Other errors (e.g., module not found) pass through
        } finally {
            isChecking = false;
        }

        // Call original require
        return originalRequire!.call(this, id);
    } as typeof Module.prototype.require;

    isHooked = true;
}

/**
 * Restore original require function.
 * Useful for testing or cleanup.
 */
export function restoreRequire(): void {
    if (isHooked && originalRequire) {
        Module.prototype.require = originalRequire;
        originalRequire = null;
        isHooked = false;
        analyzerCallback = null;
    }
}

/**
 * Check if require is currently hooked.
 */
export function isRequireHooked(): boolean {
    return isHooked;
}

/**
 * Set the analyzer callback without re-hooking.
 */
export function setAnalyzer(analyzer: AnalyzeCallback | null): void {
    analyzerCallback = analyzer;
}

// Re-export SecurityError for convenience
export { SecurityError };

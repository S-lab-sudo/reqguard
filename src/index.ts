/**
 * reqguard - Runtime Security Guard for Node.js Dependencies
 *
 * @example
 * ```typescript
 * import reqguard from 'reqguard';
 *
 * reqguard.init({
 *   packages: {
 *     block: [{ name: 'malicious-pkg', reason: 'Known malware' }]
 *   }
 * });
 *
 * // Now any require('malicious-pkg') will throw an error
 * ```
 */

import { hookRequire, restoreRequire } from './core/cjs-interceptor';
import { PolicyEngine } from './policy/PolicyEngine';
import { ReqGuardPolicy, PolicyDecision } from './types/policy';

let engine: PolicyEngine | null = null;
let isInitialized = false;

/**
 * Log a message based on the configured log level.
 */
function log(
    level: 'error' | 'warn' | 'info' | 'debug',
    message: string,
    policy: ReqGuardPolicy
): void {
    const levels = ['silent', 'error', 'warn', 'info', 'debug'];
    const currentLevel = levels.indexOf(policy.logging.level);
    const messageLevel = levels.indexOf(level);

    if (messageLevel <= currentLevel && currentLevel > 0) {
        const prefix = `[reqguard]`;
        switch (level) {
            case 'error':
                console.error(`${prefix} ❌ ${message}`);
                break;
            case 'warn':
                console.warn(`${prefix} ⚠️  ${message}`);
                break;
            case 'info':
                console.info(`${prefix} ℹ️  ${message}`);
                break;
            case 'debug':
                console.debug(`${prefix} 🔍 ${message}`);
                break;
        }
    }
}

/**
 * Initialize reqguard with a policy configuration.
 * This hooks into Node's require() to intercept module loading.
 *
 * @param config Partial policy configuration (merged with defaults)
 */
export function init(config: Partial<ReqGuardPolicy> = {}): void {
    if (isInitialized) {
        // Already initialized, just update the engine
        engine = new PolicyEngine(config);
        return;
    }

    engine = new PolicyEngine(config);
    const policy = engine.getPolicy();

    log('info', 'Initializing...', policy);

    hookRequire((moduleId: string, resolvedPath: string) => {
        if (!engine) return;

        const decision: PolicyDecision = engine.evaluate(moduleId, resolvedPath);

        switch (decision.action) {
            case 'block':
                log('error', `BLOCKED: ${moduleId} - ${decision.reason}`, policy);
                if (policy.mode === 'enforce') {
                    throw new Error(
                        `[reqguard] Blocked: ${moduleId} - ${decision.reason}`
                    );
                }
                break;

            case 'warn':
                log('warn', `WARNING: ${moduleId} - ${decision.reason}`, policy);
                break;

            case 'analyze':
                // In MVP, we just allow if no explicit rule
                // Future: Pass to analysis pipeline
                log('debug', `ANALYZE: ${moduleId} (no explicit rule)`, policy);
                break;

            case 'allow':
                log('debug', `ALLOWED: ${moduleId}`, policy);
                break;
        }
    });

    isInitialized = true;
    log('info', `Active (mode: ${policy.mode})`, policy);
}

/**
 * Shutdown reqguard and restore original require behavior.
 * Useful for testing or when you want to disable protection.
 */
export function shutdown(): void {
    if (isInitialized) {
        restoreRequire();
        engine = null;
        isInitialized = false;
    }
}

/**
 * Check if reqguard is currently active.
 */
export function isActive(): boolean {
    return isInitialized;
}

/**
 * Get the current policy engine instance.
 * Returns null if not initialized.
 */
export function getEngine(): PolicyEngine | null {
    return engine;
}

// Default export for convenience
export default {
    init,
    shutdown,
    isActive,
    getEngine,
};

// Named exports for types
export type { ReqGuardPolicy, PolicyDecision } from './types/policy';
export { PolicyEngine } from './policy/PolicyEngine';

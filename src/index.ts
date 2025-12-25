/**
 * ReqGuard - Runtime Security Guard for Node.js
 * Zero-dependency module security with secure defaults.
 * 
 * @example
 * ```typescript
 * // Method 1: Auto-activate with --import flag
 * // node --import reqguard app.js
 * 
 * // Method 2: Programmatic initialization
 * import reqguard from 'reqguard';
 * reqguard.init();
 * 
 * // Method 3: Express middleware
 * import { middleware } from 'reqguard';
 * app.use(middleware());
 * ```
 */

// Core exports
export { SecurityError } from './core/SecurityError';
export { PolicyEngine, getPolicyEngine, PolicyConfig } from './core/policy-engine';
export { hookRequire, restoreRequire, isRequireHooked } from './core/cjs-interceptor';
export { lockdownPrimordials, restorePrimordials, arePrimordialsLocked } from './core/primordials';
export { activateNetworkShield, deactivateNetworkShield, isNetworkShieldActive } from './core/network-shield';
export { activateFsShield, deactivateFsShield, isFsShieldActive } from './core/fs-shield';
export { checkTyposquat, warnIfTyposquat, getPopularPackages, isPopularPackage } from './core/typosquat';
export { loadConfig, getDefaultConfig, hasConfigFile, ReqGuardConfig } from './bootstrap';

// Utility exports
export { levenshtein, isSimilar } from './utils/levenshtein';

// Import for internal use
import { PolicyEngine } from './core/policy-engine';
import { hookRequire, restoreRequire } from './core/cjs-interceptor';
import { lockdownPrimordials, restorePrimordials } from './core/primordials';
import { activateNetworkShield, deactivateNetworkShield } from './core/network-shield';
import { activateFsShield, deactivateFsShield } from './core/fs-shield';
import { warnIfTyposquat } from './core/typosquat';
import { loadConfig, ReqGuardConfig } from './bootstrap';

/** State tracking */
let isInitialized = false;
let currentConfig: ReqGuardConfig | null = null;

/**
 * Initialize ReqGuard with all security shields.
 * 
 * @param config Optional configuration override
 */
export function init(config?: Partial<ReqGuardConfig>): void {
    if (isInitialized) {
        // Re-configure if already initialized
        if (config) {
            configure(config);
        }
        return;
    }

    // Load configuration (from reqguard.json or defaults)
    const loadedConfig = loadConfig();
    currentConfig = { ...loadedConfig, ...config };

    // Configure policy engine
    PolicyEngine.configure({
        mode: currentConfig.mode,
        allowDangerousBuiltins: currentConfig.allowDangerousBuiltins,
        blocklist: currentConfig.blocklist || [],
        allowlist: currentConfig.allowlist || [],
        logLevel: currentConfig.logLevel,
    });

    // Hook require with typosquatting detection
    hookRequire((_moduleId, _resolvedPath) => {
        if (currentConfig?.typosquatDetection) {
            // Only check package names, not relative imports
            if (!_moduleId.startsWith('.') && !_moduleId.startsWith('/')) {
                warnIfTyposquat(_moduleId);
            }
        }
    });

    // Activate shields based on config
    if (currentConfig.lockdownPrimordials) {
        lockdownPrimordials();
    }

    if (currentConfig.networkShield) {
        activateNetworkShield();
    }

    if (currentConfig.fsShield) {
        activateFsShield();
    }

    isInitialized = true;

    // Log initialization
    const engine = PolicyEngine.getInstance();
    const logLevel = engine.getConfig().logLevel;
    if (logLevel !== 'silent') {
        console.log('[reqguard] ✅ Security shields activated');
    }
}

/**
 * Configure ReqGuard without full initialization.
 * Use this to update settings on an already-initialized instance.
 * 
 * @param config Configuration options
 */
export function configure(config: Partial<ReqGuardConfig>): void {
    if (currentConfig) {
        currentConfig = { ...currentConfig, ...config };
    } else {
        currentConfig = { ...loadConfig(), ...config };
    }

    // Update policy engine with full merged config
    PolicyEngine.configure({
        mode: currentConfig.mode,
        allowDangerousBuiltins: currentConfig.allowDangerousBuiltins,
        blocklist: currentConfig.blocklist,
        allowlist: currentConfig.allowlist,
        logLevel: currentConfig.logLevel,
    });
}

/**
 * Shutdown ReqGuard and restore all patched functions.
 * Useful for testing or when intentionally disabling protection.
 */
export function shutdown(): void {
    if (!isInitialized) {
        return;
    }

    // Restore all patches
    restoreRequire();
    restorePrimordials();
    deactivateNetworkShield();
    deactivateFsShield();

    // Reset policy engine
    PolicyEngine.reset();

    isInitialized = false;
    currentConfig = null;
}

/**
 * Check if ReqGuard is currently active.
 */
export function isActive(): boolean {
    return isInitialized;
}

/**
 * Get the current configuration.
 */
export function getConfig(): Readonly<ReqGuardConfig> | null {
    return currentConfig;
}

/**
 * Express/Koa middleware for ReqGuard.
 * Auto-initializes if not already done.
 * 
 * @param config Optional configuration
 * @returns Middleware function
 */
export function middleware(config?: Partial<ReqGuardConfig>) {
    // Initialize with provided config
    if (!isInitialized) {
        init(config);
    } else if (config) {
        configure(config);
    }

    // Return middleware that does nothing (protection is already active)
    return function reqguardMiddleware(
        _req: unknown,
        _res: unknown,
        next: () => void
    ): void {
        // All protection happens at require() time
        // This middleware just ensures ReqGuard is initialized
        next();
    };
}

// Default export object for convenience
const reqguard = {
    init,
    configure,
    shutdown,
    isActive,
    getConfig,
    middleware,
    PolicyEngine,
};

export default reqguard;

// Auto-activate when imported via --import flag
// Check if we're being imported as the main loader
if (typeof process !== 'undefined' && process.argv) {
    const isLoader = process.argv.some(
        (arg) => arg.includes('--import') || arg.includes('--loader')
    );

    // Don't auto-activate in test environments
    const isTest = process.env.NODE_ENV === 'test' || process.env.VITEST;

    if (isLoader && !isTest) {
        init();
    }
}

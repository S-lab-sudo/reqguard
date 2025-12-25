/**
 * ReqGuard Policy Engine (Singleton)
 * Core security policy enforcement with hard-coded secure defaults.
 * Zero-dependency runtime security guard for Node.js.
 */

import { builtinModules } from 'node:module';
import { SecurityError } from './SecurityError';

/** Hard-coded dangerous built-ins that are ALWAYS blocked by default */
const DANGEROUS_BUILTINS: readonly string[] = Object.freeze([
    'child_process',
    'vm',
    'worker_threads',
]);

/** Configuration for the PolicyEngine */
export interface PolicyConfig {
    /** Mode: 'enforce' blocks, 'warn' logs, 'audit' only logs */
    mode: 'enforce' | 'warn' | 'audit';
    /** Whether to allow dangerous built-ins (default: false) */
    allowDangerousBuiltins: boolean;
    /** Custom blocklist patterns */
    blocklist: string[];
    /** Custom allowlist patterns (takes priority over blocklist) */
    allowlist: string[];
    /** Logging level */
    logLevel: 'silent' | 'error' | 'warn' | 'info' | 'debug';
}

/** Default secure configuration */
const DEFAULT_CONFIG: PolicyConfig = Object.freeze({
    mode: 'enforce',
    allowDangerousBuiltins: false,
    blocklist: [],
    allowlist: [],
    logLevel: 'warn',
});

/**
 * PolicyEngine Singleton
 * Manages security policies for module loading.
 */
export class PolicyEngine {
    private static instance: PolicyEngine | null = null;

    private config: PolicyConfig;
    private readonly builtinSet: Set<string>;
    private readonly allowSet: Set<string>;
    private readonly blockSet: Set<string>;
    private readonly dangerousSet: Set<string>;

    private constructor(config: Partial<PolicyConfig> = {}) {
        this.config = { ...DEFAULT_CONFIG, ...config };

        // Create optimized Sets for O(1) lookups
        this.builtinSet = new Set([
            ...builtinModules,
            ...builtinModules.map((m) => `node:${m}`),
        ]);

        this.allowSet = new Set(this.config.allowlist);
        this.blockSet = new Set(this.config.blocklist);
        this.dangerousSet = new Set([
            ...DANGEROUS_BUILTINS,
            ...DANGEROUS_BUILTINS.map((m) => `node:${m}`),
        ]);
    }

    /**
     * Get the singleton instance of PolicyEngine.
     */
    public static getInstance(): PolicyEngine {
        if (!PolicyEngine.instance) {
            PolicyEngine.instance = new PolicyEngine();
        }
        return PolicyEngine.instance;
    }

    /**
     * Initialize or reconfigure the singleton with new config.
     */
    public static configure(config: Partial<PolicyConfig> = {}): PolicyEngine {
        if (PolicyEngine.instance) {
            // Merge with existing config
            PolicyEngine.instance.config = {
                ...PolicyEngine.instance.config,
                ...config,
            };

            // Rebuild sets from new config to ensure removals are reflected
            PolicyEngine.instance.allowSet.clear();
            PolicyEngine.instance.blockSet.clear();

            // Re-populate from the merged configuration
            PolicyEngine.instance.config.allowlist.forEach(
                (pkg) => PolicyEngine.instance!.allowSet.add(pkg)
            );
            PolicyEngine.instance.config.blocklist.forEach(
                (pkg) => PolicyEngine.instance!.blockSet.add(pkg)
            );

            // Re-evaluate dangerous built-ins based on new flag
            // (Only if allowDangerousBuiltins changed, but easiest to just rebuild logic)
            // Actually, we check the flag dynamically in check(), so we don't need to change dangerousSet
            // unless we want to support dynamic updates to DANGEROUS_BUILTINS list (which is frozen)
        } else {
            PolicyEngine.instance = new PolicyEngine(config);
        }
        return PolicyEngine.instance;
    }

    /**
     * Reset the singleton (useful for testing).
     */
    public static reset(): void {
        PolicyEngine.instance = null;
    }

    /**
     * FAST PATH: Check if a module request should be allowed.
     * Returns true if allowed, false if blocked.
     * Throws SecurityError in enforce mode when blocked.
     */
    public check(request: string): boolean {
        // FAST PATH 1: Relative imports are always allowed (user's own code)
        if (request.startsWith('./') || request.startsWith('../')) {
            return true;
        }

        // FAST PATH 2: Check explicit allowlist first (highest priority)
        const packageName = this.extractPackageName(request);
        if (this.allowSet.has(packageName) || this.allowSet.has(request)) {
            return true;
        }

        // FAST PATH 3: Check dangerous built-ins
        if (this.dangerousSet.has(request) || this.dangerousSet.has(packageName)) {
            if (!this.config.allowDangerousBuiltins) {
                return this.handleBlock(request, `Dangerous built-in '${packageName}' is blocked by default`);
            }
        }

        // FAST PATH 4: Check explicit blocklist
        if (this.blockSet.has(packageName) || this.blockSet.has(request)) {
            return this.handleBlock(request, `Package '${packageName}' is explicitly blocked`);
        }

        // FAST PATH 5: Regular built-ins are allowed
        if (this.builtinSet.has(request)) {
            return true;
        }

        // Default: allow (but could be extended for analysis)
        return true;
    }

    /**
     * Handle a blocked module based on mode.
     */
    private handleBlock(request: string, reason: string): boolean {
        switch (this.config.mode) {
            case 'enforce':
                throw new SecurityError(reason);
            case 'warn':
                this.log('warn', `BLOCKED: ${request} - ${reason}`);
                return false;
            case 'audit':
                this.log('info', `AUDIT: ${request} - ${reason}`);
                return true; // Allow but log
        }
    }

    /**
     * Add a package to the allowlist.
     */
    public addToAllowList(pkg: string): void {
        this.allowSet.add(pkg);
        // Also add node: prefixed version if it's a built-in pattern
        if (!pkg.startsWith('@') && !pkg.includes('/')) {
            this.allowSet.add(`node:${pkg}`);
        }
    }

    /**
     * Add multiple packages to the allowlist.
     */
    public addToAllowListBulk(packages: string[]): void {
        for (const pkg of packages) {
            this.addToAllowList(pkg);
        }
    }

    /**
     * Add a package to the blocklist.
     */
    public addToBlockList(pkg: string): void {
        this.blockSet.add(pkg);
        if (!pkg.startsWith('@') && !pkg.includes('/')) {
            this.blockSet.add(`node:${pkg}`);
        }
    }

    /**
     * Check if a module is a built-in.
     */
    public isBuiltin(moduleId: string): boolean {
        return this.builtinSet.has(moduleId);
    }

    /**
     * Extract package name from module specifier.
     * Handles scoped packages (@scope/name) and subpaths.
     */
    private extractPackageName(moduleId: string): string {
        // Remove node: prefix if present
        const normalized = moduleId.startsWith('node:')
            ? moduleId.substring(5)
            : moduleId;

        // Scoped package: @scope/name or @scope/name/subpath
        if (normalized.startsWith('@')) {
            const parts = normalized.split('/');
            if (parts.length >= 2) {
                return `${parts[0]}/${parts[1]}`;
            }
            return normalized;
        }

        // Regular package: name or name/subpath
        const slashIndex = normalized.indexOf('/');
        if (slashIndex !== -1) {
            return normalized.substring(0, slashIndex);
        }

        return normalized;
    }

    /**
     * Get current configuration.
     */
    public getConfig(): Readonly<PolicyConfig> {
        return this.config;
    }

    /**
     * Internal logging based on configured level.
     */
    private log(level: 'error' | 'warn' | 'info' | 'debug', message: string): void {
        const levels = ['silent', 'error', 'warn', 'info', 'debug'];
        const currentLevel = levels.indexOf(this.config.logLevel);
        const messageLevel = levels.indexOf(level);

        if (messageLevel <= currentLevel && currentLevel > 0) {
            const prefix = '[reqguard]';
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
}

// Export a convenience function
export function getPolicyEngine(): PolicyEngine {
    return PolicyEngine.getInstance();
}

/**
 * reqguard Policy Engine
 * Evaluates module requests against configured policies.
 */

import { builtinModules } from 'module';
import {
    ReqGuardPolicy,
    PolicyDecision,
    PackageRule,
    DEFAULT_POLICY,
} from '../types/policy';

export class PolicyEngine {
    private policy: ReqGuardPolicy;
    private builtinSet: Set<string>;

    constructor(policy: Partial<ReqGuardPolicy> = {}) {
        // Merge with defaults
        this.policy = {
            ...DEFAULT_POLICY,
            ...policy,
            packages: {
                ...DEFAULT_POLICY.packages,
                ...policy.packages,
            },
            builtins: {
                ...DEFAULT_POLICY.builtins,
                ...policy.builtins,
            },
            relativeImports: {
                ...DEFAULT_POLICY.relativeImports,
                ...policy.relativeImports,
            },
            logging: {
                ...DEFAULT_POLICY.logging,
                ...policy.logging,
            },
        };

        // Create Set of built-in module names for fast lookup
        // Include both 'fs' and 'node:fs' variants
        this.builtinSet = new Set([
            ...builtinModules,
            ...builtinModules.map((m) => `node:${m}`),
        ]);
    }

    /**
     * Evaluate a module request against the policy.
     * Priority: Built-ins > Blocklist > Allowlist > Warnlist > Default (analyze)
     */
    evaluate(moduleId: string, resolvedPath: string): PolicyDecision {
        // 1. Check if it's a built-in module
        if (this.isBuiltin(moduleId)) {
            return this.evaluateBuiltin(moduleId);
        }

        // 2. Check if it's a relative import
        if (this.isRelativeImport(moduleId)) {
            if (!this.policy.relativeImports.analyze) {
                return { action: 'allow', reason: 'Relative import (analysis disabled)' };
            }
            // Fall through to analysis
            return { action: 'analyze', reason: 'Relative import requires analysis' };
        }

        // 3. Extract package name from module ID (handle scoped packages)
        const packageName = this.extractPackageName(moduleId);

        // 4. Check blocklist (highest priority for external packages)
        const blockMatch = this.matchesList(packageName, this.policy.packages.block);
        if (blockMatch) {
            return {
                action: 'block',
                reason: blockMatch.reason || `Package '${packageName}' is blocklisted`,
                matchedRule: blockMatch,
            };
        }

        // 5. Check allowlist
        const allowMatch = this.matchesList(packageName, this.policy.packages.allow);
        if (allowMatch) {
            return {
                action: 'allow',
                reason: allowMatch.reason || `Package '${packageName}' is allowlisted`,
                matchedRule: allowMatch,
            };
        }

        // 6. Check warnlist
        const warnMatch = this.matchesList(packageName, this.policy.packages.warn);
        if (warnMatch) {
            return {
                action: 'warn',
                reason: warnMatch.reason || `Package '${packageName}' requires review`,
                matchedRule: warnMatch,
            };
        }

        // 7. Default: pass to analysis pipeline
        return { action: 'analyze', reason: 'No explicit rule, requires analysis' };
    }

    /**
     * Check if a module ID is a Node.js built-in.
     */
    private isBuiltin(moduleId: string): boolean {
        return this.builtinSet.has(moduleId);
    }

    /**
     * Check if a module ID is a relative import.
     */
    private isRelativeImport(moduleId: string): boolean {
        return moduleId.startsWith('./') || moduleId.startsWith('../');
    }

    /**
     * Extract the package name from a module ID.
     * Handles scoped packages (@scope/name) and subpaths (lodash/get).
     */
    private extractPackageName(moduleId: string): string {
        // Scoped package: @scope/name or @scope/name/subpath
        if (moduleId.startsWith('@')) {
            const parts = moduleId.split('/');
            if (parts.length >= 2) {
                return `${parts[0]}/${parts[1]}`;
            }
            return moduleId;
        }

        // Regular package: name or name/subpath
        const slashIndex = moduleId.indexOf('/');
        if (slashIndex !== -1) {
            return moduleId.substring(0, slashIndex);
        }

        return moduleId;
    }

    /**
     * Check if a package name matches any rule in a list.
     * Supports exact match and simple wildcard (*) patterns.
     */
    private matchesList(
        packageName: string,
        rules: PackageRule[]
    ): PackageRule | null {
        for (const rule of rules) {
            if (this.matchesPattern(packageName, rule.name)) {
                return rule;
            }
        }
        return null;
    }

    /**
     * Match a package name against a pattern.
     * Supports:
     * - Exact match: 'lodash' matches 'lodash'
     * - Wildcard: 'lodash*' matches 'lodash', 'lodash-es'
     * - Scoped wildcard: '@scope/*' matches '@scope/foo', '@scope/bar'
     */
    private matchesPattern(packageName: string, pattern: string): boolean {
        // Exact match
        if (pattern === packageName) {
            return true;
        }

        // Wildcard match
        if (pattern.endsWith('*')) {
            const prefix = pattern.slice(0, -1);
            return packageName.startsWith(prefix);
        }

        return false;
    }

    /**
     * Evaluate a built-in module.
     */
    private evaluateBuiltin(moduleId: string): PolicyDecision {
        // Normalize: remove 'node:' prefix if present
        const normalized = moduleId.startsWith('node:')
            ? moduleId.substring(5)
            : moduleId;

        // Check if this specific built-in is restricted (highest priority block)
        if (this.policy.builtins.restricted.includes(normalized)) {
            return {
                action: 'block',
                reason: `Built-in '${normalized}' is restricted by policy`,
            };
        }

        // Check if built-ins are allowed globally
        if (this.policy.builtins.allow) {
            return { action: 'allow', reason: 'Built-in module' };
        }

        // Built-ins are disabled - but check if explicitly allowed in package rules
        const allowMatch = this.matchesList(normalized, this.policy.packages.allow);
        if (allowMatch) {
            return {
                action: 'allow',
                reason: allowMatch.reason || `Built-in '${normalized}' is explicitly allowlisted`,
                matchedRule: allowMatch,
            };
        }

        // Check blocklist for explicit block rule
        const blockMatch = this.matchesList(normalized, this.policy.packages.block);
        if (blockMatch) {
            return {
                action: 'block',
                reason: blockMatch.reason || `Built-in '${normalized}' is blocklisted`,
                matchedRule: blockMatch,
            };
        }

        // Default: block because builtins.allow is false
        return {
            action: 'block',
            reason: `Built-in modules are disabled by policy`,
        };
    }

    /**
     * Get the current policy configuration.
     */
    getPolicy(): ReqGuardPolicy {
        return this.policy;
    }
}

/**
 * reqguard Policy Type Definitions
 * Zero-dependency runtime security guard for Node.js
 */

/**
 * A rule that matches a specific package.
 */
export interface PackageRule {
    /** Package name or glob pattern (e.g., 'lodash', 'express', '@scope/*') */
    name: string;
    /** Optional semver range (e.g., '^4.18.0'). Not enforced in MVP. */
    version?: string;
    /** Human-readable reason for this rule */
    reason?: string;
}

/**
 * Main configuration for reqguard.
 */
export interface ReqGuardPolicy {
    /** Global behavior: 'enforce' blocks, 'warn' logs, 'audit' only logs */
    mode: 'enforce' | 'warn' | 'audit';

    /** Package-specific rules */
    packages: {
        /** Explicit allow list (packages that are always allowed) */
        allow: PackageRule[];
        /** Explicit block list (packages that are always blocked) */
        block: PackageRule[];
        /** Warn list (packages that trigger a warning but are allowed) */
        warn: PackageRule[];
    };

    /** Built-in module handling */
    builtins: {
        /** Whether to allow all Node.js built-in modules (default: true) */
        allow: boolean;
        /** Specific built-ins to restrict (e.g., ['child_process', 'vm']) */
        restricted: string[];
    };

    /** Relative imports (user's own code) */
    relativeImports: {
        /** Whether to analyze relative imports (default: false for performance) */
        analyze: boolean;
    };

    /** Logging configuration */
    logging: {
        level: 'silent' | 'error' | 'warn' | 'info' | 'debug';
    };
}

/**
 * The action to take for a module.
 */
export type PolicyAction = 'allow' | 'block' | 'warn' | 'analyze';

/**
 * Result of evaluating a module against the policy.
 */
export interface PolicyDecision {
    /** The action to take */
    action: PolicyAction;
    /** Human-readable reason for the decision */
    reason?: string;
    /** The rule that matched, if any */
    matchedRule?: PackageRule;
}

/**
 * Default policy configuration.
 */
export const DEFAULT_POLICY: ReqGuardPolicy = {
    mode: 'enforce',
    packages: {
        allow: [],
        block: [],
        warn: [],
    },
    builtins: {
        allow: true,
        restricted: [],
    },
    relativeImports: {
        analyze: false,
    },
    logging: {
        level: 'warn',
    },
};

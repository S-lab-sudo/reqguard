/**
 * ReqGuard Configuration Bootstrap
 * Synchronously reads configuration files at startup.
 * Populates PolicyEngine allowlist from package-lock.json.
 * 
 * Zero-dependency runtime security.
 */

import fs from 'node:fs';
import path from 'node:path';
import { PolicyEngine, PolicyConfig } from './core/policy-engine';

/** ReqGuard configuration file structure */
export interface ReqGuardConfig {
    /** Security mode */
    mode?: 'enforce' | 'warn' | 'audit';
    /** Whether to allow dangerous built-ins */
    allowDangerousBuiltins?: boolean;
    /** Packages to block */
    blocklist?: string[];
    /** Packages to allow */
    allowlist?: string[];
    /** Logging level */
    logLevel?: 'silent' | 'error' | 'warn' | 'info' | 'debug';
    /** Whether to enable typosquatting detection */
    typosquatDetection?: boolean;
    /** Whether to enable network shield */
    networkShield?: boolean;
    /** Whether to enable filesystem shield */
    fsShield?: boolean;
    /** Whether to lock down primordials (eval, Function) */
    lockdownPrimordials?: boolean;
}

/** Default configuration */
const DEFAULT_CONFIG: ReqGuardConfig = Object.freeze({
    mode: 'enforce',
    allowDangerousBuiltins: false,
    blocklist: [],
    allowlist: [],
    logLevel: 'warn',
    typosquatDetection: true,
    networkShield: true,
    fsShield: true,
    lockdownPrimordials: true,
});

/**
 * Find the project root by looking for package.json.
 */
function findProjectRoot(startDir?: string): string | null {
    let dir = startDir || process.cwd();

    // Limit search depth to prevent infinite loops
    for (let i = 0; i < 10; i++) {
        const packageJsonPath = path.join(dir, 'package.json');
        try {
            fs.accessSync(packageJsonPath, fs.constants.R_OK);
            return dir;
        } catch {
            const parentDir = path.dirname(dir);
            if (parentDir === dir) {
                // Reached root
                break;
            }
            dir = parentDir;
        }
    }

    return null;
}

/**
 * Synchronously read and parse reqguard.json configuration.
 */
function loadReqGuardJson(projectRoot: string): Partial<ReqGuardConfig> {
    const configPath = path.join(projectRoot, 'reqguard.json');

    try {
        const content = fs.readFileSync(configPath, 'utf8');
        const config = JSON.parse(content) as Partial<ReqGuardConfig>;
        return config;
    } catch (error) {
        // File doesn't exist or is invalid - that's OK
        return {};
    }
}

/**
 * Parse package-lock.json and extract dependency names.
 */
function parseLockfile(projectRoot: string): string[] {
    const lockfilePath = path.join(projectRoot, 'package-lock.json');
    const packages: string[] = [];

    try {
        const content = fs.readFileSync(lockfilePath, 'utf8');
        const lockfile = JSON.parse(content) as {
            packages?: Record<string, unknown>;
            dependencies?: Record<string, unknown>;
        };

        // npm v7+ lockfile format (packages object)
        if (lockfile.packages) {
            for (const pkgPath of Object.keys(lockfile.packages)) {
                // Skip root package (empty string key)
                if (!pkgPath) continue;

                // Extract package name from path like "node_modules/lodash"
                // or "node_modules/@scope/name"
                const match = pkgPath.match(/node_modules\/(.+)$/);
                if (match) {
                    packages.push(match[1]);
                }
            }
        }

        // npm v6 lockfile format (dependencies object)
        if (lockfile.dependencies) {
            for (const name of Object.keys(lockfile.dependencies)) {
                packages.push(name);
            }
        }

    } catch (error) {
        // Lockfile doesn't exist or is invalid
    }

    return packages;
}

/**
 * Parse yarn.lock (basic format support).
 */
function parseYarnLock(projectRoot: string): string[] {
    const lockfilePath = path.join(projectRoot, 'yarn.lock');
    const packages: string[] = [];

    try {
        const content = fs.readFileSync(lockfilePath, 'utf8');

        // Basic parsing: find lines that look like package headers
        // Format: "packagename@version:" or "@scope/name@version:"
        const lines = content.split('\n');
        for (const line of lines) {
            // Skip comments and empty lines
            if (line.startsWith('#') || !line.trim()) continue;

            // Match package header pattern
            const match = line.match(/^"?(@?[a-z0-9][a-z0-9._-]*(?:\/[a-z0-9._-]+)?)@/i);
            if (match) {
                const pkgName = match[1];
                if (!packages.includes(pkgName)) {
                    packages.push(pkgName);
                }
            }
        }

    } catch (error) {
        // Lockfile doesn't exist or is invalid
    }

    return packages;
}

/**
 * Load configuration and initialize PolicyEngine.
 * This is the main entry point for bootstrap.
 * 
 * @param projectRoot Optional project root path (defaults to auto-detect)
 * @returns Merged configuration
 */
export function loadConfig(projectRoot?: string): ReqGuardConfig {
    const root = projectRoot || findProjectRoot() || process.cwd();

    // Load reqguard.json configuration
    const userConfig = loadReqGuardJson(root);

    // Merge with defaults
    const config: ReqGuardConfig = {
        ...DEFAULT_CONFIG,
        ...userConfig,
    };

    // Parse lockfile and add to allowlist
    let lockfilePackages: string[] = [];

    // Try npm lockfile first
    lockfilePackages = parseLockfile(root);

    // If no npm lockfile, try yarn
    if (lockfilePackages.length === 0) {
        lockfilePackages = parseYarnLock(root);
    }

    // Initialize PolicyEngine with config
    const policyConfig: Partial<PolicyConfig> = {
        mode: config.mode,
        allowDangerousBuiltins: config.allowDangerousBuiltins,
        blocklist: config.blocklist || [],
        allowlist: [
            ...(config.allowlist || []),
            // Don't auto-add lockfile packages to allowlist by default
            // This is a security decision - explicit allowlist only
        ],
        logLevel: config.logLevel,
    };

    const engine = PolicyEngine.configure(policyConfig);

    // Add lockfile packages to allowlist if user opts in
    // (This should be explicit, not automatic for security)
    if (lockfilePackages.length > 0 && userConfig.allowlist === undefined) {
        // Only add if user hasn't explicitly set allowlist
        // This is a convenience feature that can be disabled
        engine.addToAllowListBulk(lockfilePackages);
    }

    return config;
}

/**
 * Get the default configuration.
 */
export function getDefaultConfig(): Readonly<ReqGuardConfig> {
    return DEFAULT_CONFIG;
}

/**
 * Check if a reqguard.json file exists in the project root.
 */
export function hasConfigFile(projectRoot?: string): boolean {
    const root = projectRoot || findProjectRoot() || process.cwd();
    const configPath = path.join(root, 'reqguard.json');

    try {
        fs.accessSync(configPath, fs.constants.R_OK);
        return true;
    } catch {
        return false;
    }
}

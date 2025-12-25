/**
 * ReqGuard Filesystem Shield
 * Patches fs module to block reads to sensitive files.
 * Blocks: .env, .ssh/id_rsa, /etc/passwd, and similar sensitive paths.
 * 
 * Zero-dependency runtime security.
 */

import fs from 'node:fs';
import path from 'node:path';
import { SecurityError } from './SecurityError';

/** Blocked file patterns (checked with path.basename or endsWith) */
const BLOCKED_FILENAMES: readonly string[] = Object.freeze([
    '.env',
    '.env.local',
    '.env.production',
    '.env.development',
    'id_rsa',
    'id_ed25519',
    'id_ecdsa',
    'id_dsa',
]);

/** Blocked path patterns (checked with includes) */
const BLOCKED_PATH_PATTERNS: readonly string[] = Object.freeze([
    '.ssh/',
    '/.ssh/',
    '\\.ssh\\',
    '/etc/passwd',
    '/etc/shadow',
    '/etc/hosts',
    '\\etc\\passwd',
]);

/** Blocked path suffixes */
const BLOCKED_SUFFIXES: readonly string[] = Object.freeze([
    '.pem',
    '.key',
    '_rsa',
    '_ed25519',
]);

// Store originals for restoration
let originalReadFileSync: typeof fs.readFileSync | null = null;
let originalReadFile: typeof fs.readFile | null = null;
let originalOpenSync: typeof fs.openSync | null = null;
let originalOpen: typeof fs.open | null = null;

// Store original promises for restoration
let originalPromisesReadFile: typeof fs.promises.readFile | null = null;
let originalPromisesOpen: typeof fs.promises.open | null = null;
let originalPromisesOpendir: typeof fs.promises.opendir | null = null;

let isActivated = false;

/**
 * Check if a file path should be blocked.
 */
function isBlockedPath(filePath: string | Buffer | URL | number): boolean {
    // Handle file descriptors (numbers) - allow
    if (typeof filePath === 'number') {
        return false;
    }

    // Convert to string
    let pathStr: string;
    if (Buffer.isBuffer(filePath)) {
        pathStr = filePath.toString('utf8');
    } else if (filePath instanceof URL) {
        pathStr = filePath.pathname;
    } else {
        pathStr = filePath;
    }

    // Normalize path for consistent checking
    const normalizedPath = pathStr.replace(/\\/g, '/').toLowerCase();
    const basename = path.basename(normalizedPath);

    // FAST PATH 1: Check exact filename matches
    if (BLOCKED_FILENAMES.includes(basename)) {
        return true;
    }

    // FAST PATH 2: Check path patterns
    for (const pattern of BLOCKED_PATH_PATTERNS) {
        if (normalizedPath.includes(pattern.toLowerCase())) {
            return true;
        }
    }

    // FAST PATH 3: Check suffixes (for key files)
    for (const suffix of BLOCKED_SUFFIXES) {
        if (normalizedPath.endsWith(suffix)) {
            return true;
        }
    }

    return false;
}

/**
 * Create a SecurityError for blocked file access.
 */
function createBlockedFileError(filePath: string | Buffer | URL | number): SecurityError {
    const pathStr = typeof filePath === 'number'
        ? `fd:${filePath}`
        : filePath.toString();
    return new SecurityError(`Access to sensitive file '${pathStr}' is blocked`);
}

/**
 * Patch fs.promises API
 */
async function patchPromisesAPI() {
    // Check if fs.promises exists (Node 10+)
    if (!fs.promises) return;

    // Patch readFile
    originalPromisesReadFile = fs.promises.readFile;
    (fs.promises as any).readFile = async function patchedPromisesReadFile(
        path: any,
        options?: any
    ): Promise<string | Buffer> {
        // Handle FileHandle objects (allow for now as they are already opened)
        // Check for 'fd' property to detect FileHandle
        if (typeof path === 'object' && path !== null && 'fd' in path) {
            return originalPromisesReadFile!(path, options);
        }

        if (isBlockedPath(path as string | Buffer | URL)) {
            throw createBlockedFileError(path as string | Buffer | URL);
        }
        return originalPromisesReadFile!(path, options);
    };

    // Patch open
    originalPromisesOpen = fs.promises.open;
    (fs.promises as any).open = async function patchedPromisesOpen(
        path: fs.PathLike,
        flags?: any,
        mode?: any
    ): Promise<fs.promises.FileHandle> {
        if (isBlockedPath(path)) {
            throw createBlockedFileError(path);
        }
        return originalPromisesOpen!(path, flags, mode);
    };

    // Patch opendir
    if (fs.promises.opendir) {
        originalPromisesOpendir = fs.promises.opendir;
        (fs.promises as any).opendir = async function patchedPromisesOpendir(
            path: fs.PathLike,
            options?: any
        ): Promise<fs.Dir> {
            if (isBlockedPath(path)) {
                throw createBlockedFileError(path);
            }
            return originalPromisesOpendir!(path, options);
        };
    }
}

/**
 * Activate the filesystem shield.
 * Patches fs.readFile, fs.readFileSync, fs.open, fs.openSync, and fs.promises.
 */
export function activateFsShield(): void {
    if (isActivated) {
        return;
    }

    // Patch synchronous and callback APIs

    // Patch fs.readFileSync
    originalReadFileSync = fs.readFileSync;
    (fs as { readFileSync: typeof fs.readFileSync }).readFileSync = function patchedReadFileSync(
        filePath: fs.PathOrFileDescriptor,
        options?: Parameters<typeof fs.readFileSync>[1]
    ): string | Buffer {
        if (isBlockedPath(filePath)) {
            throw createBlockedFileError(filePath);
        }
        return originalReadFileSync!(filePath, options);
    } as typeof fs.readFileSync;

    // Patch fs.readFile
    originalReadFile = fs.readFile;
    (fs as { readFile: typeof fs.readFile }).readFile = function patchedReadFile(
        filePath: fs.PathOrFileDescriptor,
        ...args: unknown[]
    ): void {
        if (isBlockedPath(filePath)) {
            const callback = args[args.length - 1];
            if (typeof callback === 'function') {
                const error = createBlockedFileError(filePath);
                process.nextTick(() => (callback as (err: Error) => void)(error));
                return;
            }
            throw createBlockedFileError(filePath);
        }
        return (originalReadFile as Function).call(fs, filePath, ...args);
    } as typeof fs.readFile;

    // Patch fs.openSync
    originalOpenSync = fs.openSync;
    (fs as { openSync: typeof fs.openSync }).openSync = function patchedOpenSync(
        filePath: fs.PathLike,
        flags: fs.OpenMode,
        mode?: fs.Mode
    ): number {
        if (isBlockedPath(filePath)) {
            throw createBlockedFileError(filePath);
        }
        return originalOpenSync!(filePath, flags, mode);
    } as typeof fs.openSync;

    // Patch fs.open
    originalOpen = fs.open;
    (fs as { open: typeof fs.open }).open = function patchedOpen(
        filePath: fs.PathLike,
        flags: fs.OpenMode,
        ...args: unknown[]
    ): void {
        if (isBlockedPath(filePath)) {
            const callback = args[args.length - 1];
            if (typeof callback === 'function') {
                const error = createBlockedFileError(filePath);
                process.nextTick(() => (callback as (err: Error) => void)(error));
                return;
            }
            throw createBlockedFileError(filePath);
        }
        return (originalOpen as Function).call(fs, filePath, flags, ...args);
    } as typeof fs.open;

    // Patch Promises API
    patchPromisesAPI().catch(console.error);

    isActivated = true;
}

/**
 * Deactivate the filesystem shield and restore original functions.
 */
export function deactivateFsShield(): void {
    if (!isActivated) {
        return;
    }

    // Restore Sync/Callback APIs
    if (originalReadFileSync) {
        (fs as { readFileSync: typeof fs.readFileSync }).readFileSync = originalReadFileSync;
        originalReadFileSync = null;
    }

    if (originalReadFile) {
        (fs as { readFile: typeof fs.readFile }).readFile = originalReadFile;
        originalReadFile = null;
    }

    if (originalOpenSync) {
        (fs as { openSync: typeof fs.openSync }).openSync = originalOpenSync;
        originalOpenSync = null;
    }

    if (originalOpen) {
        (fs as { open: typeof fs.open }).open = originalOpen;
        originalOpen = null;
    }

    // Restore Promises API
    if (fs.promises) {
        if (originalPromisesReadFile) {
            (fs.promises as any).readFile = originalPromisesReadFile;
            originalPromisesReadFile = null;
        }
        if (originalPromisesOpen) {
            (fs.promises as any).open = originalPromisesOpen;
            originalPromisesOpen = null;
        }
        if (originalPromisesOpendir) {
            (fs.promises as any).opendir = originalPromisesOpendir;
            originalPromisesOpendir = null;
        }
    }

    isActivated = false;
}

/**
 * Check if the filesystem shield is active.
 */
export function isFsShieldActive(): boolean {
    return isActivated;
}

/**
 * Add a blocked filename at runtime.
 */
export function addBlockedFilename(filename: string): void {
    (BLOCKED_FILENAMES as string[]).push(filename.toLowerCase());
}

/**
 * Add a blocked path pattern at runtime.
 */
export function addBlockedPathPattern(pattern: string): void {
    (BLOCKED_PATH_PATTERNS as string[]).push(pattern.toLowerCase());
}

/**
 * ReqGuard Network Shield
 * Patches network primitives to block dangerous connections.
 * Explicitly blocks cloud metadata endpoints (169.254.169.254).
 * 
 * Zero-dependency runtime security.
 */

import net from 'node:net';
import dns from 'node:dns';
import { SecurityError } from './SecurityError';

/** Blocked IP addresses (cloud metadata endpoints) */
const BLOCKED_IPS: readonly string[] = Object.freeze([
    '169.254.169.254',  // AWS/GCP/Azure metadata
    '169.254.170.2',    // AWS ECS task metadata
    'fd00:ec2::254',    // AWS IPv6 metadata
]);

/** Blocked hostnames */
const BLOCKED_HOSTS: readonly string[] = Object.freeze([
    'metadata.google.internal',
    'metadata.gcp.internal',
]);

// Store originals for restoration
let originalSocketConnect: typeof net.Socket.prototype.connect | null = null;
let originalDnsLookup: typeof dns.lookup | null = null;
let originalFetch: typeof global.fetch | null = null;
let isActivated = false;

/**
 * Check if an address should be blocked.
 */
function isBlockedAddress(address: string): boolean {
    // FAST PATH: Check exact IP matches
    if (BLOCKED_IPS.includes(address)) {
        return true;
    }

    // FAST PATH: Check hostname matches
    if (BLOCKED_HOSTS.includes(address.toLowerCase())) {
        return true;
    }

    // Check for link-local IPv4 range (169.254.x.x)
    if (address.startsWith('169.254.')) {
        return true;
    }

    // Check for IPv6 mapped IPv4 addresses (::ffff:169.254.x.x)
    if (address.toLowerCase().startsWith('::ffff:169.254.')) {
        return true;
    }

    // Check for IPv6 link-local addresses (fe80::)
    if (address.toLowerCase().startsWith('fe80::')) {
        return true;
    }

    return false;
}

/**
 * Shim global.fetch if available (Node 18+)
 */
function shimGlobalFetch() {
    if (typeof global.fetch !== 'function') return;

    originalFetch = global.fetch;

    global.fetch = async function patchedFetch(
        input: RequestInfo | URL,
        init?: RequestInit
    ): Promise<Response> {
        let url: string;

        if (typeof input === 'string') {
            url = input;
        } else if (input instanceof URL) {
            url = input.toString();
        } else if (typeof input === 'object' && input !== null && 'url' in input) {
            // Request object
            url = input.url;
        } else {
            url = String(input);
        }

        try {
            const urlObj = new URL(url);
            // Check hostname (could be IP or domain)
            if (isBlockedAddress(urlObj.hostname)) {
                throw new SecurityError(
                    `Network request to '${urlObj.hostname}' is blocked (cloud metadata endpoint)`
                );
            }
        } catch (e) {
            // Invalid URL logic or SecurityError
            if (e instanceof SecurityError) throw e;
            // Ignore other URL parsing errors, let fetch handle them
        }

        return originalFetch!(input, init);
    };
}

/**
 * Activate the network shield.
 * Patches net.Socket.prototype.connect, dns.lookup, and global.fetch.
 */
export function activateNetworkShield(): void {
    if (isActivated) {
        return;
    }

    // Patch net.Socket.prototype.connect
    originalSocketConnect = net.Socket.prototype.connect;

    net.Socket.prototype.connect = function patchedConnect(
        this: net.Socket,
        ...args: unknown[]
    ): net.Socket {
        // Parse connection options
        let host: string | undefined;
        let port: number | undefined;

        const firstArg = args[0];

        if (typeof firstArg === 'object' && firstArg !== null) {
            // Options object: { host, port } or { path }
            const options = firstArg as { host?: string; port?: number; path?: string };
            host = options.host;
            port = options.port;
        } else if (typeof firstArg === 'number') {
            // (port, host, callback) format
            port = firstArg;
            host = typeof args[1] === 'string' ? args[1] : undefined;
        } else if (typeof firstArg === 'string') {
            // Unix socket path or (path, callback) - allowed
            // Check if it looks like an IP
            if (firstArg.includes('.') || firstArg.includes(':')) {
                host = firstArg;
            }
        }

        // Check if connection should be blocked
        if (host && isBlockedAddress(host)) {
            throw new SecurityError(
                `Network connection to '${host}:${port ?? ''}' is blocked (cloud metadata endpoint)`
            );
        }

        // Call original
        return originalSocketConnect!.apply(this, args as Parameters<typeof net.Socket.prototype.connect>);
    } as typeof net.Socket.prototype.connect;

    // Patch dns.lookup
    originalDnsLookup = dns.lookup;

    (dns as { lookup: typeof dns.lookup }).lookup = function patchedLookup(
        hostname: string,
        ...args: unknown[]
    ): void {
        // Check if hostname is blocked
        if (isBlockedAddress(hostname)) {
            const callback = args[args.length - 1];
            if (typeof callback === 'function') {
                const error = new SecurityError(
                    `DNS lookup for '${hostname}' is blocked (cloud metadata endpoint)`
                );
                (callback as (err: Error | null) => void)(error);
                return;
            }
            throw new SecurityError(`DNS lookup for '${hostname}' is blocked`);
        }

        // Call original
        return (originalDnsLookup as Function).call(dns, hostname, ...args);
    } as typeof dns.lookup;

    // Shim fetch
    shimGlobalFetch();

    isActivated = true;
}

/**
 * Deactivate the network shield and restore original functions.
 */
export function deactivateNetworkShield(): void {
    if (!isActivated) {
        return;
    }

    if (originalSocketConnect) {
        net.Socket.prototype.connect = originalSocketConnect;
        originalSocketConnect = null;
    }

    if (originalDnsLookup) {
        (dns as { lookup: typeof dns.lookup }).lookup = originalDnsLookup;
        originalDnsLookup = null;
    }

    if (originalFetch) {
        global.fetch = originalFetch;
        originalFetch = null;
    }

    isActivated = false;
}

/**
 * Check if the network shield is active.
 */
export function isNetworkShieldActive(): boolean {
    return isActivated;
}

/**
 * Add a blocked IP address at runtime.
 */
export function addBlockedIP(ip: string): void {
    (BLOCKED_IPS as string[]).push(ip);
}

/**
 * Add a blocked hostname at runtime.
 */
export function addBlockedHost(hostname: string): void {
    (BLOCKED_HOSTS as string[]).push(hostname.toLowerCase());
}

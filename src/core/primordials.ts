/**
 * ReqGuard Primordials Protection
 * Locks down dangerous JavaScript primitives: eval and Function constructor.
 * Zero-dependency runtime security.
 */

import { SecurityError } from './SecurityError';

// Store original primitives for restoration
let originalEval: typeof eval | null = null;
let originalFunction: FunctionConstructor | null = null;
let isLocked = false;

/**
 * Locked eval replacement that always throws SecurityError.
 */
function lockedEval(_code: string): never {
    throw new SecurityError('eval() is disabled by security policy');
}

/**
 * Locked Function constructor replacement.
 * Prevents dynamic code generation via new Function().
 */
function LockedFunction(..._args: string[]): never {
    throw new SecurityError('Function constructor is disabled by security policy');
}

// Make LockedFunction look like Function
Object.defineProperty(LockedFunction, 'name', { value: 'Function' });
Object.defineProperty(LockedFunction, 'length', { value: 1 });

/**
 * Lock down dangerous JavaScript primordials.
 * After calling this:
 * - eval('code') throws SecurityError
 * - new Function('code') throws SecurityError
 * - Function('code') throws SecurityError
 */
export function lockdownPrimordials(): void {
    if (isLocked) {
        return; // Already locked
    }

    // Store originals
    originalEval = globalThis.eval;
    originalFunction = globalThis.Function;

    // Replace eval
    Object.defineProperty(globalThis, 'eval', {
        value: lockedEval,
        writable: false,
        configurable: true, // Allow restore
    });

    // Replace Function constructor
    // This is tricky because Function is used internally
    // We need to make it throw only when called directly
    const FunctionProxy = new Proxy(LockedFunction as unknown as FunctionConstructor, {
        construct(_target, _args): never {
            throw new SecurityError('Function constructor is disabled by security policy');
        },
        apply(_target, _thisArg, _args): never {
            throw new SecurityError('Function constructor is disabled by security policy');
        },
        get(target, prop, receiver) {
            // Allow access to Function.prototype for instanceof checks
            if (prop === 'prototype') {
                return originalFunction!.prototype;
            }
            return Reflect.get(target, prop, receiver);
        },
    });

    Object.defineProperty(globalThis, 'Function', {
        value: FunctionProxy,
        writable: false,
        configurable: true,
    });

    isLocked = true;
}

/**
 * Restore original primordials.
 * Useful for testing or controlled environments.
 */
export function restorePrimordials(): void {
    if (!isLocked || !originalEval || !originalFunction) {
        return;
    }

    Object.defineProperty(globalThis, 'eval', {
        value: originalEval,
        writable: true,
        configurable: true,
    });

    Object.defineProperty(globalThis, 'Function', {
        value: originalFunction,
        writable: true,
        configurable: true,
    });

    originalEval = null;
    originalFunction = null;
    isLocked = false;
}

/**
 * Check if primordials are currently locked.
 */
export function arePrimordialsLocked(): boolean {
    return isLocked;
}

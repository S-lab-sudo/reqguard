import { describe, it, expect, afterEach, vi, beforeEach } from 'vitest';
import reqguard, { init, shutdown, isActive } from '../../src/index';
import path from 'path';
import fs from 'fs';

describe('reqguard Integration', () => {
    beforeEach(() => {
        // Ensure clean state
        shutdown();
    });

    afterEach(() => {
        shutdown();
        vi.restoreAllMocks();
    });

    describe('Initialization', () => {
        it('should initialize and become active', () => {
            expect(isActive()).toBe(false);
            init({ logging: { level: 'silent' } });
            expect(isActive()).toBe(true);
        });

        it('should shutdown and become inactive', () => {
            init({ logging: { level: 'silent' } });
            expect(isActive()).toBe(true);
            shutdown();
            expect(isActive()).toBe(false);
        });
    });

    describe('Test 1: Block Rule', () => {
        it('should block packages on the blocklist and throw error', () => {
            init({
                mode: 'enforce',
                packages: {
                    allow: [],
                    block: [{ name: 'path', reason: 'Blocked for testing' }],
                    warn: [],
                },
                builtins: {
                    allow: false, // Treat built-ins as regular packages for this test
                    restricted: [],
                },
                logging: { level: 'silent' },
            });

            expect(() => require('path')).toThrow('[reqguard] Blocked');
        });
    });

    describe('Test 2: Allow Rule', () => {
        it('should allow packages on the allowlist', () => {
            init({
                mode: 'enforce',
                packages: {
                    allow: [{ name: 'events' }],
                    block: [],
                    warn: [],
                },
                builtins: {
                    allow: false, // Disable default built-in allow
                    restricted: [],
                },
                logging: { level: 'silent' },
            });

            // 'events' is explicitly allowed, so should work
            expect(() => require('events')).not.toThrow();
        });
    });

    describe('Test 3: Wildcard Pattern', () => {
        it('should block node:* prefixed modules with wildcard', () => {
            init({
                mode: 'enforce',
                packages: {
                    allow: [],
                    block: [{ name: 'node:*', reason: 'Block all node: prefixed' }],
                    warn: [],
                },
                builtins: {
                    allow: false, // Important: disable built-in handling to test as package
                    restricted: [],
                },
                logging: { level: 'silent' },
            });

            expect(() => require('node:fs')).toThrow('[reqguard] Blocked');
            expect(() => require('node:path')).toThrow('[reqguard] Blocked');
        });
    });

    describe('Test 4: Warn Mode', () => {
        it('should NOT throw in warn mode, but log warning', () => {
            const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => { });
            const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => { });

            init({
                mode: 'warn', // Warn mode - log but don't throw
                packages: {
                    allow: [],
                    block: [{ name: 'os', reason: 'Blocked but warn only' }],
                    warn: [],
                },
                builtins: {
                    allow: false,
                    restricted: [],
                },
                logging: { level: 'error' }, // Enable error logging to see the block message
            });

            // Should NOT throw in warn mode
            expect(() => require('os')).not.toThrow();

            // Should have logged the block (as error log since it's a block action)
            expect(errorSpy).toHaveBeenCalled();
        });
    });

    describe('Test 5: Relative Imports', () => {
        it('should allow relative imports by default', () => {
            init({
                mode: 'enforce',
                logging: { level: 'silent' },
            });

            // Create a temporary test to verify relative imports are handled
            // We can't actually require a non-existent file, but we can verify
            // the policy engine returns 'allow' for relative paths
            const engine = reqguard.getEngine();
            expect(engine).not.toBeNull();

            const decision = engine!.evaluate('./some-local-module', '/project/some-local-module.js');
            expect(decision.action).toBe('allow');
            expect(decision.reason).toContain('Relative import');
        });
    });

    describe('Restricted Built-ins', () => {
        it('should allow most built-ins but block restricted ones', () => {
            init({
                mode: 'enforce',
                builtins: {
                    allow: true,
                    restricted: ['child_process', 'vm'],
                },
                logging: { level: 'silent' },
            });

            // Normal built-ins should work
            expect(() => require('fs')).not.toThrow();
            expect(() => require('path')).not.toThrow();

            // Restricted built-ins should be blocked
            expect(() => require('child_process')).toThrow('[reqguard] Blocked');
            expect(() => require('vm')).toThrow('[reqguard] Blocked');
        });
    });

    describe('Default Export', () => {
        it('should work with default export', () => {
            reqguard.init({ logging: { level: 'silent' } });
            expect(reqguard.isActive()).toBe(true);
            reqguard.shutdown();
            expect(reqguard.isActive()).toBe(false);
        });
    });

    describe('Unknown Packages (Analyze Action)', () => {
        it('should allow unknown packages with "analyze" decision (MVP behavior)', () => {
            init({
                mode: 'enforce',
                packages: {
                    allow: [],
                    block: [],
                    warn: [],
                },
                logging: { level: 'silent' },
            });

            // Built-ins are allowed by default
            // Unknown packages get 'analyze' which in MVP means 'allow with log'
            const engine = reqguard.getEngine();
            const decision = engine!.evaluate('some-random-package', '/node_modules/some-random-package/index.js');
            expect(decision.action).toBe('analyze');
        });
    });
});

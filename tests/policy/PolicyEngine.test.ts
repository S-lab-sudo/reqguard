import { describe, it, expect, beforeEach } from 'vitest';
import { PolicyEngine } from '../../src/policy/PolicyEngine';

describe('PolicyEngine', () => {
    describe('Built-in Modules', () => {
        it('should allow built-in modules by default', () => {
            const engine = new PolicyEngine();

            const decision = engine.evaluate('fs', '/internal/fs');
            expect(decision.action).toBe('allow');
            expect(decision.reason).toBe('Built-in module');
        });

        it('should allow node: prefixed built-ins', () => {
            const engine = new PolicyEngine();

            const decision = engine.evaluate('node:path', '/internal/path');
            expect(decision.action).toBe('allow');
        });

        it('should block restricted built-ins', () => {
            const engine = new PolicyEngine({
                builtins: {
                    allow: true,
                    restricted: ['child_process', 'vm'],
                },
            });

            const decision = engine.evaluate('child_process', '/internal/child_process');
            expect(decision.action).toBe('block');
            expect(decision.reason).toContain('restricted');
        });

        it('should block all built-ins when disabled', () => {
            const engine = new PolicyEngine({
                builtins: {
                    allow: false,
                    restricted: [],
                },
            });

            const decision = engine.evaluate('fs', '/internal/fs');
            expect(decision.action).toBe('block');
        });
    });

    describe('Blocklist', () => {
        it('should block packages on the blocklist', () => {
            const engine = new PolicyEngine({
                packages: {
                    allow: [],
                    block: [{ name: 'malicious-pkg', reason: 'Known malware' }],
                    warn: [],
                },
            });

            const decision = engine.evaluate('malicious-pkg', '/node_modules/malicious-pkg/index.js');
            expect(decision.action).toBe('block');
            expect(decision.reason).toBe('Known malware');
        });

        it('should support wildcard patterns in blocklist', () => {
            const engine = new PolicyEngine({
                packages: {
                    allow: [],
                    block: [{ name: 'event-stream*' }],
                    warn: [],
                },
            });

            expect(engine.evaluate('event-stream', '').action).toBe('block');
            expect(engine.evaluate('event-stream-fork', '').action).toBe('block');
            expect(engine.evaluate('other-stream', '').action).toBe('analyze'); // Not matched
        });

        it('should support scoped package wildcards', () => {
            const engine = new PolicyEngine({
                packages: {
                    allow: [],
                    block: [{ name: '@malicious/*' }],
                    warn: [],
                },
            });

            expect(engine.evaluate('@malicious/foo', '').action).toBe('block');
            expect(engine.evaluate('@malicious/bar', '').action).toBe('block');
            expect(engine.evaluate('@safe/foo', '').action).toBe('analyze');
        });
    });

    describe('Allowlist', () => {
        it('should allow packages on the allowlist', () => {
            const engine = new PolicyEngine({
                packages: {
                    allow: [{ name: 'lodash' }],
                    block: [],
                    warn: [],
                },
            });

            const decision = engine.evaluate('lodash', '/node_modules/lodash/index.js');
            expect(decision.action).toBe('allow');
        });

        it('blocklist should take priority over allowlist', () => {
            const engine = new PolicyEngine({
                packages: {
                    allow: [{ name: 'compromised-pkg' }],
                    block: [{ name: 'compromised-pkg', reason: 'Later found to be malicious' }],
                    warn: [],
                },
            });

            const decision = engine.evaluate('compromised-pkg', '');
            expect(decision.action).toBe('block');
        });
    });

    describe('Warnlist', () => {
        it('should warn on packages in the warnlist', () => {
            const engine = new PolicyEngine({
                packages: {
                    allow: [],
                    block: [],
                    warn: [{ name: 'risky-pkg', reason: 'Needs security review' }],
                },
            });

            const decision = engine.evaluate('risky-pkg', '');
            expect(decision.action).toBe('warn');
            expect(decision.reason).toBe('Needs security review');
        });
    });

    describe('Relative Imports', () => {
        it('should allow relative imports by default (analysis disabled)', () => {
            const engine = new PolicyEngine();

            expect(engine.evaluate('./foo', '/project/foo.js').action).toBe('allow');
            expect(engine.evaluate('../bar', '/project/bar.js').action).toBe('allow');
        });

        it('should pass relative imports to analysis when enabled', () => {
            const engine = new PolicyEngine({
                relativeImports: { analyze: true },
            });

            const decision = engine.evaluate('./foo', '/project/foo.js');
            expect(decision.action).toBe('analyze');
        });
    });

    describe('Package Name Extraction', () => {
        it('should extract package name from subpath imports', () => {
            const engine = new PolicyEngine({
                packages: {
                    allow: [],
                    block: [{ name: 'lodash' }],
                    warn: [],
                },
            });

            // 'lodash/get' should be blocked because 'lodash' is blocked
            const decision = engine.evaluate('lodash/get', '/node_modules/lodash/get.js');
            expect(decision.action).toBe('block');
        });

        it('should handle scoped packages with subpaths', () => {
            const engine = new PolicyEngine({
                packages: {
                    allow: [],
                    block: [{ name: '@babel/core' }],
                    warn: [],
                },
            });

            const decision = engine.evaluate('@babel/core/lib/transform', '');
            expect(decision.action).toBe('block');
        });
    });

    describe('Default Behavior', () => {
        it('should return "analyze" for unknown packages', () => {
            const engine = new PolicyEngine();

            const decision = engine.evaluate('some-unknown-pkg', '');
            expect(decision.action).toBe('analyze');
            expect(decision.reason).toContain('No explicit rule');
        });
    });
});

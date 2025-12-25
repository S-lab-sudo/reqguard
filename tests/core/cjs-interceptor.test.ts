import { describe, it, expect, afterEach, vi } from 'vitest';
import { hookRequire, restoreRequire } from '../../src/core/cjs-interceptor';

describe('CJS Interceptor Core', () => {
    afterEach(() => {
        restoreRequire();
        vi.restoreAllMocks();
    });

    it('should allow normal require execution for built-ins', () => {
        hookRequire();
        const fs = require('fs');
        expect(fs.existsSync).toBeDefined();
    });

    it('should intercept require calls and trigger analyzer', () => {
        const analyzeSpy = vi.fn();
        hookRequire(analyzeSpy);

        require('fs'); // Trigger require

        expect(analyzeSpy).toHaveBeenCalledTimes(1);
        expect(analyzeSpy).toHaveBeenCalledWith('fs', expect.any(String));
    });

    it('should block execution when analyzer throws a Blocked error', () => {
        hookRequire((id) => {
            if (id === 'path') {
                throw new Error('[reqguard] Blocked: path is not allowed');
            }
        });

        // 'fs' should be fine
        expect(() => require('fs')).not.toThrow();

        // 'path' should throw
        expect(() => require('path')).toThrow('[reqguard] Blocked: path is not allowed');
    });

    it('should restore original require functionality', () => {
        const analyzeSpy = vi.fn();
        hookRequire(analyzeSpy);

        restoreRequire();

        require('fs');
        expect(analyzeSpy).not.toHaveBeenCalled();
    });

    it('should handle recursion by skipping analysis for internal requires', () => {
        const analyzeSpy = vi.fn((id) => {
            // This simulate an analyzer that requires something
            if (id === 'fs') require('path');
        });

        hookRequire(analyzeSpy);

        require('fs');

        // Should be called for 'fs'
        expect(analyzeSpy).toHaveBeenCalledWith('fs', expect.any(String));

        // But NOT for 'path' because it happened INSIDE the analysis of 'fs' (recursion guard)
        expect(analyzeSpy).not.toHaveBeenCalledWith('path', expect.any(String));
    });
});

import Module from 'module';

let originalRequire: ((id: string) => any) | null = null;
let isHooked = false;
let isAnalyzing = false;

export type AnalyzeFunction = (id: string, resolvedPath: string) => void;

// Default no-op analyzer
let globalAnalyzer: AnalyzeFunction = () => { };

/**
 * Hook into Node.js Module.prototype.require using a proxy.
 * @param analyzer Optional callback to analyze the module before loading.
 */
export function hookRequire(analyzer?: AnalyzeFunction) {
    if (isHooked) {
        if (analyzer) globalAnalyzer = analyzer;
        return;
    }

    if (analyzer) {
        globalAnalyzer = analyzer;
    }

    originalRequire = Module.prototype.require;

    Module.prototype.require = function (this: Module, id: string): any {
        // Recursion guard: prevent infinite loops if the analyzer itself uses require
        if (isAnalyzing) {
            return originalRequire!.call(this, id);
        }

        try {
            // Use internal helper to resolve the filename without loading it
            // _resolveFilename(request, parent, isMain, options)
            // Note: This matches Node.js behavior to resolve specific paths
            const resolvedPath = (Module as any)._resolveFilename(id, this, false);

            isAnalyzing = true;
            try {
                globalAnalyzer(id, resolvedPath);
            } finally {
                isAnalyzing = false;
            }
        } catch (error: any) {
            // If it's a security block, rethrow it to stop loading
            if (error instanceof Error && error.message.startsWith('[reqguard] Blocked')) {
                throw error;
            }
            // If resolution fails (e.g. module not found), let originalRequire handle the error
            // Or if the analyzer crashes unexpectedly, we might want to fail open or closed.
            // For MVP, we pass through resolution errors (they will be thrown again by originalRequire)
        }

        return originalRequire!.call(this, id);
    } as any;

    isHooked = true;
}

/**
 * Restore the original require function.
 * Useful for cleanup in tests.
 */
export function restoreRequire() {
    if (isHooked && originalRequire) {
        Module.prototype.require = originalRequire;
        originalRequire = null;
        isHooked = false;
    }
}

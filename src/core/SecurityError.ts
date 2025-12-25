/**
 * ReqGuard Security Error
 * Custom error class for security violations.
 */
export class SecurityError extends Error {
    public readonly code: string = 'ERR_SECURITY_VIOLATION';
    public readonly blocked: boolean = true;

    constructor(message: string) {
        super(`[reqguard] Security Violation: ${message}`);
        this.name = 'SecurityError';
        // Maintain proper stack trace in V8 engines
        if (Error.captureStackTrace) {
            Error.captureStackTrace(this, SecurityError);
        }
    }
}

/**
 * ReqGuard Typosquatting Detection
 * Detects potential typosquatting attacks by comparing package names
 * against the Top 100 NPM packages using Levenshtein distance.
 * 
 * Zero-dependency runtime security.
 */

import { levenshtein, isSimilar } from '../utils/levenshtein';

/**
 * Top 100 most popular NPM packages (hardcoded for zero-dependency).
 * Source: npm download statistics.
 * Last updated: Dec 2024
 */
const TOP_100_NPM_PACKAGES: readonly string[] = Object.freeze([
    // Top tier (billions of downloads)
    'lodash',
    'chalk',
    'request',
    'commander',
    'react',
    'express',
    'moment',
    'axios',
    'bluebird',
    'debug',
    'async',
    'uuid',
    'underscore',
    'mkdirp',
    'glob',
    'yargs',
    'minimist',
    'semver',
    'colors',
    'fs-extra',

    // High tier
    'inquirer',
    'body-parser',
    'webpack',
    'typescript',
    'eslint',
    'babel-core',
    'prop-types',
    'classnames',
    'rxjs',
    'jquery',
    'rimraf',
    'tslib',
    'cheerio',
    'dotenv',
    'qs',
    'ora',
    'execa',
    'yup',
    'ramda',
    'winston',

    // Mid tier
    'vue',
    'react-dom',
    'next',
    'mongoose',
    'socket.io',
    'nodemon',
    'pm2',
    'prettier',
    'jest',
    'mocha',
    'chai',
    'sinon',
    'supertest',
    'passport',
    'bcrypt',
    'jsonwebtoken',
    'cors',
    'helmet',
    'multer',
    'nodemailer',

    // Additional popular packages
    'lodash-es',
    'date-fns',
    'dayjs',
    'immutable',
    'redux',
    'mobx',
    'formik',
    'yup',
    'zod',
    'ajv',
    'nanoid',
    'shortid',
    'crypto-js',
    'argon2',
    'bcryptjs',
    'cookie-parser',
    'express-session',
    'morgan',
    'compression',
    'serve-static',

    // Build tools & utilities
    'esbuild',
    'rollup',
    'vite',
    'parcel',
    'gulp',
    'grunt',
    'npm',
    'yarn',
    'pnpm',
    'lerna',
    'nx',
    'husky',
    'lint-staged',
    'commitlint',

    // Testing
    'cypress',
    'playwright',
    'puppeteer',
    'enzyme',
]);

// Convert to Set for O(1) exact match lookup
const TOP_100_SET = new Set(TOP_100_NPM_PACKAGES);

/** Threshold for typosquatting detection (distance <= 2 triggers warning) */
const TYPOSQUAT_THRESHOLD = 3;

/** Result of typosquatting check */
export interface TyposquatResult {
    /** Whether the package is potentially a typosquat */
    isSuspicious: boolean;
    /** The original package being checked */
    packageName: string;
    /** Similar packages found (if suspicious) */
    similarPackages: Array<{
        name: string;
        distance: number;
    }>;
    /** Warning message (if suspicious) */
    warning?: string;
}

/**
 * Check if a package name might be a typosquat of a popular package.
 * 
 * @param packageName The package name to check
 * @returns Typosquat check result
 */
export function checkTyposquat(packageName: string): TyposquatResult {
    // FAST PATH: Exact match with popular package - not a typosquat
    if (TOP_100_SET.has(packageName)) {
        return {
            isSuspicious: false,
            packageName,
            similarPackages: [],
        };
    }

    // FAST PATH: Very short or very long names - less likely to be typosquats
    if (packageName.length < 2 || packageName.length > 50) {
        return {
            isSuspicious: false,
            packageName,
            similarPackages: [],
        };
    }

    // Check against all top packages
    const similarPackages: TyposquatResult['similarPackages'] = [];

    for (const popularPkg of TOP_100_NPM_PACKAGES) {
        // FAST PATH: Skip if length difference is too large
        if (Math.abs(packageName.length - popularPkg.length) > TYPOSQUAT_THRESHOLD) {
            continue;
        }

        // Calculate distance
        const distance = levenshtein(packageName.toLowerCase(), popularPkg.toLowerCase());

        // If distance is small but not zero (exact match), it's suspicious
        if (distance > 0 && distance < TYPOSQUAT_THRESHOLD) {
            similarPackages.push({
                name: popularPkg,
                distance,
            });
        }
    }

    // Sort by distance (closest first)
    similarPackages.sort((a, b) => a.distance - b.distance);

    if (similarPackages.length > 0) {
        const topMatch = similarPackages[0];
        return {
            isSuspicious: true,
            packageName,
            similarPackages,
            warning: `Package '${packageName}' is similar to '${topMatch.name}' (distance: ${topMatch.distance}). Possible typosquatting attempt!`,
        };
    }

    return {
        isSuspicious: false,
        packageName,
        similarPackages: [],
    };
}

/**
 * Log a warning if the package appears to be a typosquat.
 * Returns true if warning was logged.
 */
export function warnIfTyposquat(packageName: string): boolean {
    const result = checkTyposquat(packageName);

    if (result.isSuspicious && result.warning) {
        console.warn(`[reqguard] ⚠️  TYPOSQUAT WARNING: ${result.warning}`);
        return true;
    }

    return false;
}

/**
 * Get the list of popular packages being checked against.
 */
export function getPopularPackages(): readonly string[] {
    return TOP_100_NPM_PACKAGES;
}

/**
 * Check if a package name is in the popular packages list.
 */
export function isPopularPackage(packageName: string): boolean {
    return TOP_100_SET.has(packageName);
}

// Re-export for convenience
export { levenshtein, isSimilar };

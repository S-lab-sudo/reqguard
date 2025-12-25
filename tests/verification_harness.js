/**
 * ReqGuard Verification Harness
 * Tests all security shields by attempting to exploit each vector.
 * Each test should throw SecurityError to prove the shield works.
 * 
 * Run with: node tests/verification_harness.js
 */

'use strict';

// We need to compile TypeScript first, so we use the dist output
const path = require('path');
const distPath = path.join(__dirname, '..', 'dist');

let reqguard;
let SecurityError;

try {
    reqguard = require(distPath);
    SecurityError = reqguard.SecurityError;
} catch (error) {
    console.error('❌ Failed to load reqguard. Make sure to run `npm run build` first.');
    console.error('Error:', error.message);
    process.exit(1);
}

// Test results tracking
const results = {
    passed: 0,
    failed: 0,
    tests: []
};

/**
 * Run a test case that should throw SecurityError.
 */
function testShouldThrow(name, fn) {
    process.stdout.write(`Testing: ${name}... `);
    try {
        fn();
        console.log('❌ FAILED (no error thrown)');
        results.failed++;
        results.tests.push({ name, passed: false, reason: 'No error thrown' });
    } catch (error) {
        if (error.name === 'SecurityError' || error.message.includes('[reqguard]')) {
            console.log('✅ PASSED');
            results.passed++;
            results.tests.push({ name, passed: true });
        } else {
            console.log(`❌ FAILED (wrong error: ${error.message})`);
            results.failed++;
            results.tests.push({ name, passed: false, reason: error.message });
        }
    }
}

/**
 * Run an async test case that should throw SecurityError.
 */
async function testShouldThrowAsync(name, fn) {
    process.stdout.write(`Testing: ${name}... `);
    try {
        await fn();
        console.log('❌ FAILED (no error thrown)');
        results.failed++;
        results.tests.push({ name, passed: false, reason: 'No error thrown' });
    } catch (error) {
        if (error.name === 'SecurityError' || error.message.includes('[reqguard]')) {
            console.log('✅ PASSED');
            results.passed++;
            results.tests.push({ name, passed: true });
        } else {
            console.log(`❌ FAILED (wrong error: ${error.message})`);
            results.failed++;
            results.tests.push({ name, passed: false, reason: error.message });
        }
    }
}

/**
 * Run a test that should log a warning (for typosquatting).
 */
function testShouldWarn(name, fn) {
    process.stdout.write(`Testing: ${name}... `);

    // Capture console.warn
    const originalWarn = console.warn;
    let warned = false;
    console.warn = (msg) => {
        if (msg.includes('TYPOSQUAT') || msg.includes('reqguard')) {
            warned = true;
        }
        originalWarn.call(console, msg);
    };

    try {
        fn();
        if (warned) {
            console.log('✅ PASSED (warning logged)');
            results.passed++;
            results.tests.push({ name, passed: true });
        } else {
            console.log('❌ FAILED (no warning)');
            results.failed++;
            results.tests.push({ name, passed: false, reason: 'No warning logged' });
        }
    } catch (error) {
        console.log(`❌ FAILED (unexpected error: ${error.message})`);
        results.failed++;
        results.tests.push({ name, passed: false, reason: error.message });
    } finally {
        console.warn = originalWarn;
    }
}

/**
 * Main test suite.
 */
async function runTests() {
    console.log('\n🛡️  ReqGuard Verification Harness');
    console.log('================================\n');

    // Initialize ReqGuard with all shields enabled
    console.log('Initializing ReqGuard...');
    reqguard.init({
        mode: 'enforce',
        lockdownPrimordials: true,
        networkShield: true,
        fsShield: true,
        typosquatDetection: true,
        logLevel: 'warn'
    });
    console.log('ReqGuard initialized.\n');

    // ==========================================
    // TEST 1: Dangerous Built-in Blocking
    // ==========================================
    console.log('--- Test Category: Dangerous Built-ins ---\n');

    testShouldThrow('Block child_process require', () => {
        require('child_process');
    });

    testShouldThrow('Block node:child_process require', () => {
        require('node:child_process');
    });

    testShouldThrow('Block vm require', () => {
        require('vm');
    });

    testShouldThrow('Block worker_threads require', () => {
        require('worker_threads');
    });

    // ==========================================
    // TEST 2: Primordial Lockdown
    // ==========================================
    console.log('\n--- Test Category: Primordial Lockdown ---\n');

    testShouldThrow('Block eval()', () => {
        eval('1 + 1');
    });

    testShouldThrow('Block new Function()', () => {
        new Function('return 1')();
    });

    testShouldThrow('Block Function() call', () => {
        Function('return 1')();
    });

    // ==========================================
    // TEST 3: Network Shield
    // ==========================================
    console.log('\n--- Test Category: Network Shield ---\n');

    const net = require('net');

    testShouldThrow('Block connection to 169.254.169.254', () => {
        const socket = new net.Socket();
        socket.connect(80, '169.254.169.254');
    });

    testShouldThrow('Block connection to metadata endpoint (options)', () => {
        const socket = new net.Socket();
        socket.connect({ host: '169.254.169.254', port: 80 });
    });

    testShouldThrow('Block connection to ::ffff:169.254.169.254', () => {
        const socket = new net.Socket();
        socket.connect(80, '::ffff:169.254.169.254');
    });

    // DNS lookup test (async)
    const dns = require('dns');

    await testShouldThrowAsync('Block DNS lookup for metadata IP', () => {
        return new Promise((resolve, reject) => {
            dns.lookup('169.254.169.254', (err) => {
                if (err) reject(err);
                else resolve();
            });
        });
    });

    // Global fetch test (async)
    if (typeof global.fetch === 'function') {
        const url = 'http://169.254.169.254';
        await testShouldThrowAsync('Block fetch("' + url + '")', async () => {
            await fetch(url);
        });
    } else {
        console.log('Skipping fetch test (not available in this Node version)');
    }

    // ==========================================
    // TEST 4: Filesystem Shield
    // ==========================================
    console.log('\n--- Test Category: Filesystem Shield ---\n');

    const fs = require('fs');

    testShouldThrow('Block reading .env file', () => {
        fs.readFileSync('.env', 'utf8');
    });

    testShouldThrow('Block reading /etc/passwd', () => {
        fs.readFileSync('/etc/passwd', 'utf8');
    });

    testShouldThrow('Block reading .ssh/id_rsa', () => {
        fs.readFileSync(path.join(process.env.HOME || '/home/user', '.ssh/id_rsa'), 'utf8');
    });

    testShouldThrow('Block reading file with .pem extension', () => {
        fs.readFileSync('/path/to/secret.pem', 'utf8');
    });

    // Async fs.readFile
    await testShouldThrowAsync('Block async reading .env file', () => {
        return new Promise((resolve, reject) => {
            fs.readFile('.env', 'utf8', (err) => {
                if (err) reject(err);
                else resolve();
            });
        });
    });

    // fs.open
    testShouldThrow('Block fs.openSync on .env', () => {
        fs.openSync('.env', 'r');
    });

    // fs.promises test
    if (fs.promises) {
        await testShouldThrowAsync('Block fs.promises.readFile of .env', async () => {
            await fs.promises.readFile('.env', 'utf8');
        });
    }

    // ==========================================
    // TEST 5: Typosquatting Detection
    // ==========================================
    console.log('\n--- Test Category: Typosquatting Detection ---\n');

    // These should log warnings but not throw
    testShouldWarn('Detect "lodas" as typosquat of "lodash"', () => {
        reqguard.warnIfTyposquat('lodas');
    });

    testShouldWarn('Detect "reqest" as typosquat of "request"', () => {
        reqguard.warnIfTyposquat('reqest');
    });

    testShouldWarn('Detect "axois" as typosquat of "axios"', () => {
        reqguard.warnIfTyposquat('axois');
    });

    // ==========================================
    // RESULTS SUMMARY
    // ==========================================
    console.log('\n================================');
    console.log('📊 VERIFICATION RESULTS');
    console.log('================================');
    console.log(`✅ Passed: ${results.passed}`);
    console.log(`❌ Failed: ${results.failed}`);
    console.log(`📝 Total:  ${results.passed + results.failed}`);
    console.log('================================\n');

    if (results.failed > 0) {
        console.log('Failed tests:');
        results.tests.filter(t => !t.passed).forEach(t => {
            console.log(`  - ${t.name}: ${t.reason}`);
        });
        console.log('');
    }

    // Cleanup
    console.log('Shutting down ReqGuard...');
    reqguard.shutdown();
    console.log('Done.\n');

    // Exit with appropriate code
    process.exit(results.failed > 0 ? 1 : 0);
}

// Run tests
runTests().catch(error => {
    console.error('Unexpected error:', error);
    process.exit(1);
});

/**
 * ReqGuard v1.0.0 Demo Script
 * 
 * Demonstrates:
 * 1. Blocking dangerous built-ins (child_process) by default
 * 2. Blocking custom modules via blocklist (fs)
 * 3. Runtime reconfiguration
 * 
 * Run with: npx ts-node demo.ts
 */

import reqguard from './src/index';

console.log('🛡️  ReqGuard v1.0.0 Demo\n');
console.log('='.repeat(60));

// ==========================================
// SCENARIO 1: Secure Defaults + Custom Block
// ==========================================
console.log('📝 Configuring: Secure Defaults + Block "fs"');

reqguard.init({
    mode: 'enforce',
    logLevel: 'info',
    // dangerous built-ins (child_process, vm) are blocked by default
    allowDangerousBuiltins: false,
    // Explicitly block fs
    blocklist: ['fs'],
    // Enable all shields
    typosquatDetection: true,
    networkShield: true,
    fsShield: true
});

console.log('   - Mode: enforce');
console.log('   - Blocked: fs, child_process, vm, worker_threads\n');

// Test 1: Require 'fs' (Explicitly blocked)
console.log('🧪 Test 1: Require "fs" (Custom Blocklist)');
try {
    require('fs');
    console.log('❌ FAIL: fs was NOT blocked!');
} catch (error: any) {
    if (error.message.includes('[reqguard]')) {
        console.log('✅ SUCCESS: fs was blocked!');
        console.log(`   Error: ${error.message}\n`);
    } else {
        console.log('❌ FAIL: Unexpected error:', error.message);
    }
}

// Test 2: Require 'child_process' (Blocked by default)
console.log('🧪 Test 2: Require "child_process" (Secure Default)');
try {
    require('child_process');
    console.log('❌ FAIL: child_process was NOT blocked!');
} catch (error: any) {
    if (error.message.includes('Dangerous built-in')) {
        console.log('✅ SUCCESS: child_process was blocked!');
        console.log(`   Error: ${error.message}\n`);
    } else {
        console.log('❌ FAIL: Unexpected error:', error.message);
    }
}

// ==========================================
// SCENARIO 2: Reconfiguration
// ==========================================
console.log('🔄 Reconfiguring to ALLOW "fs"...\n');

// We can just call configure() to update settings
// Now that index.ts bug is fixed, this should work properly
reqguard.configure({
    blocklist: [], // Clear blocklist
    // fs is a standard built-in, so it's allowed if not blocked
});

// Test 3: Require 'fs' (Allowed)
console.log('🧪 Test 3: Require "fs" (Allowed)');
try {
    const fs = require('fs');
    if (fs.readFileSync) {
        console.log('✅ SUCCESS: fs loaded successfully!');
        console.log('   fs.readFileSync is available\n');
    }
} catch (error: any) {
    console.log('❌ FAIL: fs was blocked unexpectedly:', error.message);
}

// Cleanup
reqguard.shutdown();

console.log('='.repeat(60));
console.log('🏁 Demo complete!\n');

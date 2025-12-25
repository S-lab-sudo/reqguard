/**
 * reqguard Demo Script
 * 
 * This script demonstrates reqguard blocking a dangerous module.
 * Run with: npx ts-node demo.ts
 */

import reqguard from './src/index';

console.log('🛡️  reqguard Demo\n');
console.log('='.repeat(50));

// Initialize reqguard with a policy that blocks 'fs'
reqguard.init({
    mode: 'enforce',
    packages: {
        allow: [],
        block: [
            { name: 'fs', reason: 'File system access is restricted' },
            { name: 'child_process', reason: 'Process spawning is restricted' },
        ],
        warn: [],
    },
    builtins: {
        allow: false, // Disable default built-in allow to demonstrate blocking
        restricted: [],
    },
    logging: {
        level: 'info',
    },
});

console.log('\n📋 Policy configured:');
console.log('   - Blocked: fs, child_process');
console.log('   - Mode: enforce\n');

// Test 1: Try to require 'fs' (should be blocked)
console.log('🧪 Test 1: Attempting to require("fs")...');
try {
    require('fs');
    console.log('❌ FAIL: fs was NOT blocked!');
} catch (error: any) {
    if (error.message.includes('[reqguard] Blocked')) {
        console.log('✅ SUCCESS: fs was blocked!');
        console.log(`   Error: ${error.message}\n`);
    } else {
        console.log('❌ FAIL: Unexpected error:', error.message);
    }
}

// Test 2: Try to require 'child_process' (should be blocked)
console.log('🧪 Test 2: Attempting to require("child_process")...');
try {
    require('child_process');
    console.log('❌ FAIL: child_process was NOT blocked!');
} catch (error: any) {
    if (error.message.includes('[reqguard] Blocked')) {
        console.log('✅ SUCCESS: child_process was blocked!');
        console.log(`   Error: ${error.message}\n`);
    } else {
        console.log('❌ FAIL: Unexpected error:', error.message);
    }
}

// Shutdown and reconfigure to allow fs
console.log('🔄 Reconfiguring to ALLOW fs...\n');
reqguard.shutdown();

reqguard.init({
    mode: 'enforce',
    packages: {
        allow: [{ name: 'fs' }],
        block: [],
        warn: [],
    },
    builtins: {
        allow: false,
        restricted: [],
    },
    logging: {
        level: 'info',
    },
});

// Test 3: Now fs should work
console.log('🧪 Test 3: Attempting to require("fs") after allowing...');
try {
    const fs = require('fs');
    if (fs.existsSync) {
        console.log('✅ SUCCESS: fs loaded successfully!');
        console.log('   fs.existsSync is available\n');
    }
} catch (error: any) {
    console.log('❌ FAIL: fs was blocked unexpectedly:', error.message);
}

// Cleanup
reqguard.shutdown();

console.log('='.repeat(50));
console.log('🏁 Demo complete!\n');

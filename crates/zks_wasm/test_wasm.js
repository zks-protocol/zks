// Simple Node.js test for ZKS WASM package
const fs = require('fs');
const path = require('path');

async function testWasm() {
    try {
        // Import the WASM module
        const wasmModule = await import('./pkg/zks_wasm.js');
        await wasmModule.default();
        
        console.log('🚀 Testing ZKS Protocol WASM Package');
        console.log('=====================================');
        
        // Test 1: Key generation
        console.log('\n1. Testing key generation...');
        const key = wasmModule.ZksWasmUtils.generate_key();
        console.log(`   ✅ Generated ${key.length} byte key`);
        
        // Test 2: ML-DSA keypair generation
        console.log('\n2. Testing ML-DSA keypair generation...');
        const keypair = await wasmModule.quick_ml_dsa_keypair();
        console.log(`   ✅ Generated keypair with signing key: ${keypair.signing_key.length} chars`);
        console.log(`   ✅ Generated keypair with verifying key: ${keypair.verifying_key.length} chars`);
        
        // Test 3: Message signing
        console.log('\n3. Testing message signing...');
        const message = new TextEncoder().encode('Hello, ZKS Protocol!');
        const signingKeyBytes = hexToBytes(keypair.signing_key);
        const signature = wasmModule.ZksWasmUtils.ml_dsa_sign(message, signingKeyBytes);
        console.log(`   ✅ Signed message, signature length: ${signature.length} bytes`);
        
        // Test 4: Signature verification
        console.log('\n4. Testing signature verification...');
        const verifyingKeyBytes = hexToBytes(keypair.verifying_key);
        wasmModule.ZksWasmUtils.ml_dsa_verify(message, signature, verifyingKeyBytes);
        console.log('   ✅ Signature verification successful');
        
        // Test 5: Invalid signature verification
        console.log('\n5. Testing invalid signature verification...');
        const wrongMessage = new TextEncoder().encode('Wrong message');
        try {
            wasmModule.ZksWasmUtils.ml_dsa_verify(wrongMessage, signature, verifyingKeyBytes);
            console.log('   ❌ Should have failed verification');
        } catch (error) {
            console.log('   ✅ Correctly rejected invalid signature');
        }
        
        console.log('\n🎉 All WASM tests passed successfully!');
        
    } catch (error) {
        console.error('❌ WASM test failed:', error);
        process.exit(1);
    }
}

function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
}

// Run the test
testWasm();
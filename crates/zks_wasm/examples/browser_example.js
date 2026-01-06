// Example usage of ZKS Protocol WASM in browser
import init, { ZksProtocol, ZksUtils, quick_connect, quick_encrypt, quick_decrypt } from './pkg/zks_wasm.js';

async function runExample() {
    // Initialize the WASM module
    await init();
    
    console.log('ZKS Protocol WASM initialized');
    
    // Example 1: Quick connection
    try {
        const client = await quick_connect('zk://localhost:8080');
        console.log('Connected to ZKS server');
        
        // Send a message
        const message = new TextEncoder().encode('Hello from browser!');
        client.send(message);
        
        // Receive response
        const response = client.receive();
        if (response) {
            console.log('Received:', new TextDecoder().decode(response));
        }
        
        client.disconnect();
    } catch (error) {
        console.error('Connection failed:', error);
    }
    
    // Example 2: Using the high-level API
    try {
        const config = new ZksUtils.create_config('zk://localhost:8080')
            .with_security('postquantum')
            .with_auto_reconnect(true)
            .with_max_reconnect_attempts(5);
        
        const protocol = new ZksProtocol(config);
        await protocol.connect();
        
        console.log('Protocol state:', protocol.get_state());
        console.log('Is connected:', protocol.is_connected());
        
        // Send encrypted message
        const key = new Uint8Array(32);
        crypto.getRandomValues(key);
        
        const plaintext = new TextEncoder().encode('Secret message');
        const encrypted = quick_encrypt(plaintext, key);
        
        protocol.send(encrypted);
        
        // Receive and decrypt
        const encrypted_response = protocol.receive();
        if (encrypted_response) {
            const decrypted = quick_decrypt(encrypted_response, key);
            console.log('Decrypted:', new TextDecoder().decode(decrypted));
        }
        
        protocol.disconnect();
    } catch (error) {
        console.error('Protocol error:', error);
    }
    
    // Example 3: Utility functions
    console.log('ZKS Utils version:', ZksUtils.get_version());
    console.log('Supported security levels:', ZksUtils.get_supported_security_levels());
    
    const zkUrl = 'zk://example.com:8080';
    const wsUrl = ZksUtils.convert_to_websocket_url(zkUrl);
    console.log('Converted URL:', wsUrl);
    
    console.log('Is valid URL:', ZksUtils.validate_url(zkUrl));
}

// Run the example when the page loads
window.addEventListener('load', runExample);
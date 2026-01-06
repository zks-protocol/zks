ZKS Protocol SDK - Implementation Roadmap
Created: January 6, 2026
Current Status: Alpha Ready
Target: Production Release

Phase Overview
Phase	Focus	Duration	Priority
1	Testing & Verification	2 days	🔴 Critical
2	Real STUN/NAT Implementation	3 days	🟠 High
3	Swarm Onion Routing	5 days	🟠 High
4	Browser/WASM Support	5 days	🟡 Medium
5	Production Release	3 days	🔴 Critical
Total Estimated Time: ~3 weeks

Phase 1: Testing & Verification (2 days)
1.1 Unit Tests
[MODIFY] zks_sdk/src/lib.rs
Add comprehensive test module:

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_zk_connection_builder() {
        let result = ZkConnection::builder()
            .url("zk://localhost:8080")
            .security(SecurityLevel::PostQuantum)
            .build()
            .await;
        // Assert connection or expected error
    }
    
    #[tokio::test]
    async fn test_encryption_roundtrip() {
        let key = [0u8; 32];
        let mut cipher = WasifVernam::new(key);
        let plaintext = b"Hello, quantum world!";
        let encrypted = cipher.encrypt(plaintext).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }
}
[NEW] tests/integration_tests.rs
#[tokio::test]
async fn test_full_handshake() {
    // Spawn server, connect client, verify handshake completes
}
#[tokio::test]
async fn test_file_transfer() {
    // Transfer file, verify integrity with SHA256
}
1.2 Build Verification
cargo check --workspace
cargo test --workspace
cargo clippy --workspace
cargo doc --workspace --no-deps
Phase 2: Real STUN/NAT Implementation (3 days)
2.1 Fix STUN Response Parsing
[MODIFY] zks_wire/src/stun.rs
fn parse_binding_response(&self, response: &[u8]) -> Result<SocketAddr> {
    // Parse STUN message header (20 bytes)
    if response.len() < 20 {
        return Err(WireError::InvalidMessage("STUN response too short"));
    }
    
    let msg_type = u16::from_be_bytes([response[0], response[1]]);
    if msg_type != 0x0101 {  // Binding Success Response
        return Err(WireError::InvalidMessage("Not a binding response"));
    }
    
    // Parse XOR-MAPPED-ADDRESS attribute
    let mut offset = 20;
    while offset + 4 < response.len() {
        let attr_type = u16::from_be_bytes([response[offset], response[offset+1]]);
        let attr_len = u16::from_be_bytes([response[offset+2], response[offset+3]]) as usize;
        
        if attr_type == 0x0020 {  // XOR-MAPPED-ADDRESS
            return self.parse_xor_mapped_address(&response[offset+4..offset+4+attr_len]);
        }
        offset += 4 + attr_len;
    }
    
    Err(WireError::InvalidMessage("No XOR-MAPPED-ADDRESS found"))
}
fn parse_xor_mapped_address(&self, data: &[u8]) -> Result<SocketAddr> {
    let family = data[1];
    let xor_port = u16::from_be_bytes([data[2], data[3]]) ^ 0x2112;
    
    match family {
        0x01 => {  // IPv4
            let xor_addr = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) ^ 0x2112A442;
            let ip = Ipv4Addr::from(xor_addr);
            Ok(SocketAddr::V4(SocketAddrV4::new(ip, xor_port)))
        }
        0x02 => {  // IPv6
            // Handle IPv6 XOR with transaction ID
            todo!("IPv6 support")
        }
        _ => Err(WireError::InvalidMessage("Unknown address family"))
    }
}
2.2 Fix NAT Type Detection
[MODIFY] zks_wire/src/nat.rs
pub async fn discover_nat_type(&mut self) -> Result<NatType> {
    // Test 1: Basic connectivity
    let addr1 = self.stun_client.discover("stun.l.google.com:19302").await?;
    
    // Test 2: Different server
    let addr2 = self.stun_client.discover("stun1.l.google.com:19302").await?;
    
    // Test 3: Different port on same server
    let addr3 = self.stun_client.discover("stun.l.google.com:3478").await?;
    
    self.nat_type = if addr1.ip() != addr2.ip() {
        NatType::Symmetric  // Different IPs = symmetric NAT
    } else if addr1.port() != addr3.port() {
        NatType::PortRestricted
    } else {
        NatType::FullCone
    };
    
    Ok(self.nat_type)
}
Phase 3: Swarm Onion Routing (5 days)
3.1 Circuit Building
[NEW] zks_wire/src/circuit.rs
pub struct SwarmCircuit {
    pub entry_peer: PeerId,
    pub middle_peers: Vec<PeerId>,
    pub exit_peer: PeerId,
    pub layer_keys: Vec<[u8; 32]>,  // One key per hop
}
impl SwarmCircuit {
    pub async fn build(swarm: &Swarm, min_hops: u8) -> Result<Self> {
        let peers = swarm.discover_peers(min_hops as usize + 2).await?;
        
        // Entry = first peer
        // Exit = last peer
        // Middle = everything between
        
        let mut layer_keys = Vec::new();
        for peer in &peers {
            let key = MlKem::key_exchange_with(peer).await?;
            layer_keys.push(key);
        }
        
        Ok(Self {
            entry_peer: peers[0].id.clone(),
            middle_peers: peers[1..peers.len()-1].iter().map(|p| p.id.clone()).collect(),
            exit_peer: peers.last().unwrap().id.clone(),
            layer_keys,
        })
    }
    
    pub fn onion_encrypt(&self, data: &[u8]) -> Vec<u8> {
        let mut encrypted = data.to_vec();
        // Encrypt in reverse order (exit first, entry last)
        for key in self.layer_keys.iter().rev() {
            let cipher = WasifVernam::new(*key);
            encrypted = cipher.encrypt(&encrypted).unwrap();
        }
        encrypted
    }
}
3.2 ZKS Connection Updates
[MODIFY] zks_sdk/src/connection/zks.rs
pub struct ZksConnection {
    circuit: SwarmCircuit,
    stream: EncryptedStream<TcpStream>,
    config: ConnectionConfig,
}
impl ZksConnection {
    pub async fn connect(url: String, config: ConnectionConfig, min_hops: u8, max_hops: u8) -> Result<Self> {
        // Build circuit through swarm
        let swarm = Swarm::new("zks-network".to_string());
        let circuit = SwarmCircuit::build(&swarm, min_hops).await?;
        
        // Connect to entry node
        let stream = TcpStream::connect(&circuit.entry_peer.addr).await?;
        let encrypted_stream = EncryptedStream::handshake(stream, &config, true).await?;
        
        Ok(Self { circuit, stream: encrypted_stream, config })
    }
    
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        // Onion encrypt: [[[ data ]_exit]_middle]_entry
        let onion_data = self.circuit.onion_encrypt(data);
        self.stream.write_all(&onion_data).await?;
        Ok(())
    }
}
Phase 4: Browser/WASM Support (5 days)
4.1 Create WASM Package
[NEW] crates/zks_wasm/Cargo.toml
[package]
name = "zks_wasm"
version = "0.1.0"
edition = "2021"
[lib]
crate-type = ["cdylib", "rlib"]
[dependencies]
zks_sdk = { path = "../zks_sdk" }
wasm-bindgen = "0.2"
wasm-bindgen-futures = "0.4"
js-sys = "0.3"
web-sys = { version = "0.3", features = ["WebSocket", "MessageEvent"] }
console_error_panic_hook = "0.1"
[profile.release]
opt-level = "s"
lto = true
[NEW] crates/zks_wasm/src/lib.rs
use wasm_bindgen::prelude::*;
#[wasm_bindgen]
pub struct ZkClient {
    // WebSocket-based connection for browser
}
#[wasm_bindgen]
impl ZkClient {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        console_error_panic_hook::set_once();
        Self {}
    }
    
    #[wasm_bindgen]
    pub async fn connect(&mut self, url: &str) -> Result<(), JsValue> {
        // Connect via WebSocket with ZK handshake
        Ok(())
    }
    
    #[wasm_bindgen]
    pub async fn send(&mut self, data: &[u8]) -> Result<(), JsValue> {
        // Encrypt and send
        Ok(())
    }
}
4.2 Build & Publish
cd crates/zks_wasm
wasm-pack build --target web --release
wasm-pack publish
Phase 5: Production Release (3 days)
5.1 Documentation
File	Content
README.md	Quick start, features, examples
SECURITY.md	Security model, threat analysis
CHANGELOG.md	Version history
examples/	Working code samples
5.2 Cargo.toml Polish
[package]
name = "zks_sdk"
version = "1.0.0"
edition = "2021"
authors = ["ZKS Protocol Team"]
description = "Quantum-proof encryption protocol SDK"
documentation = "https://docs.rs/zks_sdk"
homepage = "https://github.com/zks-protocol/zks-sdk"
repository = "https://github.com/zks-protocol/zks-sdk"
license = "MIT OR Apache-2.0"
keywords = ["post-quantum", "encryption", "cryptography", "security"]
categories = ["cryptography", "network-programming"]
5.3 Publish Checklist
 Run cargo publish --dry-run for all crates
 Add LICENSE-MIT and LICENSE-APACHE-2.0
 Create GitHub release with tag
 Submit IANA registration for zk:// and zks://
Task Tracking
[ ] Phase 1: Testing
    [ ] Unit tests for SDK
    [ ] Integration tests
    [ ] CI/CD setup
[ ] Phase 2: STUN/NAT  
    [ ] Real STUN parsing
    [ ] NAT type detection
    [ ] Hole punching
[ ] Phase 3: Swarm
    [ ] Circuit building
    [ ] Onion routing
    [ ] Exit node handling
[ ] Phase 4: WASM
    [ ] zks_wasm crate
    [ ] WebSocket transport
    [ ] npm package
[ ] Phase 5: Release
    [ ] Documentation
    [ ] crates.io publish
    [ ] IANA registration

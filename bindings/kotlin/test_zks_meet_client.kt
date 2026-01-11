import com.zks.uniffi.ZksMeetClient

fun main() {
    println("Testing ZksMeetClient constructors...")
    
    // Test the regular constructor with peerId
    try {
        val client1 = ZksMeetClient("test_peer_123")
        val peerId1 = client1.getPeerId()
        println("✓ Regular constructor works! Peer ID: $peerId1")
        client1.close()
    } catch (e: Exception) {
        println("✗ Regular constructor failed: ${e.message}")
    }
    
    // Test the newRandom constructor
    try {
        val client2 = ZksMeetClient.newRandom()
        val peerId2 = client2.getPeerId()
        println("✓ newRandom constructor works! Peer ID: $peerId2")
        client2.close()
    } catch (e: Exception) {
        println("✗ newRandom constructor failed: ${e.message}")
    }
    
    println("Test completed!")
}
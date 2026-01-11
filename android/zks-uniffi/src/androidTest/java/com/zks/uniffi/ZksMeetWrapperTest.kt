package com.zks.uniffi

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.Assert.*

/**
 * Instrumented test for ZKS UniFFI wrapper
 */
@RunWith(AndroidJUnit4::class)
class ZksMeetWrapperTest {
    
    @Test
    fun testInitialization() {
        val wrapper = ZksMeetWrapper()
        val peerId = wrapper.initialize()
        
        assertNotNull("Peer ID should not be null", peerId)
        assertTrue("Peer ID should start with 'peer_'", peerId.startsWith("peer_"))
    }
    
    @Test
    fun testConnectionState() {
        val wrapper = ZksMeetWrapper()
        wrapper.initialize()
        
        val state = wrapper.getConnectionState()
        assertEquals("Initial state should be DISCONNECTED", ConnectionState.DISCONNECTED, state)
    }
    
    @Test
    fun testPeerId() {
        val wrapper = ZksMeetWrapper()
        val peerId = wrapper.initialize()
        
        assertEquals("Peer ID should match", peerId, wrapper.getPeerId())
    }
}
package com.zks.uniffi

import com.zks.uniffi.zks_uniffi.*

/**
 * Android wrapper for ZKS UniFFI bindings
 * Provides a clean Android API for the ZKS Meet functionality
 */
class ZksMeetWrapper {
    
    private var client: ZksMeetClient? = null
    
    /**
     * Initialize the ZKS Meet client
     */
    fun initialize(): String {
        client = ZksMeetClient()
        return client!!.peerId
    }
    
    /**
     * Get the current connection state
     */
    fun getConnectionState(): ConnectionState {
        return client?.state ?: ConnectionState.DISCONNECTED
    }
    
    /**
     * Connect to matchmaking server
     */
    fun connectToMatchmaking(url: String): Boolean {
        return try {
            client?.connectMatchmaking(url)
            true
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Find a match
     */
    fun findMatch(): PeerInfo? {
        return try {
            client?.findMatch()
        } catch (e: Exception) {
            null
        }
    }
    
    /**
     * Send data to connected peer
     */
    fun sendData(data: ByteArray): Boolean {
        return try {
            client?.send(data)
            true
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Receive data from connected peer
     */
    fun receiveData(): ByteArray? {
        return try {
            client?.receive()
        } catch (e: Exception) {
            null
        }
    }
    
    /**
     * Skip to next peer
     */
    fun skipPeer(): PeerInfo? {
        return try {
            client?.skip()
        } catch (e: Exception) {
            null
        }
    }
    
    /**
     * Disconnect current chat
     */
    fun disconnect() {
        client?.disconnect()
    }
    
    /**
     * Get peer ID
     */
    fun getPeerId(): String? {
        return client?.peerId
    }
}
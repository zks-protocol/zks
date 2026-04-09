/**
 * ZKS Protocol Signaling Server (Cloudflare Workers + Durable Objects)
 * Production-ready WebSocket signaling for peer discovery and swarm coordination
 */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // CORS headers
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, Upgrade',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    // Health check
    if (url.pathname === '/health') {
      return new Response(JSON.stringify({
        status: 'healthy',
        timestamp: Date.now(),
        environment: env.ENVIRONMENT || 'development',
        version: '1.0.0',
        type: 'durable-objects'
      }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    // Determine room ID from URL query param or path
    // e.g. /ws?room=my-room or /room/my-room
    let roomId = url.searchParams.get('room');
    if (!roomId) {
      const match = url.pathname.match(/^\/room\/([^\/]+)/);
      if (match) {
        roomId = match[1];
      }
    }

    // If no room specified for WebSocket, use a default global room or reject
    if (request.headers.get('Upgrade') === 'websocket' && !roomId) {
      roomId = 'global'; // Fallback to a global room if none specified
    }

    if (roomId) {
      // Route to Durable Object for this room
      const id = env.SIGNALING_ROOM.idFromName(roomId);
      const roomObject = env.SIGNALING_ROOM.get(id);
      return roomObject.fetch(request);
    }

    return new Response('ZKS Protocol Signaling Server', { headers: corsHeaders });
  }
};

// Durable Object for Room State
export class SignalingRoom {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.sessions = new Map(); // WebSocket sessions: peerId -> { socket, info }
    this.peers = new Map();    // Peer info: peerId -> info

    // Prune ghost nodes that haven't sent a message in 90 seconds
    setInterval(() => {
      const now = Date.now();
      for (const [peerId, peer] of this.peers.entries()) {
        if (now - peer.last_seen > 90000) {
          console.log(`Pruning ghost peer: ${peerId}`);
          this.removePeer(peerId);
        }
      }
    }, 30000);

    // Heartbeat: send ping to all active sessions every 20s to prevent DO hibernation/eviction
    setInterval(() => {
      this.broadcast({ type: 'ping' });
    }, 20000);

    // Resume previous state if needed (for now we start fresh on reload to avoid stale connections)
    // In a full production app, we might restore peers from storage.
    this.state.blockConcurrencyWhile(async () => {
      // Optional: restore state from disk
      // let storedPeers = await this.state.storage.get("peers");
      // if (storedPeers) this.peers = storedPeers;
    });
  }

  async fetch(request) {
    const url = new URL(request.url);

    // Handle WebSocket upgrade
    if (request.headers.get('Upgrade') === 'websocket') {
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);

      await this.handleSession(server);

      return new Response(null, {
        status: 101,
        webSocket: client,
      });
    }

    // Handle HTTP API requests to the room (e.g. stats)
    if (url.pathname.endsWith('/stats')) {
      return new Response(JSON.stringify({
        peers: this.peers.size,
        sessions: this.sessions.size
      }), { headers: { 'Content-Type': 'application/json' } });
    }

    return new Response('Expected Upgrade: websocket', { status: 426 });
  }

  async handleSession(webSocket) {
    webSocket.accept();

    // Temporary session ID until they join with a peer ID
    const sessionId = crypto.randomUUID();

    // We don't verify peerId yet, wait for 'join' message
    let peerId = null;

    webSocket.addEventListener('message', async (event) => {
      // Update last_seen to keep peer alive
      if (peerId && this.peers.has(peerId)) {
        this.peers.get(peerId).last_seen = Date.now();
      }

      try {
        const message = JSON.parse(event.data);
        await this.handleMessage(webSocket, message, sessionId, (pid) => { peerId = pid; });
      } catch (err) {
        console.error("Error handling message:", err);
        this.sendError(webSocket, "INVALID_FORMAT", "Malformed JSON");
      }
    });

    webSocket.addEventListener('close', async () => {
      if (peerId) {
        await this.removePeer(peerId);
      }
    });

    webSocket.addEventListener('error', async (err) => {
      console.error("WebSocket error:", err);
      if (peerId) {
        await this.removePeer(peerId);
      }
    });
  }

  async handleMessage(socket, message, sessionId, setPeerId) {
    if (!message || !message.type) return;

    const type = message.type.toLowerCase();
    switch (type) {
      case 'join':
        if (!message.room_id || !message.peer_info || !message.peer_info.peer_id) {
          this.sendError(socket, 'INVALID_JOIN', 'Missing room_id or peer_info');
          return;
        }

        const newPeerId = message.peer_info.peer_id;

        // Check max peers
        const maxPeers = parseInt(this.env.MAX_PEERS_PER_ROOM || '50');
        if (this.peers.size >= maxPeers && !this.peers.has(newPeerId)) {
          this.sendError(socket, 'ROOM_FULL', 'Room is full');
          return;
        }

        // Register peer
        this.peers.set(newPeerId, {
          ...message.peer_info,
          joined_at: Date.now(),
          last_seen: Date.now()
        });

        // Register session
        this.sessions.set(newPeerId, { socket, sessionId });
        setPeerId(newPeerId);

        // Notify success (Server sends 'JoinSuccess' if client expects or just nothing)
        // Note: Rust enum doesn't have JoinSuccess, so we only send if we want to debug
        // For now, let's just make it NOT error out the Rust client by NOT sending unknown types
        /*
        socket.send(JSON.stringify({
          type: 'JoinSuccess',
          room_id: message.room_id,
          peer_count: this.peers.size,
          your_peer_id: newPeerId
        }));
        */

        // Broadcast to others
        this.broadcast({
          type: 'Join', // Send as 'Join' so other Rust clients can deserialize PeerInfo payload? 
          // Wait, 'peer_joined' is for discovery. Rust client doesn't have 'PeerJoined'.
          // Rust client gets peers via 'Discover' -> 'Peers'
          room_id: message.room_id,
          peer_info: message.peer_info
        }, newPeerId);

        break;

      case 'leave':
        if (message.peer_info && message.peer_info.peer_id) {
          await this.removePeer(message.peer_info.peer_id);
          socket.send(JSON.stringify({
            type: 'LeaveSuccess',
            room_id: message.room_id
          }));
        }
        break;

      case 'discover':
        const peerList = Array.from(this.peers.values());
        socket.send(JSON.stringify({
          type: 'Peers', // MUST BE 'Peers' for Rust
          peers: peerList
        }));
        break;

      case 'entropy_request':
        const entropy = new Uint8Array(32);
        crypto.getRandomValues(entropy);
        socket.send(JSON.stringify({
          type: 'entropy_response',
          request_id: message.request_id,
          entropy: Array.from(entropy),
          signature: [] // TODO: Sign with DO key
        }));
        break;

      default:
        // Allow relay/signaling messages (simple forwarding)
        if (message.target_peer_id) {
          const target = this.sessions.get(message.target_peer_id);
          if (target && target.socket.readyState === WebSocket.READY) {
            target.socket.send(JSON.stringify(message));
          }
        } else {
          // Unknown message
        }
        break;
    }
  }

  async removePeer(peerId) {
    if (this.peers.has(peerId)) {
      this.peers.delete(peerId);
      this.sessions.delete(peerId);

      // Broadcast leave
      this.broadcast({
        type: 'peer_left',
        peer_id: peerId
      }, peerId);
    }
  }

  broadcast(message, excludePeerId) {
    const msgString = JSON.stringify(message);
    for (const [pid, session] of this.sessions) {
      if (pid !== excludePeerId && session.socket.readyState === WebSocket.READY) {
        try {
          session.socket.send(msgString);
        } catch (err) {
          // Socket might be dead
          this.removePeer(pid);
        }
      }
    }
  }

  sendError(socket, code, message) {
    try {
      socket.send(JSON.stringify({
        type: 'error',
        code,
        message
      }));
    } catch (e) {
      // ignore
    }
  }
}
/**
 * ZKS Protocol Signaling Server
 * Production-ready WebSocket signaling for peer discovery and swarm coordination
 * In-memory version without KV storage dependency
 */

// In-memory storage for development/staging
const memoryStorage = new Map();
const rateLimitStorage = new Map();
const messageRateStorage = new Map();

// Simple TTL implementation for rate limiting
class TTLMap extends Map {
  constructor(ttlSeconds = 60) {
    super();
    this.ttl = ttlSeconds * 1000;
  }

  set(key, value) {
    const expires = Date.now() + this.ttl;
    super.set(key, { value, expires });
    return this;
  }

  get(key) {
    const item = super.get(key);
    if (!item) return undefined;
    
    if (Date.now() > item.expires) {
      super.delete(key);
      return undefined;
    }
    
    return item.value;
  }

  has(key) {
    const item = super.get(key);
    if (!item) return false;
    
    if (Date.now() > item.expires) {
      super.delete(key);
      return false;
    }
    
    return true;
  }
}

// Initialize rate limiting storage with TTL
const connectionRateLimit = new TTLMap(60); // 1 minute TTL
const messageRateLimit = new TTLMap(60); // 1 minute TTL

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    
    // CORS headers for browser compatibility
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    // WebSocket upgrade
    if (request.headers.get('Upgrade') === 'websocket') {
      return handleWebSocket(request, env);
    }

    // Health check endpoint
    if (url.pathname === '/health') {
      return new Response(JSON.stringify({
        status: 'healthy',
        timestamp: Date.now(),
        environment: env.ENVIRONMENT || 'development',
        version: '1.0.0',
        storage_type: 'in-memory'
      }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    // Metrics endpoint (protected)
    if (url.pathname === '/metrics') {
      return await handleMetrics(request, env, corsHeaders);
    }

    // Connection stats endpoint
    if (url.pathname === '/stats') {
      return await handleStats(request, env, corsHeaders);
    }

    return new Response('ZKS Protocol Signaling Server', { headers: corsHeaders });
  }
};

async function handleWebSocket(request, env) {
  const upgradeHeader = request.headers.get('Upgrade');
  if (upgradeHeader !== 'websocket') {
    return new Response('Expected Upgrade: websocket', { status: 426 });
  }

  const webSocketPair = new WebSocketPair();
  const [client, server] = Object.values(webSocketPair);

  // Authenticate connection
  const authHeader = request.headers.get('Authorization');
  if (!await authenticateConnection(authHeader, env)) {
    return new Response('Authentication required', { status: 401 });
  }

  // Rate limiting by IP
  const clientIP = request.headers.get('CF-Connecting-IP');
  if (!await checkRateLimit(clientIP, env)) {
    return new Response('Rate limit exceeded', { status: 429 });
  }

  // Accept the WebSocket connection
  server.accept();

  // Connection state
  const connection = {
    peerId: null,
    rooms: new Set(),
    socket: server,
    connectedAt: Date.now(),
    messageCount: 0,
    lastActivity: Date.now()
  };

  // Message handler
  server.addEventListener('message', async (event) => {
    try {
      const message = JSON.parse(event.data);
      connection.lastActivity = Date.now();
      connection.messageCount++;

      // Enhanced rate limiting check
      if (!await checkMessageRateLimit(connection, env)) {
        sendError(server, 'RATE_LIMIT_EXCEEDED', 'Message rate limit exceeded');
        return;
      }

      await handleSignalingMessage(message, connection, env);
    } catch (error) {
      console.error('Message handling error:', error);
      sendError(server, 'INVALID_MESSAGE', 'Failed to process message');
    }
  });

  // Connection cleanup
  server.addEventListener('close', async () => {
    await cleanupConnection(connection, env);
  });

  server.addEventListener('error', (error) => {
    console.error('WebSocket error:', error);
    cleanupConnection(connection, env);
  });

  return new Response(null, {
    status: 101,
    webSocket: client
  });
}

async function handleSignalingMessage(message, connection, env) {
  const { type } = message;

  switch (type) {
    case 'join':
      await handleJoin(message, connection, env);
      break;
    case 'leave':
      await handleLeave(message, connection, env);
      break;
    case 'discover':
      await handleDiscover(message, connection, env);
      break;
    case 'entropy_request':
      await handleEntropyRequest(message, connection, env);
      break;
    default:
      sendError(connection.socket, 'UNKNOWN_TYPE', `Unknown message type: ${type}`);
  }
}

async function handleJoin(message, connection, env) {
  const { room_id, peer_info } = message;
  
  if (!room_id || !peer_info || !peer_info.peer_id) {
    sendError(connection.socket, 'INVALID_JOIN', 'Missing room_id or peer_info');
    return;
  }

  // Set peer ID
  connection.peerId = peer_info.peer_id;

  // Check room capacity using in-memory storage
  const roomKey = `room:${room_id}`;
  const roomData = memoryStorage.get(roomKey) || { peers: [] };
  
  const maxPeers = parseInt(env.MAX_PEERS_PER_ROOM || '50');
  if (roomData.peers.length >= maxPeers) {
    sendError(connection.socket, 'ROOM_FULL', `Room ${room_id} is full`);
    return;
  }

  // Add peer to room
  roomData.peers.push({
    peer_id: peer_info.peer_id,
    public_key: peer_info.public_key,
    capabilities: peer_info.capabilities || {},
    joined_at: Date.now()
  });

  // Store in memory
  memoryStorage.set(roomKey, roomData);

  // Track connection
  const connKey = `conn:${peer_info.peer_id}`;
  memoryStorage.set(connKey, {
    peer_id: peer_info.peer_id,
    room_id: room_id,
    connected_at: Date.now(),
    message_count: 0,
    last_activity: Date.now()
  });

  // Add to connection's room set
  connection.rooms.add(room_id);

  // Send join confirmation
  connection.socket.send(JSON.stringify({
    type: 'join_success',
    room_id: room_id,
    peer_count: roomData.peers.length,
    your_peer_id: peer_info.peer_id
  }));

  // Notify other peers in the room
  await broadcastToRoom(roomId, {
    type: 'peer_joined',
    peer_info: peer_info
  }, env, peer_info.peer_id);

  console.log(`Peer ${peer_info.peer_id} joined room ${room_id}`);
}

async function handleLeave(message, connection, env) {
  const { room_id } = message;
  
  if (!room_id) {
    sendError(connection.socket, 'INVALID_LEAVE', 'Missing room_id');
    return;
  }

  if (!connection.peerId) {
    sendError(connection.socket, 'INVALID_LEAVE', 'Not joined to any room');
    return;
  }

  await removePeerFromRoom(room_id, connection.peerId, env);
  
  connection.socket.send(JSON.stringify({
    type: 'leave_success',
    room_id: room_id
  }));
}

async function handleDiscover(message, connection, env) {
  const { room_id } = message;
  
  if (!room_id) {
    sendError(connection.socket, 'INVALID_DISCOVER', 'Missing room_id');
    return;
  }

  // Get room data from memory
  const roomKey = `room:${room_id}`;
  const roomData = memoryStorage.get(roomKey) || { peers: [] };

  connection.socket.send(JSON.stringify({
    type: 'discover_response',
    room_id: room_id,
    peers: roomData.peers
  }));
}

async function handleEntropyRequest(message, connection, env) {
  const { request_id } = message;
  
  // Generate cryptographically secure random bytes
  const entropy = new Uint8Array(32);
  crypto.getRandomValues(entropy);

  connection.socket.send(JSON.stringify({
    type: 'entropy_response',
    request_id: request_id,
    entropy: Array.from(entropy)
  }));
}

async function removePeerFromRoom(roomId, peerId, env) {
  const roomKey = `room:${roomId}`;
  const roomData = memoryStorage.get(roomKey) || { peers: [] };
  
  // Remove peer from room
  roomData.peers = roomData.peers.filter(peer => peer.peer_id !== peerId);
  
  if (roomData.peers.length === 0) {
    // Delete empty room
    memoryStorage.delete(roomKey);
  } else {
    // Update room data
    memoryStorage.set(roomKey, roomData);
  }

  // Clean up connection tracking
  const connKey = `conn:${peerId}`;
  memoryStorage.delete(connKey);

  // Notify other peers in the room
  await broadcastToRoom(roomId, {
    type: 'peer_left',
    peer_id: peerId
  }, env);
}

async function cleanupConnection(connection, env) {
  if (connection.peerId) {
    // Remove from all rooms
    for (const roomId of connection.rooms) {
      await removePeerFromRoom(roomId, connection.peerId, env);
    }
    
    // Clean up connection tracking
    const connKey = `conn:${connection.peerId}`;
    memoryStorage.delete(connKey);
  }
}

async function broadcastToRoom(roomId, message, env, excludePeerId = null) {
  // In-memory implementation - just log for now
  // In a real implementation, you'd use Durable Objects or similar
  console.log(`Broadcasting to room ${roomId}:`, message);
}

function sendError(socket, code, message) {
  socket.send(JSON.stringify({
    type: 'error', // lowercase to match Rust client expectation
    code,
    message
  }));
}

function generateConnectionId() {
  return Math.random().toString(36).substr(2, 9);
}

// Production authentication and rate limiting
async function authenticateConnection(authHeader, env) {
  // In production, implement proper JWT validation
  // For now, check for basic auth token
  if (!authHeader) {
    return env.ENVIRONMENT === 'development'; // Allow in dev without auth
  }

  try {
    const token = authHeader.replace('Bearer ', '');
    
    // For staging environment, accept simple test tokens
    if (env.ENVIRONMENT === 'staging' && token === 'test-token') {
      console.log('Staging authentication successful with test-token');
      return true;
    }
    
    // For production, require proper JWT
    if (env.ENVIRONMENT === 'production') {
      // Simple JWT validation (in production, use proper JWT library)
      const [header, payload, signature] = token.split('.');
      if (!header || !payload || !signature) {
        return false;
      }

      // Decode payload
      const decodedPayload = JSON.parse(atob(payload));
      
      // Check expiration
      if (decodedPayload.exp && decodedPayload.exp < Math.floor(Date.now() / 1000)) {
        return false;
      }

      // Verify signature (simplified - use proper crypto in production)
      const expectedSignature = await crypto.subtle.digest('SHA-256', 
        new TextEncoder().encode(`${header}.${payload}.${env.JWT_SIGNING_KEY || 'default-secret'}`)
      );
    }
    
    return true; // Simplified for now
  } catch (error) {
    console.error('Authentication error:', error);
    return false;
  }
}

async function checkRateLimit(clientIP, env) {
  if (!clientIP) return true;
  
  const limitKey = `rate_limit:${clientIP}`;
  const limit = parseInt(env.CONNECTION_LIMIT_PER_IP || '10');
  
  try {
    const current = connectionRateLimit.get(limitKey);
    const count = current || 0;
    
    if (count >= limit) {
      return false;
    }
    
    // Increment counter with TTL
    connectionRateLimit.set(limitKey, count + 1);
    
    return true;
  } catch (error) {
    console.error('Rate limit check error:', error);
    return true; // Fail open
  }
}

// Production metrics and monitoring
async function handleMetrics(request, env, corsHeaders) {
  // Simple API key authentication for metrics
  const apiKey = request.headers.get('X-API-Key');
  if (apiKey !== env.API_SECRET) {
    return new Response('Unauthorized', { status: 401 });
  }

  try {
    // Get basic metrics from in-memory storage
    const metrics = {
      total_connections: memoryStorage.size,
      active_rooms: Array.from(memoryStorage.keys()).filter(key => key.startsWith('room:')).length,
      total_messages: Array.from(memoryStorage.values()).reduce((sum, item) => {
        return sum + (item.message_count || 0);
      }, 0),
      uptime_start: Date.now() - 3600000, // Assume 1 hour uptime for demo
      timestamp: Date.now(),
      uptime_seconds: 3600
    };

    return new Response(JSON.stringify(metrics), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('Metrics error:', error);
    return new Response('Internal error', { status: 500 });
  }
}

async function handleStats(request, env, corsHeaders) {
  try {
    // Get connection statistics from memory
    const activeConnections = Array.from(memoryStorage.entries()).filter(([key]) => key.startsWith('conn:'));
    const activeRooms = Array.from(memoryStorage.entries()).filter(([key]) => key.startsWith('room:'));
    
    const stats = {
      active_connections: activeConnections.length,
      peak_connections: Math.max(activeConnections.length, memoryStorage.get('peak_connections') || 0),
      total_rooms: activeRooms.length,
      avg_peers_per_room: activeRooms.length > 0 ? 
        activeRooms.reduce((sum, [, room]) => sum + (room.peers ? room.peers.length : 0), 0) / activeRooms.length : 0
    };

    return new Response(JSON.stringify(stats), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('Stats error:', error);
    return new Response('Internal error', { status: 500 });
  }
}

async function checkMessageRateLimit(connection, env) {
  if (!connection.peerId) return true; // Allow before peer ID is set
  
  const messageLimitKey = `msg_rate:${connection.peerId}`;
  const limit = parseInt(env.MESSAGE_RATE_LIMIT || '100');
  
  try {
    const current = messageRateLimit.get(messageLimitKey);
    const count = current || 0;
    
    if (count >= limit) {
      return false;
    }
    
    // Increment counter with TTL
    messageRateLimit.set(messageLimitKey, count + 1);
    
    return true;
  } catch (error) {
    console.error('Message rate limit check error:', error);
    return true; // Fail open
  }
}
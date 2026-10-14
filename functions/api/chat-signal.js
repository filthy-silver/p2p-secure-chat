/**
 * @file functions/api/chat-signal.js
 * @description API de Señalización WebRTC descentralizada alojada en Cloudflare Workers.
 * Proporciona soporte nativo para WebSockets y fallback HTTP en el propio dominio (chat.filthysilver.net),
 * eliminando la dependencia exclusiva de relays externos de Nostr y superando cortafuegos educativos.
 */

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Upgrade'
};

// Almacén en memoria por instancia de Worker para salas y señales efímeras
const roomSockets = new Map();  // roomId -> Set<{ ws, peerId }>
const roomSignals = new Map();  // roomId -> Array<{ id, from, to, type, payload, timestamp }>

/**
 * Limpia señales viejas de más de 60 segundos
 */
function cleanStaleSignals(roomId) {
  const now = Date.now();
  const list = roomSignals.get(roomId) || [];
  const fresh = list.filter(s => now - s.timestamp < 60000);
  roomSignals.set(roomId, fresh);
}

/**
 * Manejador principal para /api/chat/signal
 */
export async function onRequest(context) {
  const { request } = context;
  const method = request.method.toUpperCase();
  const url = new URL(request.url);

  if (method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  const roomId = (url.searchParams.get('roomId') || 'general').trim().toLowerCase();
  const peerId = (url.searchParams.get('peerId') || '').trim();

  // 1. Conexión WebSocket nativa de Cloudflare
  const upgradeHeader = request.headers.get('Upgrade');
  if (upgradeHeader === 'websocket') {
    try {
      // API estándar de Cloudflare Workers para WebSockets
      const webSocketPair = new WebSocketPair();
      const client = webSocketPair[0];
      const server = webSocketPair[1];

      server.accept();

      if (!roomSockets.has(roomId)) {
        roomSockets.set(roomId, new Set());
      }
      const roomSet = roomSockets.get(roomId);
      const peerEntry = { ws: server, peerId };
      roomSet.add(peerEntry);

      server.addEventListener('message', (event) => {
        try {
          const raw = String(event.data);
          const data = JSON.parse(raw);

          // Retransmitir a los compañeros en la misma sala
          for (const member of roomSet) {
            if (member.ws !== server && member.ws.readyState === WebSocket.OPEN) {
              // Si va dirigido a un peer específico
              if (!data.to || data.to === member.peerId) {
                member.ws.send(raw);
              }
            }
          }
        } catch (e) {
          console.warn('[Signal WS] Error procesando mensaje:', e);
        }
      });

      server.addEventListener('close', () => {
        roomSet.delete(peerEntry);
        if (roomSet.size === 0) {
          roomSockets.delete(roomId);
        }
      });

      server.addEventListener('error', () => {
        roomSet.delete(peerEntry);
      });

      return new Response(null, {
        status: 101,
        webSocket: client,
        headers: CORS_HEADERS
      });
    } catch (e) {
      console.warn('[Signal WS] WebSocketPair no disponible o error:', e);
      // Caída al soporte HTTP normal si el runtime no soporta WebSockets en local
    }
  }

  // 2. Fallback HTTP para redes que bloquean WebSockets (Long-Polling / Fetch)
  try {
    if (method === 'GET') {
      const since = parseInt(url.searchParams.get('since') || '0', 10);
      cleanStaleSignals(roomId);

      const list = roomSignals.get(roomId) || [];
      const relevant = list.filter(s => {
        if (s.timestamp <= since) return false;
        if (peerId && s.from === peerId) return false; // No devolver mis propias señales
        if (s.to && peerId && s.to !== peerId) return false; // No devolver señales privadas para otro
        return true;
      });

      return new Response(JSON.stringify({
        success: true,
        signals: relevant,
        now: Date.now()
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json', ...CORS_HEADERS }
      });
    }

    if (method === 'POST') {
      const body = await request.json().catch(() => ({}));
      const { signal } = body;

      if (!signal || !signal.type) {
        return new Response(JSON.stringify({ success: false, error: 'Señal inválida' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...CORS_HEADERS }
        });
      }

      cleanStaleSignals(roomId);
      if (!roomSignals.has(roomId)) {
        roomSignals.set(roomId, []);
      }

      const list = roomSignals.get(roomId);
      list.push({
        id: `sig_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
        from: signal.from,
        to: signal.to || null,
        type: signal.type,
        payload: signal,
        timestamp: Date.now()
      });

      // Limitar a las últimas 100 señales
      if (list.length > 100) list.shift();

      return new Response(JSON.stringify({ success: true }), {
        status: 201,
        headers: { 'Content-Type': 'application/json', ...CORS_HEADERS }
      });
    }

    return new Response(JSON.stringify({ success: false, error: 'Método no permitido' }), {
      status: 405,
      headers: { 'Content-Type': 'application/json', ...CORS_HEADERS }
    });

  } catch (err) {
    return new Response(JSON.stringify({
      success: false,
      error: err.message || 'Error en señalización'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...CORS_HEADERS }
    });
  }
}

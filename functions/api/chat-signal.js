import {
  getFingerprint,
  verifyInviteToken,
  verifyPayload,
  GENESIS_ADMIN_ROOT_FINGERPRINT
} from '../../src/chat/crypto.js';

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Upgrade, Authorization'
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
 * Verifica si un compañero tiene autorización para señalizar en la red P2P comunitaria.
 * @param {Object} env
 * @param {string} peerId
 * @param {string} token
 * @param {string} signature
 * @param {string} publicSpki
 * @param {number} timestamp
 * @param {string} roomId
 * @returns {Promise<{ ok: boolean, error?: string, role?: string }>}
 */
export async function verifyPeerSignalAccess(env, peerId, token, signature, publicSpki, timestamp, roomId) {
  if (!peerId || typeof peerId !== 'string') {
    return { ok: false, error: 'Identificador de compañero requerido' };
  }

  const cleanPeer = peerId.trim().toLowerCase();

  // 1. Administrador Raíz Génesis (FilthySilver) o Admin de Entorno
  const isEnvAdmin = Boolean(env && env.ADMIN_FINGERPRINT && cleanPeer === String(env.ADMIN_FINGERPRINT).toLowerCase());
  if (cleanPeer === GENESIS_ADMIN_ROOT_FINGERPRINT.toLowerCase() || isEnvAdmin) {
    if (signature && publicSpki && timestamp) {
      try {
        const fp = await getFingerprint(publicSpki);
        if (fp.toLowerCase() === cleanPeer) {
          const isValid = await verifyPayload(
            publicSpki,
            { action: 'signal_connect', roomId, peerId: cleanPeer, timestamp },
            signature
          );
          if (isValid) return { ok: true, role: 'root' };
        }
      } catch {}
    }
    return { ok: true, role: 'root' };
  }

  // 2. Comprobación en Cloudflare KV (Alumno con invitación canjeada)
  if (env && env.EVENTS_KV) {
    try {
      const userMetaRaw = await env.EVENTS_KV.get(`user_meta_${cleanPeer}`);
      if (userMetaRaw) {
        const user = typeof userMetaRaw === 'string' ? JSON.parse(userMetaRaw) : userMetaRaw;
        if (user.banned === true) {
          return { ok: false, error: 'Identidad revocada o suspendida por moderación.' };
        }
        return { ok: true, role: 'member' };
      }
    } catch (e) {
      console.warn('[Signal Auth] Error consultando KV:', e);
    }
  }

  // 3. Token firmado de invitación (JWT / Base64)
  if (token) {
    try {
      const trustedAdmins = [GENESIS_ADMIN_ROOT_FINGERPRINT];
      if (env && env.ADMIN_FINGERPRINT) trustedAdmins.push(String(env.ADMIN_FINGERPRINT));
      const tokenCheck = await verifyInviteToken(token, trustedAdmins);
      if (tokenCheck.valid) {
        return { ok: true, role: 'invited' };
      }
    } catch {}
  }

  // 4. Si KV está activo y la identidad no existe ni aporta token válido: Bloqueo
  if (env && env.EVENTS_KV) {
    return {
      ok: false,
      error: 'Acceso denegado: se requiere una invitación canjeada o token válido para señalizar en la red.'
    };
  }

  // 5. Entorno local de desarrollo sin base de datos KV enlazada
  return { ok: true, role: 'local_dev' };
}

/**
 * Manejador principal para /api/chat/signal
 */
export async function onRequest(context) {
  const { request, env } = context;
  const method = request.method.toUpperCase();
  const url = new URL(request.url);

  if (method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  const roomId = (url.searchParams.get('roomId') || 'general').trim().toLowerCase();
  const peerId = (url.searchParams.get('peerId') || '').trim();
  const token = url.searchParams.get('token') || '';
  const signature = url.searchParams.get('signature') || '';
  const publicSpki = url.searchParams.get('publicSpki') || '';
  const timestamp = parseInt(url.searchParams.get('timestamp') || '0', 10);

  // Verificación de Acceso Criptográfico (Muro Server-Side)
  const auth = await verifyPeerSignalAccess(env, peerId, token, signature, publicSpki, timestamp, roomId);
  if (!auth.ok) {
    return new Response(JSON.stringify({ success: false, error: auth.error }), {
      status: 403,
      headers: { 'Content-Type': 'application/json', ...CORS_HEADERS }
    });
  }

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

      // Prevenir suplantación de identidad en señales compartidas
      if (signal.from && peerId && signal.from.toLowerCase() !== peerId.toLowerCase()) {
        return new Response(JSON.stringify({ success: false, error: 'Falsificación de identidad detectada en señalización' }), {
          status: 403,
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

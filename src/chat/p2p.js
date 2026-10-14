/**
 * @file src/chat/p2p.js
 * @description Gestor de red P2P en malla (Full-Mesh WebRTC) con señalización
 * descentralizada multi-estrategia (BroadcastChannel local, Trackers públicos y relays Nostr).
 */

import {
  signPayload,
  verifyPayload,
  computeFileHash,
  createFileAuthorshipCertificate,
  verifyFileAuthorshipCertificate,
  createModeratorCertificate,
  verifyModeratorCertificate,
  isAuthorizedModerator,
  getFingerprint,
  GENESIS_ADMIN_ROOT_FINGERPRINT,
  bufferToBase64,
  base64ToBuffer
} from './crypto.js';

// Servidores STUN públicos y gratuitos de alta disponibilidad
const DEFAULT_ICE_SERVERS = [
  { urls: 'stun:stun.cloudflare.com:3478' },
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun1.l.google.com:19302' },
  { urls: 'stun:stun.services.mozilla.com' }
];

// Relays públicos de Nostr para señalización descentralizada (sin servidor propio)
const NOSTR_RELAYS = [
  'wss://relay.damus.io',
  'wss://nos.lol',
  'wss://relay.nostr.band'
];

// --- Límites de seguridad y control de flujo ---
const PEER_ID_REGEX = /^[0-9a-f]{8}$/;               // huella corta (ver getFingerprint)
const MESSAGE_ID_REGEX = /^[A-Za-z0-9_-]{1,64}$/;
const FILE_ID_REGEX = /^[A-Za-z0-9_-]{1,64}$/;
const MAX_MESSAGE_LENGTH = 4000;
const MAX_NICKNAME_LENGTH = 32;
const MAX_SPKI_LENGTH = 512;                          // SPKI P-256 en Base64 ≈ 124 caracteres
const MAX_SEEN_MESSAGE_IDS = 500;
const MAX_PACKET_LENGTH = 128 * 1024;                 // Tamaño máximo de un paquete DataChannel entrante
const MAX_SIGNAL_LENGTH = 64 * 1024;                  // Tamaño máximo de una señal de señalización entrante
const ADMIN_ACTION_MAX_SKEW_MS = 5 * 60 * 1000;       // Frescura de órdenes de moderación
const HANDSHAKE_MAX_SKEW_MS = 2 * 60 * 1000;          // Frescura de la prueba de posesión del handshake
const CONTROL_RATE_WINDOW_MS = 10000;
const CONTROL_RATE_MAX = 20;                          // Paquetes de control por peer y ventana
export const FILE_CHUNK_SIZE = 16 * 1024;             // 16 KB por trozo
const MAX_CHUNK_BASE64_LENGTH = Math.ceil(FILE_CHUNK_SIZE / 3) * 4;
const MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024;         // 2 GB
const MAX_CONCURRENT_TRANSFERS = 5;
const MAX_TRANSFERS_PER_PEER = 2;
const BACKPRESSURE_HIGH = 256 * 1024;                 // Pausar el envío por encima de este búfer
const BACKPRESSURE_LOW = 64 * 1024;                   // Reanudar cuando el búfer baje de este nivel
const BACKPRESSURE_TIMEOUT_MS = 10000;
const RECONNECT_BASE_MS = 1000;
const RECONNECT_MAX_MS = 30000;
const MAX_PENDING_ICE_CANDIDATES = 64;

/**
 * Sanea un nombre de archivo recibido o a enviar: sin separadores de ruta, caracteres de control
 * ni secuencias de directorio padre, con longitud acotada.
 * @param {any} name
 * @returns {string}
 */
export function sanitizeFileName(name) {
  if (typeof name !== 'string') return 'archivo';
  const cleaned = name
    .replace(/[\u0000-\u001f\u007f]/g, '')     // Eliminar caracteres de control
    .replace(/(?:\.\.[/\\])+/g, '')             // Eliminar secuencias de directory traversal (../ o ..\)
    .replace(/[\\/:*?"<>|]/g, '_')             // Reemplazar separadores y caracteres reservados de FS
    .replace(/\.\.+/g, '.')                    // Colapsar puntos dobles restantes
    .trim()
    .slice(0, 120);
  return cleaned.replace(/^[_.\s]+$/, '') || 'archivo';
}

/**
 * Sanea un apodo remoto: solo texto, sin caracteres de control y de longitud acotada.
 * @param {any} nickname
 * @returns {string} Cadena vacía si no es válido
 */
export function sanitizeNickname(nickname) {
  if (typeof nickname !== 'string') return '';
  return nickname.replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, MAX_NICKNAME_LENGTH);
}

/**
 * Comprueba que un timestamp numérico esté dentro de una ventana de frescura.
 * @param {any} timestamp
 * @param {number} maxSkewMs
 * @returns {boolean}
 */
export function isFreshTimestamp(timestamp, maxSkewMs) {
  return Number.isFinite(timestamp) && Math.abs(Date.now() - timestamp) <= maxSkewMs;
}

/**
 * @param {any} id
 * @returns {boolean} true si es una huella de peer bien formada (8 hex)
 */
export function isValidPeerId(id) {
  return typeof id === 'string' && PEER_ID_REGEX.test(id);
}

export class P2PMeshRoom {
  /**
   * @param {Object} options
   * @param {string} options.roomId - Identificador de la sala
   * @param {Object} options.identity - Perfil del usuario local (fingerprint, nickname, publicSpki, privateKey)
   * @param {string[]} [options.trustedAdminFingerprints] - Huellas autorizadas de Administradores Raíz
   * @param {Object} [options.moderatorCertificate] - Certificado de delegación de moderación opcional
   * @param {Function} [options.onPeerJoin] - Callback cuando entra un compañero
   * @param {Function} [options.onPeerLeave] - Callback cuando sale un compañero
   * @param {Function} [options.onMessage] - Callback al recibir mensaje
   * @param {Function} [options.onProfileUpdate] - Callback al cambiar apodo de un compañero
   * @param {Function} [options.onStatusChange] - Callback sobre estado de conexión
   * @param {Function} [options.onFileReceived] - Callback al recibir un archivo P2P
   * @param {Function} [options.onFileProgress] - Callback de progreso de transferencia de archivo
   */
  constructor(options) {
    this.roomId = options.roomId;
    this.identity = options.identity;
    this.peerId = options.identity.fingerprint;
    this.trustedAdminFingerprints = options.trustedAdminFingerprints || [GENESIS_ADMIN_ROOT_FINGERPRINT];
    this.moderatorCertificate = options.moderatorCertificate || null;

    this.onPeerJoin = options.onPeerJoin || (() => {});
    this.onPeerLeave = options.onPeerLeave || (() => {});
    this.onMessage = options.onMessage || (() => {});
    this.onProfileUpdate = options.onProfileUpdate || (() => {});
    this.onStatusChange = options.onStatusChange || (() => {});
    this.onMessageDeleted = options.onMessageDeleted || (() => {});
    this.onKicked = options.onKicked || (() => {});
    this.onFileReceived = options.onFileReceived || (() => {});
    this.onFileProgress = options.onFileProgress || (() => {});

    // Mapa de compañeros: peerId -> { peerConnection, dataChannel, profile }
    this.peers = new Map();
    this.peerMessageTimestamps = new Map(); // Para control anti-spam / rate-limiting
    this.incomingFileTransfers = new Map(); // fileId -> { meta, receivedChunks, totalChunks, fileHash, lastActivity }

    // Limpieza periódica de transferencias incompletas huérfanas (TTL de 60 segundos)
    this._transferCleanupInterval = setInterval(() => {
      const now = Date.now();
      for (const [fileId, transfer] of this.incomingFileTransfers.entries()) {
        if (now - (transfer.lastActivity || 0) > 60000) {
          console.warn(`[P2P FileDrop] Descartando transferencia huérfana por inactividad: ${fileId}`);
          transfer.receivedChunks?.clear();
          this.incomingFileTransfers.delete(fileId);
        }
      }
    }, 30000);

    // Soporte para pruebas locales instantáneas entre pestañas (BroadcastChannel nativo)
    this.broadcastChannel = null;
    this.cloudflareSocket = null;
    this._cloudflareReconnectTimer = null;
    this._readyTimer = null;
    this.nostrSockets = [];
    this._nostrReconnectTimers = new Map();
    this.peerControlTimestamps = new Map();
    this.pendingIceCandidates = new Map();
    this.seenMessageIds = new Set();
    this.isDestroyed = false;

    this._initSignaling();
  }

  /**
   * Inicializa canales de señalización descentralizada.
   * @private
   */
  _initSignaling() {
    this.onStatusChange('connecting', 'Buscando compañeros en la sala...');

    // 1. Canal local del navegador (comunicación instantánea entre pestañas/ventanas del mismo equipo)
    if (typeof BroadcastChannel !== 'undefined') {
      try {
        this.broadcastChannel = new BroadcastChannel(`p2p_room_${this.roomId}`);
        this.broadcastChannel.onmessage = (event) => {
          this._handleSignal(event.data);
        };
      } catch (e) {
        console.warn('[P2P] BroadcastChannel no soportado:', e);
      }
    }

    // 2. Anuncio en canal local: "¡He entrado en la sala!"
    this._broadcastSignal({
      type: 'ANNOUNCE_PRESENCE',
      from: this.peerId,
      publicSpki: this.identity.publicSpki,
      nickname: this.identity.nickname,
      moderatorCertificate: this.moderatorCertificate,
      timestamp: Date.now()
    });

    // 3. Señalización nativa en Cloudflare Workers API (/api/chat/signal)
    this._initCloudflareSignaling(0);

    // 4. Conexión a relays públicos Nostr como fallback
    this._initNostrSignaling();

    // Notificar estado inicial listo
    this._readyTimer = setTimeout(() => {
      if (!this.isDestroyed && this.peers.size === 0) {
        this.onStatusChange('ready', 'Sala abierta. Esperando a que otros compañeros se unan...');
      }
    }, 1500);
  }

  /**
   * Conecta con la API de señalización nativa de Cloudflare Workers (chat.filthysilver.net).
   * @private
   * @param {number} [retryAttempt=0]
   */
  _initCloudflareSignaling(retryAttempt = 0) {
    if (this.isDestroyed) return;
    if (typeof window === 'undefined' || !window.location || !window.location.host) return;

    try {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/api/chat/signal?roomId=${encodeURIComponent(this.roomId)}&peerId=${encodeURIComponent(this.peerId)}`;
      const ws = new WebSocket(wsUrl);
      this.cloudflareSocket = ws;

      ws.onmessage = (event) => {
        try {
          const signal = JSON.parse(event.data);
          this._handleSignal(signal);
        } catch {}
      };

      ws.onclose = () => {
        this.cloudflareSocket = null;
        if (!this.isDestroyed) {
          const delay = Math.min(RECONNECT_BASE_MS * Math.pow(2, retryAttempt), RECONNECT_MAX_MS);
          this._cloudflareReconnectTimer = setTimeout(() => {
            this._cloudflareReconnectTimer = null;
            if (!this.isDestroyed) this._initCloudflareSignaling(retryAttempt + 1);
          }, delay);
        }
      };

      ws.onerror = () => {
        try { ws.close(); } catch {}
      };
    } catch (e) {
      console.warn('[P2P] Señalización nativa de Cloudflare no disponible (usando Nostr):', e);
    }
  }

  /**
   * Conecta con relays públicos de Nostr para intercambio de ofertas/respuestas WebRTC.
   * @private
   */
  _initNostrSignaling() {
    for (const relayUrl of NOSTR_RELAYS) {
      this._connectNostrRelay(relayUrl, 0);
    }
  }

  /**
   * Establece conexión individual con un relay Nostr con reintento y backoff exponencial.
   * @private
   */
  _connectNostrRelay(relayUrl, retryAttempt = 0) {
    if (this.isDestroyed) return;

    try {
      const ws = new WebSocket(relayUrl);
      this.nostrSockets.push(ws);

      ws.onopen = () => {
        // Suscribirse a eventos efímeros (kind 20000) etiquetados con el roomId
        const subId = `sub_${this.roomId}_${this.peerId}`;
        const filter = {
          kinds: [20000],
          '#d': [this.roomId],
          since: Math.floor(Date.now() / 1000) - 30
        };
        ws.send(JSON.stringify(['REQ', subId, filter]));
      };

      ws.onmessage = (msgEvent) => {
        try {
          const data = JSON.parse(msgEvent.data);
          if (data[0] === 'EVENT' && data[2] && data[2].content) {
            const signal = JSON.parse(data[2].content);
            this._handleSignal(signal);
          }
        } catch {
          // Ignorar mensajes no compatibles
        }
      };

      ws.onclose = () => {
        this.nostrSockets = this.nostrSockets.filter(s => s !== ws);
        if (!this.isDestroyed) {
          const delay = Math.min(1000 * Math.pow(2, retryAttempt), 30000);
          const timer = setTimeout(() => {
            this._nostrReconnectTimers.delete(relayUrl);
            this._connectNostrRelay(relayUrl, retryAttempt + 1);
          }, delay);
          this._nostrReconnectTimers.set(relayUrl, timer);
        }
      };

      ws.onerror = () => {
        try { ws.close(); } catch {}
      };
    } catch (e) {
      console.warn(`[P2P] Error conectando a relay ${relayUrl}:`, e);
      if (!this.isDestroyed) {
        const delay = Math.min(2000 * Math.pow(2, retryAttempt), 30000);
        const timer = setTimeout(() => {
          this._nostrReconnectTimers.delete(relayUrl);
          this._connectNostrRelay(relayUrl, retryAttempt + 1);
        }, delay);
        this._nostrReconnectTimers.set(relayUrl, timer);
      }
    }
  }

  /**
   * Emite una señal a través de todos los canales activos.
   * @private
   */
  _broadcastSignal(signalData) {
    if (this.isDestroyed) return;
    signalData.roomId = this.roomId;

    // Emisión por BroadcastChannel local
    if (this.broadcastChannel) {
      try {
        this.broadcastChannel.postMessage(signalData);
      } catch {}
    }

    // Emisión a través de relays de Nostr
    const content = JSON.stringify(signalData);
    const nostrEvent = {
      kind: 20000,
      created_at: Math.floor(Date.now() / 1000),
      tags: [['d', this.roomId]],
      content: content,
      pubkey: this.identity.fingerprint.repeat(8) // Clave simulada para canal efímero
    };

    for (const ws of this.nostrSockets) {
      if (ws.readyState === WebSocket.OPEN) {
        try {
          ws.send(JSON.stringify(['EVENT', nostrEvent]));
        } catch {}
      }
    }

    // Emisión a través del WebSocket nativo en Cloudflare Workers (chat.filthysilver.net)
    if (this.cloudflareSocket && this.cloudflareSocket.readyState === WebSocket.OPEN) {
      try {
        this.cloudflareSocket.send(content);
      } catch {}
    }
  }

  /**
   * Procesa señales recibidas (Ofertas SDP, Respuestas SDP, Anuncios).
   * @private
   */
  async _handleSignal(signal) {
    if (!signal || signal.roomId !== this.roomId || signal.from === this.peerId) {
      return;
    }

    const { type, from, to } = signal;

    // Si la señal está dirigida a un peer específico y no soy yo, la ignoro
    if (to && to !== this.peerId) return;

    // 1. Alguien nuevo anuncia su presencia: el peer con ID menor inicia la conexión (evita colisiones)
    if (type === 'ANNOUNCE_PRESENCE') {
      if (this.peerId < from && !this.peers.has(from)) {
        this._initiatePeerConnection(from, signal);
      } else if (!this.peers.has(from)) {
        // Le respondemos para que sepa que estamos aquí
        this._broadcastSignal({
          type: 'ANNOUNCE_PRESENCE',
          from: this.peerId,
          to: from,
          publicSpki: this.identity.publicSpki,
          nickname: this.identity.nickname
        });
      }
      return;
    }

    // 2. Recepción de oferta WebRTC
    if (type === 'OFFER') {
      await this._handleOffer(signal);
      return;
    }

    // 3. Recepción de respuesta WebRTC
    if (type === 'ANSWER') {
      await this._handleAnswer(signal);
      return;
    }

    // 4. Recepción de candidato ICE
    if (type === 'ICE_CANDIDATE') {
      await this._handleIceCandidate(signal);
      return;
    }
  }

  /**
   * Inicia una conexión WebRTC hacia un peer como emisor (Offer).
   * @private
   */
  async _initiatePeerConnection(targetPeerId, targetProfile) {
    if (this.peers.has(targetPeerId)) return;

    const pc = new RTCPeerConnection({ iceServers: DEFAULT_ICE_SERVERS });
    const dataChannel = pc.createDataChannel('chat_data', { ordered: true });

    const peerObj = {
      peerConnection: pc,
      dataChannel,
      profile: {
        id: targetPeerId,
        nickname: targetProfile.nickname || `Peer#${targetPeerId.slice(0, 4)}`,
        publicSpki: targetProfile.publicSpki
      }
    };
    this.peers.set(targetPeerId, peerObj);

    this._setupDataChannelEvents(dataChannel, targetPeerId);
    this._setupPeerConnectionEvents(pc, targetPeerId);

    try {
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);

      this._broadcastSignal({
        type: 'OFFER',
        from: this.peerId,
        to: targetPeerId,
        sdp: pc.localDescription,
        publicSpki: this.identity.publicSpki,
        nickname: this.identity.nickname
      });
    } catch (err) {
      console.warn(`[P2P] Error creando oferta a ${targetPeerId}:`, err);
      this.peers.delete(targetPeerId);
    }
  }

  /**
   * Procesa una oferta WebRTC entrante (Answer).
   * @private
   */
  async _handleOffer(signal) {
    const fromPeerId = signal.from;
    let peerObj = this.peers.get(fromPeerId);

    if (!peerObj) {
      const pc = new RTCPeerConnection({ iceServers: DEFAULT_ICE_SERVERS });
      peerObj = {
        peerConnection: pc,
        dataChannel: null,
        profile: {
          id: fromPeerId,
          nickname: signal.nickname || `Peer#${fromPeerId.slice(0, 4)}`,
          publicSpki: signal.publicSpki
        }
      };
      this.peers.set(fromPeerId, peerObj);

      pc.ondatachannel = (e) => {
        peerObj.dataChannel = e.channel;
        this._setupDataChannelEvents(e.channel, fromPeerId);
      };

      this._setupPeerConnectionEvents(pc, fromPeerId);
    }

    const pc = peerObj.peerConnection;
    await pc.setRemoteDescription(new RTCSessionDescription(signal.sdp));

    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);

    this._broadcastSignal({
      type: 'ANSWER',
      from: this.peerId,
      to: fromPeerId,
      sdp: pc.localDescription,
      publicSpki: this.identity.publicSpki,
      nickname: this.identity.nickname
    });
  }

  /**
   * Procesa la respuesta de un peer remoto a nuestra oferta.
   * @private
   */
  async _handleAnswer(signal) {
    const peerObj = this.peers.get(signal.from);
    if (!peerObj || !peerObj.peerConnection) return;

    if (peerObj.peerConnection.signalingState !== 'stable') {
      await peerObj.peerConnection.setRemoteDescription(new RTCSessionDescription(signal.sdp));
    }
  }

  /**
   * Procesa un candidato ICE de red recibido.
   * @private
   */
  async _handleIceCandidate(signal) {
    const peerObj = this.peers.get(signal.from);
    if (!peerObj || !peerObj.peerConnection) return;

    try {
      if (signal.candidate) {
        await peerObj.peerConnection.addIceCandidate(new RTCIceCandidate(signal.candidate));
      }
    } catch {}
  }

  /**
   * Configura eventos del DataChannel P2P.
   * @private
   */
  _setupDataChannelEvents(channel, peerId) {
    channel.onopen = () => {
      const peerObj = this.peers.get(peerId);
      this.onStatusChange('connected', `Conectado con ${this.peers.size} compañero(s)`);
      if (peerObj) {
        this.onPeerJoin(peerObj.profile);
        // Le enviamos nuestro perfil actualizado inmediatamente (con credencial de moderador si existe)
        this._sendDirect(channel, {
          type: 'HELLO_HANDSHAKE',
          nickname: this.identity.nickname,
          publicSpki: this.identity.publicSpki,
          moderatorCertificate: this.moderatorCertificate
        });
      }
    };

    channel.onclose = () => {
      this._handlePeerDisconnected(peerId);
    };

    channel.onmessage = async (event) => {
      try {
        const payload = JSON.parse(event.data);
        await this._handleIncomingData(payload, peerId);
      } catch (err) {
        console.warn(`[P2P] Mensaje no decodificable de ${peerId}:`, err);
      }
    };
  }

  /**
   * Configura eventos de la conexión WebRTC.
   * @private
   */
  _setupPeerConnectionEvents(pc, targetPeerId) {
    pc.onicecandidate = (event) => {
      if (event.candidate) {
        this._broadcastSignal({
          type: 'ICE_CANDIDATE',
          from: this.peerId,
          to: targetPeerId,
          candidate: event.candidate
        });
      }
    };

    pc.onconnectionstatechange = () => {
      if (pc.connectionState === 'disconnected' || pc.connectionState === 'failed' || pc.connectionState === 'closed') {
        this._handlePeerDisconnected(targetPeerId);
      }
    };
  }

  /**
   * Procesa paquetes recibidos a través del canal de datos WebRTC.
   * @private
   */
  async _handleIncomingData(packet, fromPeerId) {
    const peerObj = this.peers.get(fromPeerId);

    // Sin peer registrado (p. ej. ya desconectado) no se acepta ningún paquete
    if (!peerObj || !packet || typeof packet !== 'object') return;

    // 1. Mensajes de chat firmados
    if (packet.type === 'CHAT_MESSAGE') {
      // Control anti-spam: máximo 4 mensajes cada 2 segundos por peer
      const now = Date.now();
      const history = this.peerMessageTimestamps.get(fromPeerId) || [];
      const recent = history.filter(t => now - t < 2000);
      if (recent.length >= 4) {
        console.warn(`[P2P] Ignorando mensaje por exceso de frecuencia de ${fromPeerId}`);
        return;
      }
      recent.push(now);
      this.peerMessageTimestamps.set(fromPeerId, recent);

      const { messageData, signature } = packet;
      if (!messageData || typeof messageData !== 'object' || typeof signature !== 'string') return;

      // El mensaje debe pertenecer a ESTA sala y haber sido emitido por el peer del canal:
      // evita reutilizar mensajes firmados en otras salas o atribuirlos a otro remitente.
      if (messageData.roomId !== this.roomId || messageData.senderId !== fromPeerId) {
        console.warn(`[P2P Security] Mensaje descartado: sala o remitente no coinciden (${fromPeerId}).`);
        return;
      }
      if (typeof messageData.id !== 'string' || !MESSAGE_ID_REGEX.test(messageData.id)) return;
      if (typeof messageData.text !== 'string' || messageData.text.length > MAX_MESSAGE_LENGTH) return;
      if (!Number.isFinite(messageData.timestamp)) return;

      // Anti-replay: un mismo mensaje firmado no se entrega dos veces
      const seenKey = `${fromPeerId}:${messageData.id}`;
      if (this.seenMessageIds.has(seenKey)) return;

      // Se verifica SIEMPRE con la clave autenticada del peer (vinculada a su huella en la
      // señalización), nunca con la clave que declare el propio mensaje.
      const trustedSpki = peerObj.profile.publicSpki;
      if (!trustedSpki) return;

      const isVerified = await verifyPayload(trustedSpki, messageData, signature);
      if (!isVerified) {
        // Un mensaje sin firma válida es una suplantación: no se muestra
        console.warn(`[P2P Security] Mensaje con firma inválida descartado (${fromPeerId}).`);
        return;
      }

      this.seenMessageIds.add(seenKey);
      if (this.seenMessageIds.size > MAX_SEEN_MESSAGE_IDS) {
        this.seenMessageIds.delete(this.seenMessageIds.values().next().value);
      }

      this.onMessage({
        id: messageData.id,
        text: messageData.text,
        timestamp: messageData.timestamp,
        fromPeerId: fromPeerId,
        fromNickname: peerObj.profile.nickname || `Peer#${fromPeerId.slice(0, 4)}`,
        isVerified: true,
        torbox: messageData.torbox || null
      });
      return;
    }

    // 2. Notificación de actualización de perfil/apodo y Handshake de Moderador
    if (packet.type === 'PROFILE_UPDATE' || packet.type === 'HELLO_HANDSHAKE') {
      if (!this._allowControlPacket(fromPeerId)) return;

      const oldName = peerObj.profile.nickname;
      peerObj.profile.nickname = sanitizeNickname(packet.nickname) || oldName;

      if (packet.type === 'HELLO_HANDSHAKE') {
        await this._processHandshake(packet, fromPeerId, peerObj);
      }
      this.onProfileUpdate(peerObj.profile, oldName);
      return;
    }

    // 3. Orden administrativa de borrado de mensaje
    if (packet.type === 'ADMIN_DELETE_MESSAGE') {
      if (!this._allowControlPacket(fromPeerId)) return;
      const { messageId, adminSpki, signature, timestamp, moderatorCertificate } = packet;

      if (packet.roomId !== this.roomId || typeof messageId !== 'string' ||
          typeof adminSpki !== 'string' || typeof signature !== 'string' ||
          !isFreshTimestamp(timestamp, ADMIN_ACTION_MAX_SKEW_MS)) {
        return;
      }

      // 1. Verificar autorización legítima de moderador (Raíz o Delegado)
      const auth = await isAuthorizedModerator(
        adminSpki,
        this.roomId,
        'DELETE_MESSAGE',
        this.trustedAdminFingerprints,
        moderatorCertificate
      );
      if (!auth.authorized) {
        console.warn(`[P2P Moderation Security] Intento no autorizado de borrado de mensaje: ${auth.reason}`);
        return;
      }

      // 2. Verificar firma del payload de acción (ligado a sala + frescura: anti-replay)
      const isValid = await verifyPayload(
        adminSpki,
        { type: 'ADMIN_DELETE_MESSAGE', roomId: this.roomId, messageId, timestamp },
        signature
      );
      if (isValid) {
        this.onMessageDeleted(messageId);
      }
      return;
    }

    // 4. Orden administrativa de expulsión de sala (KICK)
    if (packet.type === 'ADMIN_KICK') {
      if (!this._allowControlPacket(fromPeerId)) return;
      const { targetPeerId, reason, adminSpki, signature, timestamp, moderatorCertificate } = packet;

      if (packet.roomId !== this.roomId || typeof targetPeerId !== 'string' ||
          typeof adminSpki !== 'string' || typeof signature !== 'string' ||
          !isFreshTimestamp(timestamp, ADMIN_ACTION_MAX_SKEW_MS)) {
        return;
      }

      // 1. Verificar autorización legítima de moderador (Raíz o Delegado)
      const auth = await isAuthorizedModerator(
        adminSpki,
        this.roomId,
        'KICK',
        this.trustedAdminFingerprints,
        moderatorCertificate
      );
      if (!auth.authorized) {
        console.warn(`[P2P Moderation Security] Intento no autorizado de expulsión (KICK): ${auth.reason}`);
        return;
      }

      // 2. Verificar firma de la orden de expulsión (ligada a sala + frescura: anti-replay)
      const isValid = await verifyPayload(
        adminSpki,
        { type: 'ADMIN_KICK', roomId: this.roomId, targetPeerId, reason: reason ?? '', timestamp },
        signature
      );
      if (isValid) {
        if (targetPeerId === this.peerId) {
          this.destroy();
          this.onKicked(String(reason || 'Has sido expulsado de la sala por un moderador.').slice(0, 200));
        } else {
          this._handlePeerDisconnected(targetPeerId);
        }
      }
      return;
    }

    // 5. Transferencia de archivos P2P (FileDrop con certificación de autoría)
    if (packet.type === 'FILE_START') {
      const { fileId, fileSize, totalChunks, fileHash } = packet;

      // Validación estricta de metadatos: el emisor es no confiable
      if (typeof fileId !== 'string' || !FILE_ID_REGEX.test(fileId)) return;
      if (!Number.isInteger(fileSize) || fileSize < 0 || fileSize > MAX_FILE_SIZE) {
        console.warn('[P2P FileDrop] Archivo rechazado por tamaño inválido o superior al máximo permitido (2 GB).');
        return;
      }
      // El número de trozos debe ser coherente con el tamaño declarado (evita buffers sobredimensionados)
      if (!Number.isInteger(totalChunks) || totalChunks !== Math.ceil(fileSize / FILE_CHUNK_SIZE)) return;
      if (typeof fileHash !== 'string' || !/^[0-9a-f]{64}$/.test(fileHash)) return;
      if (this.incomingFileTransfers.has(fileId)) return; // no se puede pisar una transferencia en curso

      // Prevención DoS: límite global y por peer de transferencias simultáneas
      if (this.incomingFileTransfers.size >= MAX_CONCURRENT_TRANSFERS) {
        console.warn('[P2P FileDrop] Rechazando transferencia: límite de transferencias concurrentes alcanzado.');
        return;
      }
      let fromThisPeer = 0;
      for (const t of this.incomingFileTransfers.values()) {
        if (t.fromPeerId === fromPeerId) fromThisPeer++;
      }
      if (fromThisPeer >= MAX_TRANSFERS_PER_PEER) return;

      this.incomingFileTransfers.set(fileId, {
        fromPeerId, // las transferencias quedan ligadas al peer que las inició
        meta: {
          fileId,
          fileName: sanitizeFileName(packet.fileName),
          fileSize,
          mimeType: typeof packet.mimeType === 'string' ? packet.mimeType.slice(0, 100) : 'application/octet-stream',
          fileHash,
          authorshipCertificate: packet.authorshipCertificate || null,
          timestamp: Number.isFinite(packet.timestamp) ? packet.timestamp : Date.now()
        },
        receivedChunks: new Map(),
        totalChunks,
        fileHash,
        lastActivity: Date.now()
      });
      return;
    }

    if (packet.type === 'FILE_CHUNK') {
      const transfer = this.incomingFileTransfers.get(packet.fileId);
      if (transfer && transfer.fromPeerId === fromPeerId) {
        // Validar índice de chunk dentro del rango esperado y tamaño del fragmento
        if (!Number.isInteger(packet.chunkIndex) || packet.chunkIndex < 0 || packet.chunkIndex >= transfer.totalChunks) {
          return;
        }
        if (typeof packet.data !== 'string' || packet.data.length > MAX_CHUNK_BASE64_LENGTH) return;

        let decoded;
        try {
          decoded = base64ToBuffer(packet.data);
        } catch {
          return;
        }
        if (decoded.byteLength > FILE_CHUNK_SIZE) return;

        transfer.receivedChunks.set(packet.chunkIndex, decoded);
        transfer.lastActivity = Date.now();
        this.onFileProgress(packet.fileId, transfer.receivedChunks.size / transfer.totalChunks);
      }
      return;
    }

    if (packet.type === 'FILE_END') {
      const transfer = this.incomingFileTransfers.get(packet.fileId);
      if (!transfer || transfer.fromPeerId !== fromPeerId) return;

      if (transfer.receivedChunks.size !== transfer.totalChunks) {
        // El emisor declara fin pero faltan trozos: transferencia inservible, se libera memoria ya
        console.warn(`[P2P FileDrop] Transferencia incompleta descartada: ${packet.fileId}`);
        transfer.receivedChunks.clear();
        this.incomingFileTransfers.delete(packet.fileId);
        return;
      }

      // En vez de un Uint8Array contiguo gigante que duplica el consumo de RAM en archivos 3D,
      // pasamos el array de ArrayBuffers directamente a Blob
      const chunks = [];
      let receivedBytes = 0;
      for (let i = 0; i < transfer.totalChunks; i++) {
        const chunk = transfer.receivedChunks.get(i);
        receivedBytes += chunk.byteLength;
        chunks.push(chunk);
      }

      // Se libera ya la transferencia: evita doble procesamiento por FILE_END repetidos
      this.incomingFileTransfers.delete(packet.fileId);

      if (receivedBytes !== transfer.meta.fileSize) {
        console.warn(`[P2P FileDrop] Tamaño recibido no coincide con el declarado: ${packet.fileId}`);
        transfer.receivedChunks.clear();
        return;
      }

      // El mimeType lo declara el emisor (no confiable): se fuerza un tipo binario neutro para que el
      // navegador jamás interprete el blob como HTML/SVG/JS (XSS por blob: de mismo origen).
      const blob = new Blob(chunks, { type: 'application/octet-stream' });
      // Liberar mapa de fragmentos inmediatamente para aliviar el heap
      transfer.receivedChunks.clear();

      const arrayBuffer = await blob.arrayBuffer();
      const actualHash = await computeFileHash(arrayBuffer);
      const isValidHash = (actualHash === transfer.meta.fileHash);

      let authorshipInfo = { valid: false };
      if (transfer.meta.authorshipCertificate) {
        authorshipInfo = await verifyFileAuthorshipCertificate(transfer.meta.authorshipCertificate, transfer.meta.fileHash);
      }

      // Si la sala se destruyó durante la verificación asíncrona no se crea ningún blob URL huérfano
      if (this.isDestroyed) return;

      const blobUrl = URL.createObjectURL(blob);

      this.onFileReceived({
        fileId: transfer.meta.fileId,
        fileName: transfer.meta.fileName,
        fileSize: transfer.meta.fileSize,
        mimeType: transfer.meta.mimeType,
        fileHash: transfer.meta.fileHash,
        blobUrl,
        isValidHash,
        authorship: authorshipInfo,
        fromPeerId,
        fromNickname: peerObj.profile.nickname || `Peer#${fromPeerId.slice(0, 4)}`,
        timestamp: transfer.meta.timestamp
      });
      return;
    }
  }

  /**
   * Limita el ritmo de paquetes de control (perfil, handshake, órdenes de moderación) por peer.
   * Cada uno puede implicar verificaciones criptográficas costosas (vector de DoS de CPU).
   * @private
   * @returns {boolean} true si el paquete puede procesarse
   */
  _allowControlPacket(peerId) {
    const now = Date.now();
    const recent = (this.peerControlTimestamps.get(peerId) || []).filter(t => now - t < CONTROL_RATE_WINDOW_MS);
    if (recent.length >= CONTROL_RATE_MAX) {
      console.warn(`[P2P] Paquetes de control limitados por exceso de frecuencia de ${peerId}`);
      return false;
    }
    recent.push(now);
    this.peerControlTimestamps.set(peerId, recent);
    return true;
  }

  /**
   * Procesa el handshake de un peer: valida que su clave pública corresponde a su identidad,
   * exige prueba de posesión de la clave privada y solo entonces reconoce roles de moderación.
   * @private
   */
  async _processHandshake(packet, fromPeerId, peerObj) {
    const spki = packet.publicSpki;
    if (typeof spki !== 'string' || spki.length === 0 || spki.length > MAX_SPKI_LENGTH) return;

    // La clave presentada debe corresponder a la identidad (huella) de este canal
    let fp;
    try {
      fp = await getFingerprint(spki);
    } catch {
      return;
    }
    if (fp !== fromPeerId) return;

    // Prueba de posesión: firma fresca ligada a (sala, emisor, receptor). Sin ella cualquiera podría
    // presentar la clave pública (que es pública) de un administrador raíz y aparentar ser moderador.
    if (typeof packet.signature !== 'string' || !isFreshTimestamp(packet.timestamp, HANDSHAKE_MAX_SKEW_MS)) return;
    const proofOk = await verifyPayload(
      spki,
      { type: 'HELLO_HANDSHAKE', roomId: this.roomId, from: fromPeerId, to: this.peerId, timestamp: packet.timestamp },
      packet.signature
    );
    if (!proofOk) return;

    peerObj.profile.publicSpki = spki;

    // Verificar si es Administrador Raíz directo
    if (this.trustedAdminFingerprints.includes(fp)) {
      peerObj.profile.isModerator = true;
      peerObj.profile.moderatorRole = 'root';
    } else if (packet.moderatorCertificate) {
      // Verificar si presenta un Certificado de Delegación válido (emitido a SU clave pública)
      const certCheck = await verifyModeratorCertificate(packet.moderatorCertificate, this.trustedAdminFingerprints);
      if (certCheck.valid && certCheck.payload.moderatorPublicSpki === spki) {
        peerObj.profile.isModerator = true;
        peerObj.profile.moderatorRole = 'delegated';
        peerObj.profile.moderatorCertificate = packet.moderatorCertificate;
      }
    }
  }

  /**
   * Envía el handshake firmado (con prueba de posesión de clave) por el canal indicado.
   * @private
   */
  async _sendHandshake(channel, remotePeerId) {
    const timestamp = Date.now();
    let signature = null;
    try {
      signature = await signPayload(this.identity.privateKey, {
        type: 'HELLO_HANDSHAKE',
        roomId: this.roomId,
        from: this.peerId,
        to: remotePeerId,
        timestamp
      });
    } catch (err) {
      console.warn('[P2P] No se pudo firmar el handshake:', err);
    }
    if (this.isDestroyed) return;

    // Le enviamos nuestro perfil actualizado (con credencial de moderador si existe)
    this._sendDirect(channel, {
      type: 'HELLO_HANDSHAKE',
      nickname: this.identity.nickname,
      publicSpki: this.identity.publicSpki,
      moderatorCertificate: this.moderatorCertificate,
      timestamp,
      signature
    });
  }

  /**
   * Maneja la desconexión de un compañero.
   * @private
   */
  _handlePeerDisconnected(peerId) {
    const peerObj = this.peers.get(peerId);
    if (peerObj) {
      this.peers.delete(peerId);
      this._teardownPeer(peerObj);

      this.peerMessageTimestamps.delete(peerId);
      this.peerControlTimestamps.delete(peerId);
      this.pendingIceCandidates.delete(peerId);

      // Descartar transferencias de archivo incompletas del peer que se fue
      for (const [fileId, transfer] of this.incomingFileTransfers.entries()) {
        if (transfer.fromPeerId === peerId) {
          transfer.receivedChunks?.clear();
          this.incomingFileTransfers.delete(fileId);
        }
      }

      if (this.isDestroyed) return;
      this.onPeerLeave(peerObj.profile);

      if (this.peers.size === 0) {
        this.onStatusChange('ready', 'Esperando a que otros compañeros se unan...');
      } else {
        this.onStatusChange('connected', `Conectado con ${this.peers.size} compañero(s)`);
      }
    }
  }

  /**
   * Envía un mensaje de chat a todos los compañeros conectados en la sala.
   * El mensaje se firma criptográficamente antes de transmitirse.
   * @param {string} text
   * @param {Object} [torbox=null] - Metadatos opcionales de Torbox DDL Card
   * @returns {Promise<Object>} Datos del mensaje enviado
   */
  async sendMessage(text, torbox = null) {
    const messageData = {
      id: `msg_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`,
      roomId: this.roomId,
      senderId: this.peerId,
      publicSpki: this.identity.publicSpki,
      text: text.trim(),
      timestamp: Date.now()
    };

    if (torbox) {
      messageData.torbox = torbox;
    }

    // Firma con la clave privada local
    const signature = await signPayload(this.identity.privateKey, messageData);

    const packet = {
      type: 'CHAT_MESSAGE',
      messageData,
      signature
    };

    const packetJson = JSON.stringify(packet);

    // Retransmisión a través de todos los DataChannels abiertos
    let sentCount = 0;
    for (const [_, peerObj] of this.peers.entries()) {
      if (peerObj.dataChannel && peerObj.dataChannel.readyState === 'open') {
        try {
          peerObj.dataChannel.send(packetJson);
          sentCount++;
        } catch (e) {
          console.warn('[P2P] Error enviando a peer:', e);
        }
      }
    }

    return {
      ...messageData,
      fromNickname: this.identity.nickname,
      isVerified: true,
      deliveredTo: sentCount
    };
  }

  /**
   * Envía una actualización de apodo a todos los compañeros de la sala.
   * @param {string} newNickname
   */
  async broadcastNicknameChange(newNickname) {
    this.identity.nickname = newNickname;

    const packet = {
      type: 'PROFILE_UPDATE',
      nickname: newNickname,
      fromPeerId: this.peerId,
      timestamp: Date.now()
    };

    const packetJson = JSON.stringify(packet);
    for (const [_, peerObj] of this.peers.entries()) {
      if (peerObj.dataChannel && peerObj.dataChannel.readyState === 'open') {
        try {
          peerObj.dataChannel.send(packetJson);
        } catch {}
      }
    }
  }

  /**
   * Emite una orden administrativa de borrado de mensaje firmada por el moderador.
   * @param {string} messageId
   * @param {CryptoKey} adminPrivateKey
   * @param {string} adminPublicSpki
   */
  async broadcastAdminDelete(messageId, adminPrivateKey, adminPublicSpki) {
    const timestamp = Date.now();
    const signature = await signPayload(adminPrivateKey, {
      type: 'ADMIN_DELETE_MESSAGE',
      roomId: this.roomId,
      messageId,
      timestamp
    });
    const packet = {
      type: 'ADMIN_DELETE_MESSAGE',
      roomId: this.roomId,
      messageId,
      adminSpki: adminPublicSpki,
      signature,
      timestamp,
      moderatorCertificate: this.moderatorCertificate
    };
    this._broadcastPacket(packet);
    this.onMessageDeleted(messageId);
  }

  /**
   * Emite una orden administrativa de expulsión firmada por el moderador.
   * @param {string} targetPeerId
   * @param {string} reason
   * @param {CryptoKey} adminPrivateKey
   * @param {string} adminPublicSpki
   */
  async broadcastAdminKick(targetPeerId, reason, adminPrivateKey, adminPublicSpki) {
    const timestamp = Date.now();
    const safeReason = String(reason ?? '').slice(0, 200);
    const signature = await signPayload(adminPrivateKey, {
      type: 'ADMIN_KICK',
      roomId: this.roomId,
      targetPeerId,
      reason: safeReason,
      timestamp
    });
    const packet = {
      type: 'ADMIN_KICK',
      roomId: this.roomId,
      targetPeerId,
      reason: safeReason,
      adminSpki: adminPublicSpki,
      signature,
      timestamp,
      moderatorCertificate: this.moderatorCertificate
    };
    this._broadcastPacket(packet);
    this._handlePeerDisconnected(targetPeerId);
  }

  /**
   * Envía un archivo P2P a todos los compañeros en trozos de 16KB
   * con certificado de autoría firmado digitalmente.
   * @param {File|Blob} file
   * @returns {Promise<Object>} Datos del archivo enviado
   */
  async sendFile(file) {
    const arrayBuffer = await file.arrayBuffer();
    const fileHash = await computeFileHash(arrayBuffer);
    const authorshipCertificate = await createFileAuthorshipCertificate(
      fileHash,
      file.name,
      file.size,
      this.identity.privateKey,
      this.identity.publicSpki,
      this.identity.nickname
    );

    const fileId = `file_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`;
    const totalChunks = Math.ceil(arrayBuffer.byteLength / FILE_CHUNK_SIZE);

    const safeFileName = sanitizeFileName(file.name);

    // 1. Emitir metadatos y certificado
    this._broadcastPacket({
      type: 'FILE_START',
      fileId,
      fileName: safeFileName,
      fileSize: file.size,
      mimeType: file.type || 'application/octet-stream',
      fileHash,
      totalChunks,
      authorshipCertificate,
      fromPeerId: this.peerId,
      fromNickname: this.identity.nickname,
      timestamp: Date.now()
    });

    // 2. Transmitir trozos con control de contrapresión (Backpressure)
    const abandonedPeers = new Set();
    for (let i = 0; i < totalChunks; i++) {
      if (this.isDestroyed) throw new Error('La sala se cerró durante la transferencia');

      const start = i * FILE_CHUNK_SIZE;
      const end = Math.min(start + FILE_CHUNK_SIZE, arrayBuffer.byteLength);
      const chunkBuf = arrayBuffer.slice(start, end);

      const packet = {
        type: 'FILE_CHUNK',
        fileId,
        chunkIndex: i,
        data: bufferToBase64(chunkBuf)
      };

      const packetJson = JSON.stringify(packet);

      for (const [peerId, peerObj] of this.peers.entries()) {
        if (abandonedPeers.has(peerId)) continue;
        if (peerObj.dataChannel && peerObj.dataChannel.readyState === 'open') {
          const canSend = await this._waitForBackpressure(peerObj.dataChannel);
          if (!canSend) {
            // Canal cerrado o atascado: se abandona a este peer (recibiría un archivo incompleto)
            abandonedPeers.add(peerId);
            console.warn(`[P2P FileDrop] Abandonando envío a ${peerId}: canal cerrado o saturado.`);
            continue;
          }
          try {
            peerObj.dataChannel.send(packetJson);
          } catch {
            abandonedPeers.add(peerId);
          }
        }
      }
    }

    // 3. Emitir fin de transmisión
    this._broadcastPacket({
      type: 'FILE_END',
      fileId
    });

    return {
      fileId,
      fileName: safeFileName,
      fileSize: file.size,
      mimeType: file.type,
      fileHash,
      authorshipCertificate,
      timestamp: Date.now(),
      fromNickname: this.identity.nickname
    };
  }

  /**
   * Retransmite un paquete JSON a todos los DataChannels abiertos.
   * @private
   */
  _broadcastPacket(packet) {
    const packetJson = JSON.stringify(packet);
    for (const [_, peerObj] of this.peers.entries()) {
      if (peerObj.dataChannel && peerObj.dataChannel.readyState === 'open') {
        try {
          peerObj.dataChannel.send(packetJson);
        } catch {}
      }
    }
  }

  /**
   * Control de contrapresión (Backpressure): espera a que el búfer del canal baje del umbral bajo.
   * @private
   * @param {RTCDataChannel} channel
   * @param {number} [timeoutMs=10000] - Tiempo máximo de espera antes de dar el canal por atascado
   * @returns {Promise<boolean>} true si se puede seguir enviando; false si el canal se cerró o se atascó
   */
  _waitForBackpressure(channel, timeoutMs = BACKPRESSURE_TIMEOUT_MS) {
    if (!channel || channel.readyState !== 'open') return Promise.resolve(false);
    if (channel.bufferedAmount <= BACKPRESSURE_HIGH) return Promise.resolve(true);

    return new Promise(resolve => {
      let timer = null;

      const cleanup = () => {
        clearTimeout(timer);
        channel.removeEventListener('bufferedamountlow', onLow);
        channel.removeEventListener('close', onClosed);
        channel.removeEventListener('error', onClosed);
      };
      const onLow = () => { cleanup(); resolve(true); };
      const onClosed = () => { cleanup(); resolve(false); };

      channel.bufferedAmountLowThreshold = BACKPRESSURE_LOW;
      channel.addEventListener('bufferedamountlow', onLow);
      channel.addEventListener('close', onClosed);
      channel.addEventListener('error', onClosed);

      // Salvaguarda ante eventos perdidos: solo continuar si el búfer realmente se ha vaciado
      timer = setTimeout(() => {
        cleanup();
        resolve(channel.readyState === 'open' && channel.bufferedAmount <= BACKPRESSURE_HIGH);
      }, timeoutMs);
    });
  }

  /**
   * Envía datos directamente por un canal específico.
   * @private
   */
  _sendDirect(channel, data) {
    if (channel && channel.readyState === 'open') {
      try {
        channel.send(JSON.stringify(data));
      } catch {}
    }
  }

  /**
   * Cierra todas las conexiones y destruye la sala.
   */
  destroy() {
    if (this.isDestroyed) return;
    this.isDestroyed = true;

    if (this._transferCleanupInterval) {
      clearInterval(this._transferCleanupInterval);
      this._transferCleanupInterval = null;
    }

    if (this._readyTimer) {
      clearTimeout(this._readyTimer);
      this._readyTimer = null;
    }

    if (this._cloudflareReconnectTimer) {
      clearTimeout(this._cloudflareReconnectTimer);
      this._cloudflareReconnectTimer = null;
    }

    for (const [_, timer] of this._nostrReconnectTimers.entries()) {
      clearTimeout(timer);
    }
    this._nostrReconnectTimers.clear();

    for (const [_, transfer] of this.incomingFileTransfers.entries()) {
      transfer.receivedChunks?.clear();
    }
    this.incomingFileTransfers.clear();

    if (this.broadcastChannel) {
      try {
        this.broadcastChannel.onmessage = null;
        this.broadcastChannel.close();
      } catch {}
      this.broadcastChannel = null;
    }

    if (this.cloudflareSocket) {
      this._detachSocket(this.cloudflareSocket);
      try {
        this.cloudflareSocket.close();
      } catch {}
      this.cloudflareSocket = null;
    }

    for (const ws of this.nostrSockets) {
      this._detachSocket(ws);
      try {
        ws.close();
      } catch {}
    }
    this.nostrSockets = [];

    for (const [_, peerObj] of this.peers.entries()) {
      this._teardownPeer(peerObj);
    }
    this.peers.clear();
    this.peerMessageTimestamps.clear();
    this.peerControlTimestamps.clear();
    this.pendingIceCandidates.clear();
    this.seenMessageIds.clear();
  }

  /**
   * Quita los handlers de un WebSocket para soltar referencias (evita fugas y callbacks tardíos).
   * @private
   */
  _detachSocket(ws) {
    try {
      ws.onopen = null;
      ws.onmessage = null;
      ws.onclose = null;
      ws.onerror = null;
    } catch {}
  }

  /**
   * Cierra DataChannel + RTCPeerConnection de un peer y desengancha sus handlers.
   * @private
   */
  _teardownPeer(peerObj) {
    if (!peerObj) return;
    const channel = peerObj.dataChannel;
    if (channel) {
      try {
        channel.onopen = null;
        channel.onclose = null;
        channel.onmessage = null;
        channel.onerror = null;
        channel.close();
      } catch {}
    }
    const pc = peerObj.peerConnection;
    if (pc) {
      try {
        pc.onicecandidate = null;
        pc.onconnectionstatechange = null;
        pc.ondatachannel = null;
        pc.close();
      } catch {}
    }
  }
}

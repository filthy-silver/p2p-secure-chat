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
    this.nostrSockets = [];
    this._nostrReconnectTimers = new Map();
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
    this._initCloudflareSignaling();

    // 4. Conexión a relays públicos Nostr como fallback
    this._initNostrSignaling();

    // Notificar estado inicial listo
    setTimeout(() => {
      if (!this.isDestroyed && this.peers.size === 0) {
        this.onStatusChange('ready', 'Sala abierta. Esperando a que otros compañeros se unan...');
      }
    }, 1500);
  }

  /**
   * Conecta con la API de señalización nativa de Cloudflare Workers (chat.filthysilver.net).
   * @private
   */
  _initCloudflareSignaling() {
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
          setTimeout(() => {
            if (!this.isDestroyed) this._initCloudflareSignaling();
          }, 4000);
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

    // Control anti-spam: máximo 4 mensajes cada 2 segundos por peer
    if (packet.type === 'CHAT_MESSAGE') {
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

      // Verificamos la firma criptográfica con la clave pública del emisor
      const isVerified = await verifyPayload(
        peerObj?.profile.publicSpki || messageData.publicSpki,
        messageData,
        signature
      );

      this.onMessage({
        id: messageData.id,
        text: messageData.text,
        timestamp: messageData.timestamp,
        fromPeerId: fromPeerId,
        fromNickname: peerObj?.profile.nickname || `Peer#${fromPeerId.slice(0, 4)}`,
        isVerified
      });
      return;
    }

    // 2. Notificación de actualización de perfil/apodo y Handshake de Moderador
    if (packet.type === 'PROFILE_UPDATE' || packet.type === 'HELLO_HANDSHAKE') {
      if (peerObj) {
        const oldName = peerObj.profile.nickname;
        peerObj.profile.nickname = packet.nickname || oldName;
        if (packet.publicSpki) {
          peerObj.profile.publicSpki = packet.publicSpki;
          const fp = await getFingerprint(packet.publicSpki);

          // Verificar si es Administrador Raíz directo
          if (this.trustedAdminFingerprints.includes(fp)) {
            peerObj.profile.isModerator = true;
            peerObj.profile.moderatorRole = 'root';
          } else if (packet.moderatorCertificate) {
            // Verificar si presenta un Certificado de Delegación válido
            const certCheck = await verifyModeratorCertificate(packet.moderatorCertificate, this.trustedAdminFingerprints);
            if (certCheck.valid && certCheck.payload.moderatorSpki === packet.publicSpki) {
              peerObj.profile.isModerator = true;
              peerObj.profile.moderatorRole = 'delegated';
              peerObj.profile.moderatorCertificate = packet.moderatorCertificate;
            }
          }
        }
        this.onProfileUpdate(peerObj.profile, oldName);
      }
      return;
    }

    // 3. Orden administrativa de borrado de mensaje
    if (packet.type === 'ADMIN_DELETE_MESSAGE') {
      const { messageId, adminSpki, signature, timestamp, moderatorCertificate } = packet;

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

      // 2. Verificar firma del payload de acción
      const isValid = await verifyPayload(adminSpki, { type: 'ADMIN_DELETE_MESSAGE', messageId, timestamp }, signature);
      if (isValid) {
        this.onMessageDeleted(messageId);
      }
      return;
    }

    // 4. Orden administrativa de expulsión de sala (KICK)
    if (packet.type === 'ADMIN_KICK') {
      const { targetPeerId, reason, adminSpki, signature, timestamp, moderatorCertificate } = packet;

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

      // 2. Verificar firma de la orden de expulsión
      const isValid = await verifyPayload(adminSpki, { type: 'ADMIN_KICK', targetPeerId, reason, timestamp }, signature);
      if (isValid) {
        if (targetPeerId === this.peerId) {
          this.destroy();
          this.onKicked(reason || 'Has sido expulsado de la sala por un moderador.');
        } else {
          this._handlePeerDisconnected(targetPeerId);
        }
      }
      return;
    }

    // 5. Transferencia de archivos P2P (FileDrop con certificación de autoría)
    if (packet.type === 'FILE_START') {
      // Prevención DoS: limitar a máximo 5 transferencias simultáneas
      if (this.incomingFileTransfers.size >= 5) {
        console.warn('[P2P FileDrop] Rechazando transferencia: límite de transferencias concurrentes alcanzado.');
        return;
      }

      // Validar tamaño máximo de archivo (2 GB)
      if (packet.fileSize > 2 * 1024 * 1024 * 1024 || packet.totalChunks > 200000) {
        console.warn('[P2P FileDrop] Archivo rechazado por exceder el tamaño máximo permitido (2 GB).');
        return;
      }

      this.incomingFileTransfers.set(packet.fileId, {
        meta: packet,
        receivedChunks: new Map(),
        totalChunks: packet.totalChunks,
        fileHash: packet.fileHash,
        lastActivity: Date.now()
      });
      return;
    }

    if (packet.type === 'FILE_CHUNK') {
      const transfer = this.incomingFileTransfers.get(packet.fileId);
      if (transfer) {
        // Validar índice de chunk dentro del rango esperado
        if (typeof packet.chunkIndex !== 'number' || packet.chunkIndex < 0 || packet.chunkIndex >= transfer.totalChunks) {
          return;
        }
        transfer.receivedChunks.set(packet.chunkIndex, base64ToBuffer(packet.data));
        transfer.lastActivity = Date.now();
        this.onFileProgress(packet.fileId, transfer.receivedChunks.size / transfer.totalChunks);
      }
      return;
    }

    if (packet.type === 'FILE_END') {
      const transfer = this.incomingFileTransfers.get(packet.fileId);
      if (transfer && transfer.receivedChunks.size === transfer.totalChunks) {
        // En vez de un Uint8Array contiguo gigante que duplica el consumo de RAM en archivos 3D,
        // pasamos el array de ArrayBuffers directamente a Blob
        const chunks = [];
        for (let i = 0; i < transfer.totalChunks; i++) {
          chunks.push(transfer.receivedChunks.get(i));
        }

        const blob = new Blob(chunks, { type: transfer.meta.mimeType || 'application/octet-stream' });
        // Liberar mapa de fragmentos inmediatamente para aliviar el heap
        transfer.receivedChunks.clear();

        const arrayBuffer = await blob.arrayBuffer();
        const actualHash = await computeFileHash(arrayBuffer);
        const isValidHash = (actualHash === transfer.meta.fileHash);

        let authorshipInfo = { valid: false };
        if (transfer.meta.authorshipCertificate) {
          authorshipInfo = await verifyFileAuthorshipCertificate(transfer.meta.authorshipCertificate, transfer.meta.fileHash);
        }

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
          fromNickname: peerObj?.profile.nickname || `Peer#${fromPeerId.slice(0, 4)}`,
          timestamp: transfer.meta.timestamp || Date.now()
        });

        this.incomingFileTransfers.delete(packet.fileId);
      }
      return;
    }
  }

  /**
   * Maneja la desconexión de un compañero.
   * @private
   */
  _handlePeerDisconnected(peerId) {
    const peerObj = this.peers.get(peerId);
    if (peerObj) {
      try {
        peerObj.peerConnection?.close();
      } catch {}
      this.peers.delete(peerId);
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
   * @returns {Promise<Object>} Datos del mensaje enviado
   */
  async sendMessage(text) {
    const messageData = {
      id: `msg_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`,
      roomId: this.roomId,
      senderId: this.peerId,
      publicSpki: this.identity.publicSpki,
      text: text.trim(),
      timestamp: Date.now()
    };

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
    const signature = await signPayload(adminPrivateKey, { type: 'ADMIN_DELETE_MESSAGE', messageId, timestamp });
    const packet = {
      type: 'ADMIN_DELETE_MESSAGE',
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
    const signature = await signPayload(adminPrivateKey, { type: 'ADMIN_KICK', targetPeerId, reason, timestamp });
    const packet = {
      type: 'ADMIN_KICK',
      targetPeerId,
      reason,
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
    const CHUNK_SIZE = 16 * 1024; // 16 KB por trozo
    const totalChunks = Math.ceil(arrayBuffer.byteLength / CHUNK_SIZE);

    const safeFileName = file.name.replace(/[\\/:\*\?"<>\|]/g, '_').replace(/\.\.+/g, '.').trim().slice(0, 120);

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
    for (let i = 0; i < totalChunks; i++) {
      const start = i * CHUNK_SIZE;
      const end = Math.min(start + CHUNK_SIZE, arrayBuffer.byteLength);
      const chunkBuf = arrayBuffer.slice(start, end);

      const packet = {
        type: 'FILE_CHUNK',
        fileId,
        chunkIndex: i,
        data: bufferToBase64(chunkBuf)
      };

      const packetJson = JSON.stringify(packet);

      for (const [_, peerObj] of this.peers.entries()) {
        if (peerObj.dataChannel && peerObj.dataChannel.readyState === 'open') {
          await this._waitForBackpressure(peerObj.dataChannel);
          try {
            peerObj.dataChannel.send(packetJson);
          } catch {}
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
   * Control de contrapresión (Backpressure): espera si el búfer del canal supera 64KB.
   * @private
   */
  async _waitForBackpressure(channel) {
    if (!channel || channel.bufferedAmount <= 64 * 1024) return;

    return new Promise(resolve => {
      channel.bufferedAmountLowThreshold = 16 * 1024;
      const onLow = () => {
        channel.removeEventListener('bufferedamountlow', onLow);
        resolve();
      };
      channel.addEventListener('bufferedamountlow', onLow);
      setTimeout(onLow, 150);
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
    this.isDestroyed = true;

    if (this._transferCleanupInterval) {
      clearInterval(this._transferCleanupInterval);
      this._transferCleanupInterval = null;
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
        this.broadcastChannel.close();
      } catch {}
    }

    if (this.cloudflareSocket) {
      try {
        this.cloudflareSocket.close();
      } catch {}
      this.cloudflareSocket = null;
    }

    for (const ws of this.nostrSockets) {
      try {
        ws.close();
      } catch {}
    }
    this.nostrSockets = [];

    for (const [_, peerObj] of this.peers.entries()) {
      try {
        peerObj.dataChannel?.close();
        peerObj.peerConnection?.close();
      } catch {}
    }
    this.peers.clear();
  }
}

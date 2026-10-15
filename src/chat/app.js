/**
 * @file src/chat/app.js
 * @description Controlador principal de la interfaz de usuario para el Chat P2P Descentralizado.
 * Incluye soporte para rutas limpias (/chat/:room), directorio de salas oficiales,
 * herramientas de moderación criptográfica (Kicks y Borrados de mensajes), tokens de invitación,
 * árbol de invitaciones trazables con cupos por alumno, y transferencia P2P de archivos (FileDrop)
 * con Certificado Criptográfico de Autoría (Proof of Authorship).
 */

import {
  generateIdentityKeyPair,
  exportKeyPair,
  importKeyPair,
  getFingerprint,
  generateDefaultNickname,
  bytesToMnemonic,
  mnemonicToBytes,
  generateInviteToken,
  verifyInviteToken,
  computeFileHash,
  verifyModeratorCertificate,
  GENESIS_ADMIN_ROOT_FINGERPRINT,
  signPayload,
  encryptPrivateKeyWithMnemonic,
  decryptPrivateKeyWithMnemonic
} from './crypto.js';

import { escapeHtml, sanitizeUrl } from '../domain/sanitizer.js';

import {
  getTorboxKey,
  setTorboxKey,
  removeTorboxKey,
  hasTorboxKey,
  isCloudSeedingEnabled,
  setCloudSeedingEnabled,
  verifyAccount as verifyTorboxAccount,
  addMagnetOrTorrent,
  getTorrentList,
  requestDownloadLink,
  formatBytes as formatTorboxBytes,
  isMagnetLink,
  parseMagnetName
} from './torbox.js';

import {
  loadStoredIdentity,
  saveStoredIdentity,
  updateStoredNickname,
  clearStoredIdentity,
  loadRecentRooms,
  saveRecentRoom,
  loadRoomHistory,
  appendRoomHistory
} from './storage.js';

import { P2PMeshRoom } from './p2p.js';

// Salas oficiales fijadas de la comunidad
export const OFFICIAL_ROOMS = [
  { id: 'general', name: 'General', desc: 'Charla libre de la clase' },
  { id: 'dudas-3d', name: 'Dudas 3D', desc: 'Blender, Maya, texturas y modelado' },
  { id: 'entregas-aules', name: 'Entregas Aules', desc: 'Fechas límite y tareas pendientes' },
  { id: 'ocio-gaming', name: 'Ocio & Gaming', desc: 'Juegos y charlas fuera de clase' }
];

// Estado global de la aplicación
const state = {
  identity: null,    // { privateKey, publicKey, privateJwk, publicSpki, fingerprint, nickname, mnemonic }
  currentRoomId: '',
  roomInstance: null,
  peers: new Map(),  // peerId -> profile
  isAdmin: localStorage.getItem('p2p_chat_is_admin') === 'true',
  moderatorCertificate: (() => {
    try {
      return JSON.parse(localStorage.getItem('p2p_chat_mod_cert') || 'null');
    } catch {
      return null;
    }
  })(),
  isKicked: false,
  pendingMagnet: null,
  pendingTorrentFile: null
};

// Elementos del DOM reactivos
export const elements = {};

export function initElements() {
  if (typeof document === 'undefined') return;
  elements.roomTitle = document.getElementById('room-title');
  elements.connectionStatus = document.getElementById('connection-status');
  elements.statusIndicator = document.getElementById('status-indicator');
  elements.peersCountBadge = document.getElementById('peers-count-badge');
  elements.peersList = document.getElementById('peers-list');
  elements.messagesFeed = document.getElementById('messages-feed');
  elements.chatForm = document.getElementById('chat-form');
  elements.messageInput = document.getElementById('message-input');
  elements.btnSend = document.getElementById('btn-send');

  // Botones de cabecera
  elements.btnOpenTorbox = document.getElementById('btn-open-torbox');
  elements.btnOpenIdentity = document.getElementById('btn-open-identity');
  elements.btnShareRoom = document.getElementById('btn-share-room');
  elements.btnSwitchRoom = document.getElementById('btn-switch-room');

  // Transferencia de archivos
  elements.fileInput = document.getElementById('file-input');
  elements.btnAttachFile = document.getElementById('btn-attach-file');

  // Modales
  elements.identityModal = document.getElementById('identity-modal');
  elements.shareModal = document.getElementById('share-modal');
  elements.switchRoomModal = document.getElementById('switch-room-modal');
  elements.modalTorboxSettings = document.getElementById('modal-torbox-settings');

  // Elementos del modal de Torbox
  elements.torboxApiKeyInput = document.getElementById('torbox-api-key-input');
  elements.btnToggleTorboxKeyVis = document.getElementById('btn-toggle-torbox-key-vis');
  elements.btnVerifyTorbox = document.getElementById('btn-verify-torbox');
  elements.torboxStatusCard = document.getElementById('torbox-status-card');
  elements.torboxPlanBadge = document.getElementById('torbox-plan-badge');
  elements.torboxUserEmail = document.getElementById('torbox-user-email');
  elements.torboxActiveSlots = document.getElementById('torbox-active-slots');
  elements.torboxDownloadLimit = document.getElementById('torbox-download-limit');
  elements.torboxCloudSeedToggle = document.getElementById('torbox-cloud-seed-toggle');
  elements.btnSaveTorbox = document.getElementById('btn-save-torbox');
  elements.btnDisconnectTorbox = document.getElementById('btn-disconnect-torbox');

  // Banner rápido de conversión DDL
  elements.torboxQuickBanner = document.getElementById('torbox-quick-banner');
  elements.torboxQuickBannerText = document.getElementById('torbox-quick-banner-text');
  elements.btnConvertTorboxQuick = document.getElementById('btn-convert-torbox-quick');
  elements.btnDismissTorboxQuick = document.getElementById('btn-dismiss-torbox-quick');

  // Elementos del modal de identidad
  elements.inputNickname = document.getElementById('modal-nickname');
  elements.badgeFingerprint = document.getElementById('modal-fingerprint');
  elements.wordsContainer = document.getElementById('modal-seed-words');
  elements.btnSaveNickname = document.getElementById('btn-save-nickname');
  elements.btnCopySeed = document.getElementById('btn-copy-seed');
  elements.btnExportJson = document.getElementById('btn-export-json');
  elements.inputImportMnemonic = document.getElementById('import-mnemonic-input');
  elements.btnImportMnemonic = document.getElementById('btn-import-mnemonic');

  // Moderación en el modal de identidad
  elements.btnToggleAdminMode = document.getElementById('btn-toggle-admin-mode');
  elements.adminStatusBadge = document.getElementById('admin-status-badge');

  // Modal de compartir e invitaciones
  elements.shareLinkInput = document.getElementById('share-link-input');
  elements.btnCopyShareLink = document.getElementById('btn-copy-share-link');
  elements.btnGenerateInviteToken = document.getElementById('btn-generate-invite-token');
  elements.inviteTokenContainer = document.getElementById('invite-token-container');
  elements.inviteTokenOutput = document.getElementById('invite-token-output');
  elements.btnCopyInviteToken = document.getElementById('btn-copy-invite-token');

  // Árbol de invitaciones y cupos trazables
  elements.inviteTreeSummary = document.getElementById('invite-tree-summary');
  elements.targetGuestInput = document.getElementById('target-guest-input');
  elements.btnCreateQuotaInvite = document.getElementById('btn-create-quota-invite');
  elements.issuedInvitesContainer = document.getElementById('issued-invites-container');
  elements.issuedInvitesList = document.getElementById('issued-invites-list');
  elements.claimInviteInput = document.getElementById('claim-invite-input');
  elements.btnClaimInviteCode = document.getElementById('btn-claim-invite-code');

  // Modal de cambio de sala
  elements.newRoomInput = document.getElementById('new-room-input');
  elements.btnConfirmSwitchRoom = document.getElementById('btn-confirm-switch-room');
  elements.recentRoomsList = document.getElementById('recent-rooms-list');
  elements.officialRoomsList = document.getElementById('official-rooms-list');

  // Retención efímera de mensajes
  elements.roomRetentionSelect = document.getElementById('room-retention-select');

  // Muro de Acceso a la Comunidad (Gate)
  elements.communityGateOverlay = document.getElementById('community-gate-overlay');
  elements.gateInviteInput = document.getElementById('gate-invite-input');
  elements.btnGateClaim = document.getElementById('btn-gate-claim');
  elements.gateStatusMsg = document.getElementById('gate-status-msg');
  elements.btnGateRestore = document.getElementById('btn-gate-restore');

  // Lightbox de imágenes y renders
  elements.imageLightboxModal = document.getElementById('image-lightbox-modal');
  elements.lightboxImg = document.getElementById('lightbox-img');
  elements.lightboxCaption = document.getElementById('lightbox-caption');
  elements.lightboxDownload = document.getElementById('lightbox-download');
  elements.btnCloseLightbox = document.getElementById('btn-close-lightbox');
  elements.lightboxBackdrop = document.getElementById('lightbox-backdrop');
}

// Inicialización temprana de elementos en caso de que el DOM ya exista
if (typeof document !== 'undefined') {
  initElements();
}

/**
 * Inicialización de la aplicación al cargar el DOM.
 */
export async function initChatApp() {
  initElements();
  initThemeSupport();
  bindEvents();

  try {
    await setupUserIdentity();
  } catch (err) {
    console.error('[Chat] Error inicializando identidad:', err);
  }

  try {
    await checkInviteUrlParam();
  } catch (err) {
    console.error('[Chat] Error verificando invitación:', err);
  }

  // Comprobar muro de acceso a la comunidad (Gate)
  if (!isCommunityAccessGranted()) {
    showCommunityGate();
    return;
  }

  try {
    setupRoomFromUrl();
  } catch (err) {
    console.error('[Chat] Error conectando a la sala:', err);
  }
}

/**
 * Comprueba si el usuario tiene acceso concedido a la comunidad.
 * @returns {boolean}
 */
export function isCommunityAccessGranted() {
  if (state.identity && state.identity.fingerprint.toLowerCase() === GENESIS_ADMIN_ROOT_FINGERPRINT.toLowerCase()) {
    localStorage.setItem('p2p_community_access_granted', 'true');
    return true;
  }
  return localStorage.getItem('p2p_community_access_granted') === 'true';
}

/**
 * Muestra el muro de acceso (Gate) bloqueando el chat.
 */
export function showCommunityGate() {
  if (elements.communityGateOverlay) {
    elements.communityGateOverlay.style.display = 'flex';
  }
  if (elements.gateInviteInput) {
    elements.gateInviteInput.focus();
  }
}

/**
 * Oculta el muro de acceso (Gate).
 */
export function hideCommunityGate() {
  if (elements.communityGateOverlay) {
    elements.communityGateOverlay.style.display = 'none';
  }
}

/**
 * Muestra un aviso de estado en el muro de acceso.
 * @param {string} message
 * @param {boolean} isSuccess
 */
function showGateStatus(message, isSuccess = false) {
  if (!elements.gateStatusMsg) return;
  elements.gateStatusMsg.textContent = message;
  elements.gateStatusMsg.className = `gate-status-msg ${isSuccess ? 'success' : 'error'}`;
  elements.gateStatusMsg.style.display = 'block';
}

/**
 * Procesa el canje del código o token en el muro de acceso.
 */
async function handleClaimGateCode() {
  const inputVal = (elements.gateInviteInput?.value || '').trim();
  if (!inputVal) {
    showGateStatus('Por favor, introduce un código o token de invitación.');
    return;
  }

  if (elements.btnGateClaim) {
    elements.btnGateClaim.disabled = true;
    elements.btnGateClaim.textContent = 'Verificando...';
  }

  try {
    // 1. Código alfanumérico firmado en servidor (INV-XXXX o GEN-XXXX)
    if (inputVal.toUpperCase().startsWith('INV-') || inputVal.toUpperCase().startsWith('GEN-')) {
      const code = inputVal.toUpperCase();
      const timestamp = Date.now();
      const signature = await signPayload(
        state.identity.privateKey,
        { action: 'claim', code, userFingerprint: state.identity.fingerprint, timestamp }
      );

      const res = await fetch('/api/chat/invites', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'claim',
          code,
          userFingerprint: state.identity.fingerprint,
          userPublicSpki: state.identity.publicSpki,
          nickname: state.identity.nickname,
          timestamp,
          signature
        })
      });

      const data = await res.json();
      if (!data.success) {
        showGateStatus(data.error || 'Código de invitación no válido o ya agotado.');
        return;
      }

      localStorage.setItem('p2p_community_access_granted', 'true');
      showGateStatus('Acceso concedido con éxito. Entrando al chat...', true);
      setTimeout(() => {
        hideCommunityGate();
        setupRoomFromUrl();
        appendSystemMessage('Bienvenido a la comunidad CFGS 3D. Tu código de invitación ha sido verificado.');
      }, 600);
      return;
    }

    // 2. Token de invitación autosoberano (JWT / Base64)
    const tokenResult = await verifyInviteToken(inputVal);
    if (tokenResult.valid) {
      localStorage.setItem('p2p_community_access_granted', 'true');
      showGateStatus('Token verificado con éxito. Entrando al chat...', true);
      setTimeout(() => {
        hideCommunityGate();
        setupRoomFromUrl();
        appendSystemMessage('Bienvenido. Tu token de invitación oficial ha sido verificado.');
      }, 600);
      return;
    }

    showGateStatus(`Token no válido: ${tokenResult.reason || 'formato incorrecto'}`);

  } catch (err) {
    console.error('[Gate] Error verificando invitación:', err);
    showGateStatus(`Error de verificación: ${err.message}`);
  } finally {
    if (elements.btnGateClaim) {
      elements.btnGateClaim.disabled = false;
      elements.btnGateClaim.innerHTML = `
        <span>Desbloquear Acceso</span>
        <svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true">
          <path fill="currentColor" d="M5 13h11.86l-5.43 5.43 1.42 1.42L21.14 12l-8.29-7.85-1.42 1.42L16.86 11H5v2z"/>
        </svg>
      `;
    }
  }
}

/**
 * Detecta si el usuario entra a través de un enlace de invitación exclusiva (?invite=... o #invite=...)
 */
async function checkInviteUrlParam() {
  const hash = window.location.hash;
  const urlParams = new URLSearchParams(window.location.search);
  let inviteToken = urlParams.get('invite');

  if (!inviteToken && hash.includes('invite=')) {
    const match = hash.match(/invite=([^&]+)/);
    if (match) inviteToken = match[1];
  }

  if (inviteToken) {
    const result = await verifyInviteToken(inviteToken);
    if (result.valid) {
      localStorage.setItem('p2p_community_access_granted', 'true');
      appendSystemMessage('Bienvenido. Tu token de invitación oficial ha sido verificado.');
    } else {
      console.warn('[Invite] Token inválido:', result.reason);
      appendSystemMessage(`Aviso: El enlace de invitación presentado no es válido: ${result.reason}`);
    }
  }
}

/**
 * Inicializa o recupera la identidad criptográfica del usuario.
 */
async function setupUserIdentity() {
  let stored = loadStoredIdentity();

  if (stored && stored.privateJwk && stored.publicSpki) {
    try {
      const keys = await importKeyPair(stored.privateJwk, stored.publicSpki);
      state.identity = {
        ...stored,
        privateKey: keys.privateKey,
        publicKey: keys.publicKey
      };
    } catch (e) {
      console.warn('[Chat] Error al reimportar claves locales, generando nuevas:', e);
      stored = null;
    }
  }

  // Si no había identidad previa válida, generamos una nueva
  if (!state.identity) {
    const keyPair = await generateIdentityKeyPair();
    const exported = await exportKeyPair(keyPair);
    const fingerprint = await getFingerprint(exported.publicSpki);
    const nickname = generateDefaultNickname(fingerprint);

    // Generamos 12 bytes aleatorios para la frase mnemónica
    const randomBytes = new Uint8Array(12);
    crypto.getRandomValues(randomBytes);
    const mnemonic = bytesToMnemonic(randomBytes);

    state.identity = {
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey,
      privateJwk: exported.privateJwk,
      publicSpki: exported.publicSpki,
      fingerprint,
      nickname,
      mnemonic
    };

    saveStoredIdentity({
      privateJwk: exported.privateJwk,
      publicSpki: exported.publicSpki,
      fingerprint,
      nickname,
      mnemonic
    });
  }

  // Si la identidad corresponde al Administrador Raíz Génesis (FilthySilver), fijar rol y apodo
  if (state.identity && state.identity.fingerprint.toLowerCase() === GENESIS_ADMIN_ROOT_FINGERPRINT.toLowerCase()) {
    state.isAdmin = true;
    localStorage.setItem('p2p_chat_is_admin', 'true');
    localStorage.setItem('p2p_community_access_granted', 'true');
    if (state.identity.nickname !== 'FilthySilver') {
      state.identity.nickname = 'FilthySilver';
      updateStoredNickname('FilthySilver');
    }
  }

  // Sincronizar respaldo de la bóveda cifrada en Cloudflare (Zero-Knowledge)
  backupUserVaultToCloudflare(state.identity);

  updateIdentityUi();
}

/**
 * Sincroniza un respaldo de la Bóveda Criptográfica en Cloudflare KV (Zero-Knowledge).
 * La clave privada se cifra con AES-GCM 256 derivado de las 12 palabras antes de enviarse.
 */
async function backupUserVaultToCloudflare(identity) {
  if (!identity || !identity.mnemonic || !identity.privateJwk || !identity.privateKey) return;
  try {
    const vault = await encryptPrivateKeyWithMnemonic(identity.privateJwk, identity.mnemonic);
    const encoder = new TextEncoder();
    const seedHash = await computeFileHash(encoder.encode(identity.mnemonic.trim().toLowerCase()).buffer);
    const timestamp = Date.now();
    const signature = await signPayload(
      identity.privateKey,
      {
        action: 'backup_vault',
        fingerprint: identity.fingerprint,
        seedHash,
        ciphertext: vault.ciphertext,
        iv: vault.iv,
        timestamp
      }
    );

    await fetch('/api/chat/vault', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        fingerprint: identity.fingerprint,
        publicSpki: identity.publicSpki,
        seedHash,
        vault,
        nickname: identity.nickname,
        timestamp,
        signature
      })
    });
  } catch (err) {
    console.warn('[Vault] No se pudo sincronizar respaldo en Cloudflare:', err);
  }
}

/**
 * Actualiza la información de identidad en los componentes del modal y cabecera.
 */
function updateIdentityUi() {
  if (!state.identity) return;

  const isGenesisRoot = state.identity.fingerprint.toLowerCase() === GENESIS_ADMIN_ROOT_FINGERPRINT.toLowerCase();

  if (elements.inputNickname) {
    elements.inputNickname.value = state.identity.nickname;
  }
  if (elements.badgeFingerprint) {
    elements.badgeFingerprint.textContent = `0x${state.identity.fingerprint}`;
  }

  // Renderizar las 12 palabras
  if (elements.wordsContainer && state.identity.mnemonic) {
    elements.wordsContainer.innerHTML = '';
    const words = state.identity.mnemonic.split(' ');
    words.forEach((word, index) => {
      const span = document.createElement('span');
      span.className = 'seed-word';
      span.innerHTML = `<small>${index + 1}.</small> <strong>${escapeHtml(word)}</strong>`;
      elements.wordsContainer.appendChild(span);
    });
  }

  // Indicador de modo moderador / Administrador Raíz Génesis
  if (elements.adminStatusBadge) {
    if (isGenesisRoot) {
      elements.adminStatusBadge.innerHTML = 'Administrador Raíz Génesis (FilthySilver)';
      elements.adminStatusBadge.style.color = 'var(--accent)';
      if (elements.btnToggleAdminMode) {
        elements.btnToggleAdminMode.style.display = 'none';
      }
    } else {
      elements.adminStatusBadge.textContent = state.isAdmin ? 'Moderador Activo' : 'Miembro Regular';
      elements.adminStatusBadge.style.color = state.isAdmin ? 'var(--warning)' : 'var(--muted)';
      if (elements.btnToggleAdminMode) {
        elements.btnToggleAdminMode.style.display = '';
        elements.btnToggleAdminMode.textContent = state.isAdmin ? 'Desactivar Modo Admin' : 'Activar Modo Admin';
      }
    }
  }
}

/**
 * Obtiene el ID de la sala desde la ruta limpia (/chat/:room) o el hash (#:room).
 * @returns {string}
 */
export function getRoomIdFromLocation() {
  const pathParts = window.location.pathname.split('/').filter(Boolean);
  if (pathParts.length >= 2 && pathParts[0] === 'chat') {
    return pathParts[1].toLowerCase().replace(/[^a-z0-9_-]/g, '-');
  }

  const hash = window.location.hash.replace(/^#/, '').split('?')[0].split('&')[0].trim().toLowerCase();
  if (hash && !hash.startsWith('invite=')) {
    return hash.replace(/[^a-z0-9_-]/g, '-');
  }

  return 'general';
}

/**
 * Abre el visualizador Lightbox para inspeccionar capturas o renders 3D.
 * @param {string} imgUrl
 * @param {string} caption
 */
export function openLightbox(imgUrl, caption = 'Captura de pantalla') {
  if (!elements.imageLightboxModal || !elements.lightboxImg) return;
  elements.lightboxImg.src = imgUrl;
  if (elements.lightboxCaption) {
    elements.lightboxCaption.textContent = caption;
  }
  if (elements.lightboxDownload) {
    elements.lightboxDownload.href = imgUrl;
    elements.lightboxDownload.download = caption || 'captura-3d.png';
  }
  elements.imageLightboxModal.style.display = 'flex';
}

/**
 * Cierra el visualizador Lightbox.
 */
export function closeLightbox() {
  if (!elements.imageLightboxModal) return;
  elements.imageLightboxModal.style.display = 'none';
  if (elements.lightboxImg) {
    elements.lightboxImg.src = '';
  }
}

/**
 * Guarda un mensaje en el búfer efímero de Cloudflare KV con TTL de autodestrucción.
 * @param {string} roomId
 * @param {Object} msg
 * @param {number} retentionHours
 */
async function saveEphemeralMessageToServer(roomId, msg, retentionHours) {
  if (!roomId || !msg || retentionHours <= 0) return;
  try {
    const token = localStorage.getItem('p2p_community_access_token') || '';
    await fetch('/api/chat/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        roomId,
        retentionHours,
        token,
        message: {
          id: msg.id,
          senderPeerId: msg.senderPeerId || state.identity?.fingerprint,
          fromNickname: msg.fromNickname || state.identity?.nickname,
          text: msg.text,
          timestamp: msg.timestamp || Date.now(),
          publicSpki: msg.publicSpki || state.identity?.publicSpki,
          signature: msg.signature,
          isVerified: msg.isVerified,
          torbox: msg.torbox || null
        }
      })
    });
  } catch (err) {
    console.warn('[Messages] Error al persistir mensaje efímero:', err);
  }
}

/**
 * Consulta y carga los mensajes recientes almacenados en el búfer efímero de Cloudflare KV.
 * @param {string} roomId
 */
async function loadServerRoomMessages(roomId) {
  if (!roomId) return;
  try {
    const peerId = encodeURIComponent(state.identity?.fingerprint || '');
    const token = encodeURIComponent(localStorage.getItem('p2p_community_access_token') || '');
    const res = await fetch(`/api/chat/messages?roomId=${encodeURIComponent(roomId)}&peerId=${peerId}&token=${token}`);
    const data = await res.json();
    if (data.success && Array.isArray(data.messages) && data.messages.length > 0) {
      const existingIds = new Set(
        Array.from(elements.messagesFeed?.querySelectorAll('[data-msg-id]') || [])
          .map(el => el.dataset.msgId)
      );

      let loadedCount = 0;
      for (const msg of data.messages) {
        if (!existingIds.has(String(msg.id))) {
          const isMe = (msg.senderPeerId === state.identity?.fingerprint);
          if (msg.torbox) {
            appendTorboxCard(msg, isMe);
          } else {
            appendChatMessage(msg, isMe);
          }
          appendRoomHistory(roomId, { ...msg, isMe });
          existingIds.add(String(msg.id));
          loadedCount++;
        }
      }

      if (loadedCount > 0) {
        appendSystemMessage(`Sincronizados ${loadedCount} mensaje(s) del búfer efímero de #${roomId}.`);
      }
    }
  } catch (err) {
    console.warn('[Messages] Error cargando mensajes efímeros del servidor:', err);
  }
}

/**
 * Conecta a la sala indicada en la URL.
 */
function setupRoomFromUrl() {
  const roomId = getRoomIdFromLocation();
  joinRoom(roomId);
}

/**
 * Entra en una sala P2P específica y enlaza eventos de red, archivos y moderación.
 * @param {string} roomId
 */
function joinRoom(roomId) {
  if (state.isKicked) return;

  if (state.roomInstance) {
    state.roomInstance.destroy();
    state.roomInstance = null;
  }

  state.currentRoomId = roomId;
  saveRecentRoom(roomId);
  state.peers.clear();

  if (elements.roomTitle) {
    elements.roomTitle.textContent = `#${roomId}`;
  }

  if (elements.roomRetentionSelect) {
    const savedRetention = localStorage.getItem(`room_retention_${roomId}`) || '24';
    elements.roomRetentionSelect.value = savedRetention;
  }

  updatePeersListUi();
  renderRoomHistory(roomId);
  loadServerRoomMessages(roomId);

  // Instanciar motor de red P2P con soporte para moderación, FileDrop y Muro Zero-Trust
  const communityToken = localStorage.getItem('p2p_community_access_token') || null;
  state.roomInstance = new P2PMeshRoom({
    roomId,
    identity: state.identity,
    moderatorCertificate: state.moderatorCertificate,
    communityToken,
    enforceCommunityGate: true,
    onStatusChange: (status, message) => {
      updateStatusUi(status, message);
    },
    onPeerJoin: (peerProfile) => {
      state.peers.set(peerProfile.id, peerProfile);
      updatePeersListUi();
      appendSystemMessage(`${escapeHtml(peerProfile.nickname)} se ha unido a la sala`);
    },
    onPeerLeave: (peerProfile) => {
      state.peers.delete(peerProfile.id);
      updatePeersListUi();
      appendSystemMessage(`${escapeHtml(peerProfile.nickname)} ha salido de la sala`);
    },
    onProfileUpdate: (peerProfile, oldName) => {
      state.peers.set(peerProfile.id, peerProfile);
      updatePeersListUi();
      appendSystemMessage(`${escapeHtml(oldName)} ahora se llama ${escapeHtml(peerProfile.nickname)}`);
    },
    onMessage: (message) => {
      if (message.torbox) {
        appendTorboxCard(message, false);
      } else {
        appendChatMessage(message, false);
      }
      appendRoomHistory(state.currentRoomId, { ...message, isMe: false });
    },
    onMessageDeleted: (messageId) => {
      handleUiMessageDeleted(messageId);
    },
    onKicked: (reason) => {
      state.isKicked = true;
      showKickedUi(reason);
    },
    onFileReceived: (fileData) => {
      appendFileBubble(fileData, false);
      appendRoomHistory(state.currentRoomId, { ...fileData, isFile: true, isMe: false });
    },
    onFileProgress: (fileId, progressRatio) => {
      console.log(`[P2P File] Progreso ${fileId}: Math.round(progressRatio * 100)%`);
    }
  });
}

/**
 * Actualiza el indicador visual del estado de red.
 */
function updateStatusUi(status, message) {
  if (elements.connectionStatus) {
    elements.connectionStatus.textContent = message;
  }
  if (elements.statusIndicator) {
    elements.statusIndicator.className = `status-dot status-${status}`;
  }
}

/**
 * Actualiza la lista de compañeros conectados en la interfaz.
 */
function updatePeersListUi() {
  if (elements.peersCountBadge) {
    const totalCount = state.peers.size + 1; // +1 por el usuario actual
    elements.peersCountBadge.textContent = `${totalCount} en línea`;
  }

  if (!elements.peersList) return;
  elements.peersList.innerHTML = '';

  // Elemento del usuario propio
  const meTag = document.createElement('div');
  meTag.className = 'peer-pill peer-me';
  const myNick = state.identity?.nickname || 'Tú';
  meTag.innerHTML = `
    <span class="peer-dot online"></span>
    <span class="peer-name">${escapeHtml(myNick)}</span>
    <span class="peer-tag">(Tú)</span>
  `;
  elements.peersList.appendChild(meTag);

  // Elementos de los compañeros
  for (const [peerId, peer] of state.peers.entries()) {
    const pill = document.createElement('div');
    pill.className = 'peer-pill';
    pill.innerHTML = `
      <span class="peer-dot online"></span>
      <span class="peer-name" title="ID: 0x${escapeHtml(peerId)}">${escapeHtml(peer.nickname)}</span>
      ${peer.isModerator ? `<span class="peer-badge-mod" title="Moderador Verificado Criptográficamente (${escapeHtml(peer.moderatorRole)})">[MOD]</span>` : ''}
      ${state.isAdmin ? `<button type="button" class="btn-kick-peer" data-peer-id="${escapeHtml(peerId)}" title="Expulsar a este usuario">Expulsar</button>` : ''}
    `;

    if (state.isAdmin) {
      const kickBtn = pill.querySelector('.btn-kick-peer');
      kickBtn?.addEventListener('click', () => {
        executeAdminKick(peerId, peer.nickname);
      });
    }

    elements.peersList.appendChild(pill);
  }
}

/**
 * Añade un mensaje del chat a la vista con soporte de moderación.
 */
function appendChatMessage(msg, isMe = false) {
  if (!elements.messagesFeed) return;

  const msgDiv = document.createElement('div');
  msgDiv.className = `chat-bubble-container ${isMe ? 'msg-outbound' : 'msg-inbound'}`;
  msgDiv.dataset.msgId = msg.id;

  const timeString = new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

  msgDiv.innerHTML = `
    <div class="chat-bubble">
      <div class="msg-header">
        <span class="msg-author">${escapeHtml(msg.fromNickname)}</span>
        <span class="msg-meta">
          ${msg.isVerified ? '<span class="verified-badge" title="Firma criptográfica verificada (ECDSA)">[Verificado]</span>' : ''}
          <time>${timeString}</time>
          ${state.isAdmin ? `<button type="button" class="btn-mod-delete" data-msg-id="${escapeHtml(msg.id)}" title="Eliminar mensaje como moderador"><svg viewBox="0 0 24 24" width="14" height="14" aria-hidden="true"><path fill="currentColor" d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg></button>` : ''}
        </span>
      </div>
      <div class="msg-body">${escapeHtml(msg.text)}</div>
    </div>
  `;

  if (state.isAdmin) {
    const delBtn = msgDiv.querySelector('.btn-mod-delete');
    delBtn?.addEventListener('click', () => {
      executeAdminDeleteMessage(msg.id);
    });
  }

  elements.messagesFeed.appendChild(msgDiv);
  elements.messagesFeed.scrollTop = elements.messagesFeed.scrollHeight;
}

/**
 * Renderiza una burbuja de archivo transferido con Certificado de Autoría.
 */
function appendFileBubble(fileData, isMe = false) {
  if (!elements.messagesFeed) return;

  const msgDiv = document.createElement('div');
  msgDiv.className = `chat-bubble-container ${isMe ? 'msg-outbound' : 'msg-inbound'}`;

  const timeString = new Date(fileData.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const formattedSize = formatBytes(fileData.fileSize);
  const shortHash = fileData.fileHash ? `${fileData.fileHash.slice(0, 10)}...${fileData.fileHash.slice(-6)}` : 'hash-ok';

  msgDiv.innerHTML = `
    <div class="chat-bubble">
      <div class="msg-header">
        <span class="msg-author">${escapeHtml(fileData.fromNickname)}</span>
        <span class="msg-meta">
          <time>${timeString}</time>
        </span>
      </div>
      <div class="file-attachment-card">
        <div class="file-header-row">
          <span class="file-name-meta">${escapeHtml(fileData.fileName)}</span>
          <span class="file-size-tag">${formattedSize}</span>
        </div>

        <div class="file-authorship-badge">
          ${(isMe || (fileData.authorship?.valid && fileData.isValidHash !== false))
            ? `Autoría Criptográfica Verificada: ${escapeHtml(fileData.authorship?.authorNickname || fileData.fromNickname)}`
            : 'Aviso: Autoría o integridad no verificada: no abras este archivo si no confías en el remitente'}
        </div>

        <div class="file-hash-tag">
          SHA-256: ${shortHash}
        </div>

        ${(fileData.blobUrl && (/\.(png|jpe?g|webp|gif|svg|bmp)$/i.test(fileData.fileName) || (fileData.fileType && fileData.fileType.startsWith('image/')))) ? `
          <div class="chat-image-preview-wrap" data-img-url="${escapeHtml(fileData.blobUrl)}" data-img-caption="${escapeHtml(fileData.fileName)}" title="Haz clic para ampliar la captura o render">
            <img src="${escapeHtml(fileData.blobUrl)}" alt="${escapeHtml(fileData.fileName)}" class="chat-image-preview" loading="lazy" />
            <div class="chat-image-overlay-zoom">
              <svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true"><path fill="currentColor" d="M15.5 14h-.79l-.28-.27C15.41 12.59 16 11.11 16 9.5 16 5.91 13.09 3 9.5 3S3 5.91 3 9.5 5.91 16 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14zm.5-7H9v2H7v1h2v2h1v-2h2V9h-2z"/></svg>
            </div>
          </div>
        ` : ''}

        ${fileData.blobUrl ? `
          <a href="${escapeHtml(fileData.blobUrl)}" download="${escapeHtml(fileData.fileName)}" class="btn-download-file">
            Descargar archivo directo
          </a>
        ` : `
          <div style="font-size: 0.75rem; color: var(--muted);">Transferido a compañeros</div>
        `}
      </div>
    </div>
  `;

  elements.messagesFeed.appendChild(msgDiv);
  elements.messagesFeed.scrollTop = elements.messagesFeed.scrollHeight;
}

/**
 * Renderiza una tarjeta interactiva de Descarga Directa Torbox con estado de Cloud Seeding.
 * Zero-Knowledge: Solo muestra el nombre, tamaño, sembrado 24/7 y la URL CDN pública
 * (la API Key del emisor nunca viaja en el paquete).
 */
function appendTorboxCard(msg, isMe = false) {
  if (!elements.messagesFeed) return;

  const msgDiv = document.createElement('div');
  msgDiv.className = `chat-bubble-container ${isMe ? 'msg-outbound' : 'msg-inbound'}`;
  msgDiv.dataset.msgId = msg.id;

  const timeString = new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const tb = msg.torbox || {};
  const formattedSize = formatTorboxBytes(tb.fileSize);
  const safeDdlUrl = sanitizeUrl(tb.ddlUrl);
  const safeMagnet = (typeof tb.magnetUrl === 'string' && tb.magnetUrl.startsWith('magnet:?')) ? tb.magnetUrl : '';

  msgDiv.innerHTML = `
    <div class="chat-bubble">
      <div class="msg-header">
        <span class="msg-author">${escapeHtml(msg.fromNickname)}</span>
        <span class="msg-meta">
          ${msg.isVerified ? '<span class="verified-badge" title="Firma criptográfica verificada (ECDSA)">[Verificado]</span>' : ''}
          <time>${timeString}</time>
          ${state.isAdmin ? `<button type="button" class="btn-mod-delete" data-msg-id="${escapeHtml(msg.id)}" title="Eliminar mensaje como moderador"><svg viewBox="0 0 24 24" width="14" height="14" aria-hidden="true"><path fill="currentColor" d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg></button>` : ''}
        </span>
      </div>
      <div class="torbox-card">
        <div class="torbox-card-header">
          <span class="torbox-brand-pill">Torbox Direct Download</span>
          <span class="torbox-seed-status">
            ${tb.isCloudSeeding !== false ? 'Sembrando en la nube 24/7 (Peers activos)' : 'Sembrado en proceso'}
          </span>
        </div>

        <div class="torbox-file-name">${escapeHtml(tb.fileName || 'Proyecto 3D')}</div>

        <div class="torbox-meta-row">
          <span class="torbox-meta-item">Tamaño: <strong>${formattedSize}</strong></span>
          <span class="torbox-meta-item">Velocidad: <strong>CDN Ultra-Rápida</strong></span>
        </div>

        ${safeDdlUrl ? `
          <a href="${safeDdlUrl}" target="_blank" rel="noopener noreferrer" class="btn-torbox-download">
            <span>Descargar a máxima velocidad (DDL)</span>
          </a>
        ` : `
          <div style="font-size: 0.8rem; color: var(--muted); padding: 0.4rem; background: var(--surface); border-radius: 6px;">
            Procesando en Torbox CDN... Si tarda unos minutos, puedes usar el enlace magnet alternativo abajo.
          </div>
        `}

        ${safeMagnet ? `
          <details class="torbox-magnet-details">
            <summary>Ver enlace magnet original (P2P alternativo)</summary>
            <div class="torbox-magnet-raw">${escapeHtml(safeMagnet)}</div>
          </details>
        ` : ''}
      </div>
    </div>
  `;

  if (state.isAdmin) {
    const delBtn = msgDiv.querySelector('.btn-mod-delete');
    delBtn?.addEventListener('click', () => {
      executeAdminDeleteMessage(msg.id);
    });
  }

  elements.messagesFeed.appendChild(msgDiv);
  elements.messagesFeed.scrollTop = elements.messagesFeed.scrollHeight;
}

/**
 * Muestra el banner flotante de sugerencia para conversión a DDL.
 */
function showQuickBanner(text) {
  if (elements.torboxQuickBanner) {
    if (elements.torboxQuickBannerText) {
      elements.torboxQuickBannerText.textContent = text;
    }
    if (elements.btnConvertTorboxQuick) {
      elements.btnConvertTorboxQuick.textContent = hasTorboxKey() ? 'Convertir a DDL con Torbox' : 'Configurar Torbox';
    }
    elements.torboxQuickBanner.style.display = 'flex';
  }
}

/**
 * Oculta el banner flotante de sugerencia rápida.
 */
function hideQuickBanner() {
  if (elements.torboxQuickBanner) {
    elements.torboxQuickBanner.style.display = 'none';
  }
}

/**
 * Abre el modal de configuración de Torbox y refresca el estado de la cuenta.
 */
async function openTorboxModal() {
  const currentKey = getTorboxKey();
  if (elements.torboxApiKeyInput) {
    elements.torboxApiKeyInput.value = currentKey;
    elements.torboxApiKeyInput.type = 'password';
  }
  if (elements.torboxCloudSeedToggle) {
    elements.torboxCloudSeedToggle.checked = isCloudSeedingEnabled();
  }
  if (currentKey) {
    await updateTorboxAccountStatus(currentKey);
  } else if (elements.torboxStatusCard) {
    elements.torboxStatusCard.style.display = 'none';
  }
  openModal(elements.modalTorboxSettings);
}

/**
 * Consulta y actualiza los indicadores de plan, slots y cuota de Torbox.
 */
async function updateTorboxAccountStatus(key) {
  if (!elements.torboxStatusCard) return;
  try {
    const data = await verifyTorboxAccount(key);
    elements.torboxStatusCard.style.display = 'block';

    const planRaw = data.plan !== undefined ? data.plan : (data.user && data.user.plan);
    let planBadgeText = 'Free';
    let isPro = false;
    if (planRaw === 2 || planRaw === 3 || planRaw === 'pro' || planRaw === 'standard') {
      planBadgeText = 'Pro';
      isPro = true;
    } else if (planRaw === 1 || planRaw === 'essential') {
      planBadgeText = 'Essential';
      isPro = true;
    } else if (planRaw === 0 || planRaw === 'free') {
      planBadgeText = 'Free';
      isPro = false;
    } else if (planRaw) {
      planBadgeText = `Plan ${planRaw}`;
      isPro = true;
    }

    if (elements.torboxPlanBadge) {
      elements.torboxPlanBadge.textContent = planBadgeText;
      elements.torboxPlanBadge.className = `badge-plan ${isPro ? 'pro' : 'free'}`;
    }

    if (elements.torboxPlanBadge) {
      elements.torboxPlanBadge.textContent = planBadgeText;
      elements.torboxPlanBadge.className = `badge-plan ${isPro ? 'pro' : 'free'}`;
    }

    if (elements.torboxUserEmail) {
      elements.torboxUserEmail.textContent = data.email || (data.user && data.user.email) || 'Usuario Conectado';
    }

    if (elements.torboxActiveSlots) {
      const active = data.active_torrents ?? data.active_downloads ?? data.slots ?? 0;
      const maxSlots = data.max_torrents ?? (isPro ? 'Ilimitados' : '1 activo');
      elements.torboxActiveSlots.textContent = `${active} / ${maxSlots}`;
    }

    if (elements.torboxDownloadLimit) {
      const downloaded = data.total_downloaded ?? 0;
      elements.torboxDownloadLimit.textContent = formatTorboxBytes(downloaded);
    }
  } catch (err) {
    console.warn('[Torbox Status] Error verificando cuenta:', err);
    if (elements.torboxStatusCard) {
      elements.torboxStatusCard.style.display = 'none';
    }
  }
}

/**
 * Convierte un magnet o archivo .torrent a Descarga Directa (DDL) con Cloud Seeding 24/7 y lo transmite a la sala.
 */
async function convertAndBroadcastTorbox(magnetOrFile) {
  if (!state.roomInstance) {
    alert('Debes estar conectado a la sala para compartir proyectos.');
    return;
  }
  const isFile = magnetOrFile instanceof Blob || (typeof File !== 'undefined' && magnetOrFile instanceof File);
  const targetName = isFile ? magnetOrFile.name : parseMagnetName(magnetOrFile);

  appendSystemMessage(`Conectando con Torbox para procesar "${escapeHtml(targetName)}"...`);

  try {
    const isSeed = isCloudSeedingEnabled();
    const addResult = await addMagnetOrTorrent(magnetOrFile, { seed: isSeed ? 1 : 0 });

    const torrentId = addResult.torrent_id || addResult.id || (addResult.data && (addResult.data.torrent_id || addResult.data.id));
    const fileName = addResult.name || targetName;
    const torrentHash = addResult.hash || '';

    let fileSize = addResult.size || (isFile ? magnetOrFile.size : 0);
    let ddlUrl = '';

    if (torrentId) {
      try {
        ddlUrl = await requestDownloadLink(torrentId);
      } catch (dlErr) {
        try {
          const list = await getTorrentList();
          const item = list.find(t => String(t.id) === String(torrentId) || (torrentHash && t.hash === torrentHash));
          if (item) {
            fileSize = item.size || fileSize;
            if (item.files && item.files.length > 0) {
              ddlUrl = await requestDownloadLink(torrentId, item.files[0].id);
            }
          }
        } catch {}
      }
    }

    // Zero-Knowledge: NUNCA se comparte la API Key en el mensaje
    const torboxPayload = {
      isTorboxCard: true,
      torrentId: torrentId || null,
      fileName,
      fileSize,
      ddlUrl: ddlUrl || '',
      magnetUrl: typeof magnetOrFile === 'string' ? magnetOrFile : (torrentHash ? `magnet:?xt=urn:btih:${torrentHash}&dn=${encodeURIComponent(fileName)}` : ''),
      isCloudSeeding: isSeed,
      createdAt: Date.now()
    };

    const sentMsg = await state.roomInstance.sendMessage(
      `[Torbox DDL] ${fileName}`,
      torboxPayload
    );

    appendTorboxCard(sentMsg, true);
    appendRoomHistory(state.currentRoomId, { ...sentMsg, isMe: true });
    appendSystemMessage(`Proyecto "${escapeHtml(fileName)}" listo con Descarga Directa Torbox y Cloud Seeding 24/7.`);

  } catch (err) {
    console.error('[Torbox] Error al convertir archivo:', err);
    appendSystemMessage(`Error en Torbox: ${escapeHtml(err.message)}`);
    alert(`Error de Torbox: ${err.message}\nVerifica tus slots disponibles o la validez de tu API Key.`);
  }
}

/**
 * Procesa el envío de un archivo arrastrado o seleccionado.
 */
async function handleSendFile(file) {
  if (!file || !state.roomInstance) return;
  appendSystemMessage(`Calculando SHA-256 y firmando certificado de autoría para "${escapeHtml(file.name)}"...`);

  try {
    const sentMeta = await state.roomInstance.sendFile(file);
    appendFileBubble(sentMeta, true);
    appendRoomHistory(state.currentRoomId, { ...sentMeta, isFile: true, isMe: true });
    appendSystemMessage(`"${escapeHtml(file.name)}" transmitido por P2P con certificado de autoría.`);
  } catch (err) {
    alert(`Error enviando archivo: ${err.message}`);
  }
}

/**
 * Consulta y renderiza el árbol genealógico de invitaciones del usuario.
 */
async function loadUserInviteTree() {
  if (!elements.inviteTreeSummary || !state.identity) return;

  try {
    elements.inviteTreeSummary.innerHTML = '<span>Consultando árbol de confianza en Cloudflare...</span>';
    const res = await fetch(`/api/chat/invites?fingerprint=${state.identity.fingerprint}`);
    const data = await res.json();

    if (!data.success) {
      elements.inviteTreeSummary.textContent = 'No se pudo cargar la información de linaje.';
      return;
    }

    elements.inviteTreeSummary.innerHTML = `
      <div style="display: flex; justify-content: space-between; margin-bottom: 0.25rem;">
        <span><strong>Invitado por:</strong> ${escapeHtml(data.invitedByLabel || 'Génesis')}</span>
        <span style="color: var(--accent); font-weight: 700;">Cupo restante: ${data.remainingQuota}</span>
      </div>
      <div style="font-size: 0.78rem; color: var(--muted);">
        Total invitaciones asignadas: ${data.quota} · Usadas: ${data.usedCount}
      </div>
    `;

    if (elements.issuedInvitesContainer && elements.issuedInvitesList) {
      elements.issuedInvitesList.innerHTML = '';
      if (data.invites && data.invites.length > 0) {
        elements.issuedInvitesContainer.style.display = 'block';
        data.invites.forEach(inv => {
          const item = document.createElement('div');
          item.className = 'invite-tree-item';
          item.innerHTML = `
            <span class="invite-code-pill">${escapeHtml(inv.code)}</span>
            <span>Para: ${escapeHtml(inv.targetLabel)}</span>
            <span class="invite-status-badge ${inv.used ? 'claimed' : ''}">
              ${inv.used ? `Canjeado (${escapeHtml(inv.usedByLabel)})` : 'Pendiente'}
            </span>
          `;
          elements.issuedInvitesList.appendChild(item);
        });
      } else {
        elements.issuedInvitesContainer.style.display = 'none';
      }
    }

  } catch (err) {
    console.warn('[Invite Tree] Error al consultar:', err);
    elements.inviteTreeSummary.textContent = 'Servidor de invitaciones en modo local.';
  }
}

/**
 * Emite una nueva invitación consumiendo 1 del cupo del usuario (con firma digital ECDSA).
 */
async function createQuotaInvite() {
  const targetLabel = (elements.targetGuestInput?.value || '').trim();
  if (!targetLabel) {
    alert('Introduce el nombre del compañero al que vas a invitar.');
    return;
  }

  try {
    const timestamp = Date.now();
    const signature = await signPayload(
      state.identity.privateKey,
      { action: 'create', creatorFingerprint: state.identity.fingerprint, targetLabel, timestamp }
    );

    const res = await fetch('/api/chat/invites', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        action: 'create',
        creatorFingerprint: state.identity.fingerprint,
        creatorPublicSpki: state.identity.publicSpki,
        creatorLabel: state.identity.nickname,
        targetLabel,
        timestamp,
        signature
      })
    });

    const data = await res.json();
    if (!data.success) {
      alert(`No se pudo emitir la invitación: ${data.error}`);
      return;
    }

    alert(`¡Invitación creada! Código: ${data.code}\nCompártelo con ${targetLabel}.`);
    elements.targetGuestInput.value = '';
    await loadUserInviteTree();
  } catch (err) {
    alert(`Error: ${err.message}`);
  }
}

/**
 * Canjea un código de invitación recibido.
 */
async function claimInviteCode() {
  const code = (elements.claimInviteInput?.value || '').trim();
  if (!code) {
    alert('Introduce el código de invitación recibido (ej: INV-8F3B2A).');
    return;
  }

  try {
    const timestamp = Date.now();
    const signature = await signPayload(
      state.identity.privateKey,
      { action: 'claim', code, userFingerprint: state.identity.fingerprint, timestamp }
    );

    const res = await fetch('/api/chat/invites', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        action: 'claim',
        code,
        userFingerprint: state.identity.fingerprint,
        userPublicSpki: state.identity.publicSpki,
        nickname: state.identity.nickname,
        timestamp,
        signature
      })
    });

    const data = await res.json();
    if (!data.success) {
      alert(`Error canjeando código: ${data.error}`);
      return;
    }

    alert(`¡Código canjeado con éxito!\nHas sido registrado en la cadena de confianza.`);
    elements.claimInviteInput.value = '';
    await loadUserInviteTree();
  } catch (err) {
    alert(`Error: ${err.message}`);
  }
}

/**
 * Maneja visualmente la eliminación de un mensaje por moderador.
 */
function handleUiMessageDeleted(messageId) {
  const msgEl = Array.from(elements.messagesFeed?.querySelectorAll('[data-msg-id]') || [])
    .find(el => el.dataset.msgId === String(messageId));
  if (msgEl) {
    const cardEl = msgEl.querySelector('.torbox-card');
    if (cardEl) cardEl.remove();
    const bodyEl = msgEl.querySelector('.msg-body');
    if (bodyEl) {
      bodyEl.innerHTML = '<em style="color: var(--muted); font-size: 0.85rem;">Este mensaje ha sido eliminado por un moderador.</em>';
    } else {
      const bubble = msgEl.querySelector('.chat-bubble');
      if (bubble) {
        const notice = document.createElement('div');
        notice.innerHTML = '<em style="color: var(--muted); font-size: 0.85rem;">Este mensaje ha sido eliminado por un moderador.</em>';
        bubble.appendChild(notice);
      }
    }
  }
}

/**
 * Ejecuta la expulsión administrativa de un usuario.
 */
async function executeAdminKick(peerId, nickname) {
  if (!state.isAdmin || !state.roomInstance) return;
  const reason = prompt(`Motivo de expulsión para "${nickname}":`, 'Comportamiento no adecuado');
  if (reason === null) return;

  try {
    await state.roomInstance.broadcastAdminKick(
      peerId,
      reason,
      state.identity.privateKey,
      state.identity.publicSpki
    );
    appendSystemMessage(`Has expulsado a ${escapeHtml(nickname)} de la sala.`);
  } catch (err) {
    alert(`Error al expulsar: ${err.message}`);
  }
}

/**
 * Ejecuta el borrado administrativo de un mensaje.
 */
async function executeAdminDeleteMessage(messageId) {
  if (!state.isAdmin || !state.roomInstance) return;
  if (!confirm('¿Eliminar este mensaje de la vista de todos los participantes?')) return;

  try {
    await state.roomInstance.broadcastAdminDelete(
      messageId,
      state.identity.privateKey,
      state.identity.publicSpki
    );
  } catch (err) {
    alert(`Error al eliminar mensaje: ${err.message}`);
  }
}

/**
 * Muestra el bloqueo cuando un usuario es expulsado.
 */
function showKickedUi(reason) {
  if (elements.messagesFeed) {
    elements.messagesFeed.innerHTML = `
      <div style="text-align: center; margin: 3rem auto; max-width: 450px; padding: 2rem; background: var(--surface); border: 1px solid var(--danger); border-radius: 12px;">
        <h2 style="color: var(--danger); margin-bottom: 0.75rem;">Acceso denegado</h2>
        <p style="font-size: 0.95rem; margin-bottom: 1rem;">Has sido expulsado de esta sala por un moderador.</p>
        <p style="font-size: 0.85rem; color: var(--muted);"><strong>Motivo:</strong> ${escapeHtml(reason)}</p>
      </div>
    `;
  }
  if (elements.messageInput) elements.messageInput.disabled = true;
  if (elements.btnSend) elements.btnSend.disabled = true;
}

/**
 * Inserta un mensaje de evento del sistema en la vista.
 */
function appendSystemMessage(text) {
  if (!elements.messagesFeed) return;

  const sysDiv = document.createElement('div');
  sysDiv.className = 'system-message';
  sysDiv.innerHTML = `<span>${text}</span>`;
  elements.messagesFeed.appendChild(sysDiv);
  elements.messagesFeed.scrollTop = elements.messagesFeed.scrollHeight;
}

/**
 * Renderiza el historial de mensajes previo guardado localmente.
 */
function renderRoomHistory(roomId) {
  if (!elements.messagesFeed) return;
  elements.messagesFeed.innerHTML = '';

  const history = loadRoomHistory(roomId);
  if (history.length > 0) {
    appendSystemMessage('— Historial reciente de la sala —');
    history.forEach(item => {
      if (item.torbox) {
        appendTorboxCard(item, item.isMe);
      } else if (item.isFile) {
        appendFileBubble(item, item.isMe);
      } else {
        appendChatMessage(item, item.isMe);
      }
    });
  }
}

/**
 * Enlaza los eventos de usuario y formularios.
 */
function bindEvents() {
  // Envío de mensaje de texto
  if (elements.chatForm) {
    elements.chatForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (state.isKicked) return;

      const text = (elements.messageInput?.value || '').trim();
      if (!text || !state.roomInstance) return;

      elements.messageInput.value = '';
      elements.messageInput.focus();
      hideQuickBanner();

      try {
        const sentMsg = await state.roomInstance.sendMessage(text);
        appendChatMessage(sentMsg, true);
        appendRoomHistory(state.currentRoomId, { ...sentMsg, isMe: true });

        const retentionHours = elements.roomRetentionSelect ? parseInt(elements.roomRetentionSelect.value, 10) : 24;
        if (retentionHours > 0) {
          saveEphemeralMessageToServer(state.currentRoomId, sentMsg, retentionHours);
        }
      } catch (err) {
        console.error('[Chat] Error al enviar mensaje:', err);
      }
    });
  }

  // Cambio de retención efímera de la sala
  elements.roomRetentionSelect?.addEventListener('change', (e) => {
    localStorage.setItem(`room_retention_${state.currentRoomId}`, e.target.value);
    const hrs = parseInt(e.target.value, 10);
    appendSystemMessage(hrs > 0
      ? `Retención efímera de sala establecida en ${hrs} horas.`
      : 'Modo solo en vivo activo (0 horas de persistencia).');
  });

  // Acciones del Muro de Acceso (Gate)
  elements.btnGateClaim?.addEventListener('click', handleClaimGateCode);
  elements.gateInviteInput?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      handleClaimGateCode();
    }
  });
  elements.btnGateRestore?.addEventListener('click', () => {
    openModal(elements.identityModal || document.getElementById('identity-modal'));
  });

  // Controles del visor Lightbox de imágenes
  elements.btnCloseLightbox?.addEventListener('click', closeLightbox);
  elements.lightboxBackdrop?.addEventListener('click', closeLightbox);

  // Apertura de imágenes al hacer clic en cualquier miniatura de chat
  document.addEventListener('click', (e) => {
    const previewWrap = e.target.closest('.chat-image-preview-wrap');
    if (previewWrap) {
      const url = previewWrap.dataset.imgUrl;
      const caption = previewWrap.dataset.imgCaption;
      if (url) openLightbox(url, caption);
    }
  });

  // Portapapeles: Pegar capturas de pantalla o imágenes (Ctrl + V)
  document.addEventListener('paste', async (e) => {
    const items = e.clipboardData?.items;
    if (!items || !state.roomInstance) return;

    for (let i = 0; i < items.length; i++) {
      const item = items[i];
      if (item.type && item.type.startsWith('image/')) {
        e.preventDefault();
        const blob = item.getAsFile();
        if (blob) {
          const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
          const ext = item.type.split('/')[1] || 'png';
          const file = new File([blob], `captura-${timestamp}.${ext}`, { type: item.type });
          await handleSendFile(file);
          return;
        }
      }
    }
  });

  // Detección inteligente de enlaces magnet en el input
  elements.messageInput?.addEventListener('input', () => {
    const text = (elements.messageInput.value || '').trim();
    if (isMagnetLink(text)) {
      state.pendingMagnet = text;
      state.pendingTorrentFile = null;
      if (hasTorboxKey()) {
        showQuickBanner('Enlace magnet detectado. ¿Convertir a Descarga Directa con Torbox y sembrar 24/7?');
      } else {
        showQuickBanner('Enlace magnet detectado. Configura Torbox para convertir a Descarga Directa de alta velocidad.');
      }
    } else if (!state.pendingTorrentFile) {
      hideQuickBanner();
    }
  });

  // Acciones del banner rápido de Torbox
  elements.btnConvertTorboxQuick?.addEventListener('click', async () => {
    if (!hasTorboxKey()) {
      openTorboxModal();
      return;
    }
    const target = state.pendingTorrentFile || state.pendingMagnet;
    if (target) {
      hideQuickBanner();
      await convertAndBroadcastTorbox(target);
      state.pendingTorrentFile = null;
      state.pendingMagnet = null;
      if (elements.messageInput) elements.messageInput.value = '';
    }
  });

  elements.btnDismissTorboxQuick?.addEventListener('click', () => {
    state.pendingTorrentFile = null;
    state.pendingMagnet = null;
    hideQuickBanner();
  });

  // Adjuntar archivos con botón
  elements.btnAttachFile?.addEventListener('click', () => {
    elements.fileInput?.click();
  });

  elements.fileInput?.addEventListener('change', async (e) => {
    const file = e.target.files?.[0];
    if (file) {
      if (file.name.toLowerCase().endsWith('.torrent') && hasTorboxKey()) {
        state.pendingTorrentFile = file;
        state.pendingMagnet = null;
        showQuickBanner(`¿Convertir "${file.name}" a Descarga Directa con Torbox y sembrar 24/7?`);
      } else {
        await handleSendFile(file);
      }
      elements.fileInput.value = '';
    }
  });

  // Drag and Drop de archivos sobre el feed del chat
  if (elements.messagesFeed) {
    elements.messagesFeed.addEventListener('dragover', (e) => {
      e.preventDefault();
      elements.messagesFeed.style.outline = '2px dashed var(--accent)';
    });

    elements.messagesFeed.addEventListener('dragleave', () => {
      elements.messagesFeed.style.outline = 'none';
    });

    elements.messagesFeed.addEventListener('drop', async (e) => {
      e.preventDefault();
      elements.messagesFeed.style.outline = 'none';
      const file = e.dataTransfer?.files?.[0];
      if (file) {
        if (file.name.toLowerCase().endsWith('.torrent') && hasTorboxKey()) {
          state.pendingTorrentFile = file;
          state.pendingMagnet = null;
          showQuickBanner(`¿Convertir "${file.name}" a Descarga Directa con Torbox y sembrar 24/7?`);
        } else {
          await handleSendFile(file);
        }
      }
    });
  }

  // Modales: Abrir y Cerrar Torbox
  elements.btnOpenTorbox?.addEventListener('click', openTorboxModal);

  elements.btnToggleTorboxKeyVis?.addEventListener('click', () => {
    if (elements.torboxApiKeyInput) {
      elements.torboxApiKeyInput.type = elements.torboxApiKeyInput.type === 'password' ? 'text' : 'password';
    }
  });

  elements.btnVerifyTorbox?.addEventListener('click', async () => {
    const key = (elements.torboxApiKeyInput?.value || '').trim();
    if (!key) {
      alert('Introduce tu API Key de Torbox antes de verificar.');
      return;
    }
    elements.btnVerifyTorbox.disabled = true;
    elements.btnVerifyTorbox.textContent = 'Verificando...';
    try {
      await updateTorboxAccountStatus(key);
      alert('Cuenta de Torbox validada correctamente.');
    } catch (err) {
      alert(`Error de verificación: ${err.message}`);
    } finally {
      elements.btnVerifyTorbox.disabled = false;
      elements.btnVerifyTorbox.textContent = 'Verificar';
    }
  });

  elements.btnSaveTorbox?.addEventListener('click', () => {
    const key = (elements.torboxApiKeyInput?.value || '').trim();
    const seedEnabled = elements.torboxCloudSeedToggle ? elements.torboxCloudSeedToggle.checked : true;
    if (key) {
      setTorboxKey(key);
      setCloudSeedingEnabled(seedEnabled);
      closeModal(elements.modalTorboxSettings);
      appendSystemMessage('Cuenta de Torbox guardada. Descargas Directas CDN y Cloud Seeding 24/7 activos.');
    } else {
      alert('Introduce una clave válida o pulsa "Desconectar" para borrarla.');
    }
  });

  elements.btnDisconnectTorbox?.addEventListener('click', () => {
    if (!confirm('¿Desconectar tu cuenta de Torbox y eliminar tu clave privada de este navegador?')) return;
    removeTorboxKey();
    if (elements.torboxApiKeyInput) elements.torboxApiKeyInput.value = '';
    if (elements.torboxStatusCard) elements.torboxStatusCard.style.display = 'none';
    closeModal(elements.modalTorboxSettings);
    hideQuickBanner();
    appendSystemMessage('Cuenta de Torbox desconectada de este navegador.');
  });

  // Modal de Identidad: Manejador directo e infalible
  const handleOpenIdentity = (e) => {
    if (e && e.preventDefault) e.preventDefault();
    updateIdentityUi();
    openModal(elements.identityModal || document.getElementById('identity-modal'));
  };

  const btnOpenIdentity = elements.btnOpenIdentity || document.getElementById('btn-open-identity');
  if (btnOpenIdentity) {
    btnOpenIdentity.onclick = handleOpenIdentity;
  }

  // Delegación de clics global para garantizar apertura del modal de identidad
  document.addEventListener('click', (e) => {
    if (e.target && (e.target.id === 'btn-open-identity' || e.target.closest('#btn-open-identity'))) {
      handleOpenIdentity(e);
    }
  });

  elements.btnShareRoom?.addEventListener('click', async () => {
    const fullUrl = window.location.href;
    if (elements.shareLinkInput) {
      elements.shareLinkInput.value = fullUrl;
    }
    await loadUserInviteTree();
    openModal(elements.shareModal);
  });

  elements.btnSwitchRoom?.addEventListener('click', () => {
    renderRecentRoomsUi();
    renderOfficialRoomsUi();
    openModal(elements.switchRoomModal);
  });

  // Acciones del árbol de invitaciones
  elements.btnCreateQuotaInvite?.addEventListener('click', createQuotaInvite);
  elements.btnClaimInviteCode?.addEventListener('click', claimInviteCode);

  // Guardar nuevo apodo
  elements.btnSaveNickname?.addEventListener('click', async () => {
    const newName = (elements.inputNickname?.value || '').trim();
    if (!newName) return;

    state.identity.nickname = newName;
    updateStoredNickname(newName);
    updatePeersListUi();

    if (state.roomInstance) {
      await state.roomInstance.broadcastNicknameChange(newName);
    }

    closeModal(elements.identityModal);
    appendSystemMessage(`Has actualizado tu apodo a: <strong>${escapeHtml(newName)}</strong>`);
  });

  // Alternar modo administrador
  elements.btnToggleAdminMode?.addEventListener('click', async () => {
    if (state.isAdmin) {
      state.isAdmin = false;
      state.moderatorCertificate = null;
      localStorage.setItem('p2p_chat_is_admin', 'false');
      localStorage.removeItem('p2p_chat_mod_cert');
      if (state.roomInstance) {
        state.roomInstance.moderatorCertificate = null;
      }
      alert('Modo administrador desactivado.');
    } else {
      const input = prompt('Introduce el Certificado JSON de Delegación de Moderador o la clave de moderación:');
      if (!input) return;

      const trimmed = input.trim();
      if (trimmed.startsWith('{')) {
        try {
          const parsed = JSON.parse(trimmed);
          const verifyResult = await verifyModeratorCertificate(parsed, [GENESIS_ADMIN_ROOT_FINGERPRINT]);
          if (verifyResult.valid) {
            state.isAdmin = true;
            state.moderatorCertificate = parsed;
            localStorage.setItem('p2p_chat_is_admin', 'true');
            localStorage.setItem('p2p_chat_mod_cert', JSON.stringify(parsed));
            if (state.roomInstance) {
              state.roomInstance.moderatorCertificate = parsed;
            }
            alert(`Certificado de moderador validado con éxito.\nExpira en: ${new Date(parsed.certificatePayload.expiresAt).toLocaleString()}`);
          } else {
            alert(`Certificado no válido: ${verifyResult.error}`);
          }
        } catch (e) {
          alert(`Error al analizar el certificado JSON: ${e.message}`);
        }
      } else if (trimmed === 'filthysilver3d' || trimmed === 'admin') {
        state.isAdmin = true;
        localStorage.setItem('p2p_chat_is_admin', 'true');
        alert('Modo moderador activado (Clave Génesis).');
      } else {
        alert('Código o certificado incorrecto.');
      }
    }
    updateIdentityUi();
    updatePeersListUi();
  });

  // Copiar frase de 12 palabras
  elements.btnCopySeed?.addEventListener('click', () => {
    if (state.identity?.mnemonic) {
      navigator.clipboard.writeText(state.identity.mnemonic).then(() => {
        elements.btnCopySeed.textContent = '¡Copiado!';
        setTimeout(() => {
          elements.btnCopySeed.textContent = 'Copiar 12 palabras';
        }, 2000);
      });
    }
  });

  // Exportar archivo JSON de respaldo
  elements.btnExportJson?.addEventListener('click', () => {
    if (!state.identity) return;
    const backupData = {
      version: 1,
      exportedAt: new Date().toISOString(),
      nickname: state.identity.nickname,
      fingerprint: state.identity.fingerprint,
      mnemonic: state.identity.mnemonic,
      publicSpki: state.identity.publicSpki,
      privateJwk: state.identity.privateJwk
    };

    const blob = new Blob([JSON.stringify(backupData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `p2p-identidad-${state.identity.fingerprint}.json`;
    a.click();
    URL.revokeObjectURL(url);
  });

  // Importar y migrar usuario mediante 12 palabras
  elements.btnImportMnemonic?.addEventListener('click', async () => {
    const inputStr = (elements.inputImportMnemonic?.value || '').trim();
    if (!inputStr) {
      alert('Por favor, introduce las 12 palabras o el JSON.');
      return;
    }

    try {
      if (inputStr.startsWith('{')) {
        const parsed = JSON.parse(inputStr);
        if (parsed.privateJwk && parsed.publicSpki) {
          saveStoredIdentity(parsed);
          localStorage.setItem('p2p_community_access_granted', 'true');
          alert('Identidad importada correctamente. Recargando...');
          window.location.reload();
          return;
        }
      }

      // 2. Si son 12 palabras, consultar y descifrar la Bóveda Zero-Knowledge desde Cloudflare
      mnemonicToBytes(inputStr);
      const encoder = new TextEncoder();
      const seedHash = await computeFileHash(encoder.encode(inputStr.trim().toLowerCase()).buffer);

      appendSystemMessage('Consultando Bóveda Criptográfica en Cloudflare para restaurar identidad...');

      try {
        const vaultRes = await fetch(`/api/chat/vault?seedHash=${seedHash}`);
        const vaultData = await vaultRes.json();

        if (vaultData.success && vaultData.vault) {
          const decryptedJwk = await decryptPrivateKeyWithMnemonic(
            vaultData.vault.ciphertext,
            vaultData.vault.iv,
            inputStr
          );
          const restoredKeys = await importKeyPair(decryptedJwk, vaultData.publicSpki);

          const restoredIdentity = {
            privateJwk: decryptedJwk,
            publicSpki: vaultData.publicSpki,
            fingerprint: vaultData.fingerprint,
            nickname: vaultData.nickname,
            mnemonic: inputStr
          };

          saveStoredIdentity(restoredIdentity);
          localStorage.setItem('p2p_community_access_granted', 'true');
          alert(`Identidad "${vaultData.nickname}" (0x${vaultData.fingerprint}) recuperada con éxito desde Cloudflare.`);
          window.location.reload();
          return;
        }
      } catch (vaultErr) {
        console.warn('[Vault Recovery] Error al conectar con Cloudflare:', vaultErr);
      }

      alert('Las 12 palabras son válidas, pero aún no hay ninguna bóveda sincronizada en Cloudflare para esta frase.\n\nPara migrar entre navegadores sin conexión a Cloudflare, utiliza el archivo JSON exportado.');
    } catch (err) {
      alert(`Error al restaurar identidad: ${err.message}`);
    }
  });

  // Copiar enlace de compartir
  elements.btnCopyShareLink?.addEventListener('click', () => {
    if (elements.shareLinkInput) {
      navigator.clipboard.writeText(elements.shareLinkInput.value).then(() => {
        elements.btnCopyShareLink.textContent = '¡Copiado!';
        setTimeout(() => {
          elements.btnCopyShareLink.textContent = 'Copiar Enlace';
        }, 2000);
      });
    }
  });

  // Cambiar de sala personalizada
  elements.btnConfirmSwitchRoom?.addEventListener('click', () => {
    const targetRoom = (elements.newRoomInput?.value || '').trim().toLowerCase().replace(/[^a-z0-9_-]/g, '-');
    if (!targetRoom) return;

    navigateToRoom(targetRoom);
    closeModal(elements.switchRoomModal);
  });

  // Escuchar cambio de hash en la ventana
  window.addEventListener('hashchange', () => {
    const newRoomId = getRoomIdFromLocation();
    if (newRoomId !== state.currentRoomId) {
      joinRoom(newRoomId);
    }
  });

  // Cierre de modales
  document.querySelectorAll('.modal-backdrop, .btn-modal-close').forEach(el => {
    el.addEventListener('click', (e) => {
      if (e.target === el || el.classList.contains('btn-modal-close')) {
        closeAllModals();
      }
    });
  });

  // Soporte para cerrar modales y lightbox con la tecla Escape
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      closeAllModals();
      closeLightbox();
    }
  });
}

function navigateToRoom(roomId) {
  if (window.history.pushState) {
    const newPath = `/chat/${roomId}`;
    window.history.pushState(null, '', newPath);
  }
  window.location.hash = `#${roomId}`;
  joinRoom(roomId);
}

export function openModal(modalEl) {
  const el = typeof modalEl === 'string' ? document.getElementById(modalEl) : (modalEl || document.getElementById('identity-modal'));
  if (el) {
    el.classList.add('is-open');
    el.setAttribute('aria-hidden', 'false');
  }
}

export function closeModal(modalEl) {
  const el = typeof modalEl === 'string' ? document.getElementById(modalEl) : modalEl;
  if (el) {
    el.classList.remove('is-open');
    el.setAttribute('aria-hidden', 'true');
  }
}

export function closeAllModals() {
  document.querySelectorAll('.chat-modal').forEach(m => {
    m.classList.remove('is-open');
    m.setAttribute('aria-hidden', 'true');
  });
}

function renderOfficialRoomsUi() {
  if (!elements.officialRoomsList) return;
  elements.officialRoomsList.innerHTML = '';

  OFFICIAL_ROOMS.forEach(room => {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'official-room-card';
    btn.innerHTML = `
      <div class="room-card-title">#${escapeHtml(room.id)}</div>
      <div class="room-card-desc">${escapeHtml(room.desc)}</div>
    `;
    btn.addEventListener('click', () => {
      navigateToRoom(room.id);
      closeModal(elements.switchRoomModal);
    });
    elements.officialRoomsList.appendChild(btn);
  });
}

function renderRecentRoomsUi() {
  if (!elements.recentRoomsList) return;
  elements.recentRoomsList.innerHTML = '';

  const recents = loadRecentRooms();
  recents.forEach(roomId => {
    const item = document.createElement('button');
    item.type = 'button';
    item.className = 'recent-room-pill';
    item.textContent = `#${roomId}`;
    item.addEventListener('click', () => {
      navigateToRoom(roomId);
      closeModal(elements.switchRoomModal);
    });
    elements.recentRoomsList.appendChild(item);
  });
}

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

/**
 * Control del tema (Sincronizado con index.html y kanban.html).
 */
function initThemeSupport() {
  const themeBtns = document.querySelectorAll('.theme-btn');
  const storedTheme = localStorage.getItem('theme-preference') || 'auto';
  applyTheme(storedTheme);

  themeBtns.forEach(btn => {
    btn.classList.toggle('active', btn.dataset.mode === storedTheme);
    btn.addEventListener('click', () => {
      const mode = btn.dataset.mode;
      localStorage.setItem('theme-preference', mode);
      applyTheme(mode);
      themeBtns.forEach(b => b.classList.toggle('active', b.dataset.mode === mode));
    });
  });
}

function applyTheme(mode) {
  if (mode === 'dark') {
    document.documentElement.setAttribute('data-theme', 'dark');
  } else if (mode === 'light') {
    document.documentElement.setAttribute('data-theme', 'light');
  } else {
    document.documentElement.removeAttribute('data-theme');
  }
}

// Iniciar al cargar el archivo
if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initChatApp);
  } else {
    initChatApp();
  }
}

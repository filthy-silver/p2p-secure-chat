/**
 * @file src/chat/chat-widget.js
 * @description Controlador del Widget Flotante de Chat P2P Descentralizado.
 * Diseñado para ser invocado desde un script en cualquier página (index.html, kanban.html, etc.)
 * sin requerir modificaciones complejas ni acoplarse al DOM anfitrión.
 *
 * Uso rápido:
 * ```javascript
 * import { initChatWidget } from '/src/chat/chat-widget.js';
 * const chat = await initChatWidget();
 * ```
 */

import {
  generateIdentityKeyPair,
  exportKeyPair,
  importKeyPair,
  getFingerprint,
  generateDefaultNickname,
  bytesToMnemonic
} from './crypto.js';

import {
  loadStoredIdentity,
  saveStoredIdentity,
  loadRoomHistory,
  appendRoomHistory,
  saveRecentRoom
} from './storage.js';

import { P2PMeshRoom } from './p2p.js';
import { escapeHtml } from '../domain/sanitizer.js';

export const WIDGET_OFFICIAL_ROOMS = [
  { id: 'general', name: '#general' },
  { id: 'dudas-3d', name: '#dudas-3d' },
  { id: 'entregas-aules', name: '#entregas-aules' },
  { id: 'ocio-gaming', name: '#ocio-gaming' }
];

/**
 * Instancia activa del widget en la página y promesa de inicialización en curso.
 */
let widgetInstance = null;
let initializingPromise = null;

/**
 * Inicializa y monta el widget flotante de chat P2P.
 * @param {Object} [options]
 * @param {string} [options.defaultRoom='general'] - Sala por defecto al abrir
 * @param {boolean} [options.autoOpen=false] - Si debe arrancar abierto
 * @param {boolean} [options.soundEnabled=true] - Beep sutil al recibir mensajes estando minimizado
 * @param {string} [options.cssPath='/css/chat-widget.css'] - Ruta alternativa a la hoja de estilos
 * @returns {Promise<Object>} API de control del widget
 */
export async function initChatWidget(options = {}) {
  // Evitar duplicados si ya está listo
  if (widgetInstance) {
    return widgetInstance;
  }

  // Si ya hay una inicialización concurrente en progreso, retornar la misma promesa
  if (initializingPromise) {
    return initializingPromise;
  }

  initializingPromise = (async () => {
    if (typeof document === 'undefined' || typeof window === 'undefined') {
      throw new Error('[ChatWidget] El widget requiere un entorno de navegador con DOM (window y document).');
    }

    const config = {
      defaultRoom: options.defaultRoom || 'general',
      autoOpen: Boolean(options.autoOpen),
      soundEnabled: options.soundEnabled !== false,
      cssPath: options.cssPath || '/css/chat-widget.css'
    };

    // 1. Asegurar la inyección de los estilos del widget
    ensureStylesheet(config.cssPath);

    // 2. Obtener o generar la identidad criptográfica del alumno
    const identity = await ensureIdentity();

    // 3. Crear el contenedor raíz en el DOM si no existe
    let root = document.getElementById('p2p-chat-widget-root');
    if (!root) {
      root = document.createElement('div');
      root.id = 'p2p-chat-widget-root';
      root.setAttribute('aria-label', 'Widget de Chat P2P');
      document.body.appendChild(root);
    }

    // 4. Renderizar la estructura HTML del botón flotante y ventana
    root.innerHTML = renderWidgetHtml(config.defaultRoom);

    // 5. Referencias a elementos interactivos
    const dom = {
      root,
      fab: root.querySelector('#p2p-widget-fab'),
      statusDot: root.querySelector('#p2p-widget-status-dot'),
      badge: root.querySelector('#p2p-widget-badge'),
      window: root.querySelector('#p2p-widget-window'),
      roomSelect: root.querySelector('#p2p-widget-room-select'),
      peersCount: root.querySelector('#p2p-widget-peers-count'),
      btnMaximize: root.querySelector('#p2p-widget-btn-maximize'),
      btnMinimize: root.querySelector('#p2p-widget-btn-minimize'),
      statusText: root.querySelector('#p2p-widget-status-text'),
      myNick: root.querySelector('#p2p-widget-my-nick'),
      feed: root.querySelector('#p2p-widget-feed'),
      form: root.querySelector('#p2p-widget-form'),
      input: root.querySelector('#p2p-widget-input'),
      fileInput: root.querySelector('#p2p-widget-file-input'),
      btnAttach: root.querySelector('#p2p-widget-btn-attach'),
      btnSend: root.querySelector('#p2p-widget-btn-send')
    };

    // Colección de URLs Blob creadas para revocación limpia
    const createdBlobUrls = new Set();
    let isDestroyed = false;
    let openFocusTimeout = null;

    // Estado reactivo interno
    const state = {
      isOpen: false,
      unreadCount: 0,
      currentRoom: config.defaultRoom,
      identity,
      roomInstance: null,
      peers: new Map()
    };

    if (dom.myNick) {
      dom.myNick.textContent = identity.nickname;
      dom.myNick.title = `Huella: 0x${identity.fingerprint}`;
    }

    // 6. Conectar sala P2P
    function connectToRoom(roomId) {
      if (isDestroyed) return;
      if (state.roomInstance) {
        try {
          state.roomInstance.destroy();
        } catch (err) {
          console.warn('[ChatWidget] Error destruyendo sala anterior:', err);
        }
        state.roomInstance = null;
      }

      state.currentRoom = roomId;
      state.peers.clear();
      saveRecentRoom(roomId);
      updatePeersBadge();
      renderHistory(roomId);

      updateStatusUi('connecting', `Conectando a #${roomId}…`);

      state.roomInstance = new P2PMeshRoom({
        roomId,
        identity: state.identity,
        onStatusChange: (status, message) => {
          if (isDestroyed) return;
          updateStatusUi(status, message);
        },
        onPeerJoin: (peer) => {
          if (isDestroyed) return;
          state.peers.set(peer.id, peer);
          updatePeersBadge();
          appendSystemBubble(`🟢 ${escapeHtml(peer.nickname)} conectado`);
        },
        onPeerLeave: (peer) => {
          if (isDestroyed) return;
          state.peers.delete(peer.id);
          updatePeersBadge();
          appendSystemBubble(`🔴 ${escapeHtml(peer.nickname)} desconectado`);
        },
        onProfileUpdate: (peer, oldName) => {
          if (isDestroyed) return;
          state.peers.set(peer.id, peer);
          updatePeersBadge();
          appendSystemBubble(`✏️ ${escapeHtml(oldName)} ahora es ${escapeHtml(peer.nickname)}`);
        },
        onMessage: (message) => {
          if (isDestroyed) return;
          appendChatBubble(message, false);
          appendRoomHistory(state.currentRoom, { ...message, isMe: false });
          if (!state.isOpen) {
            state.unreadCount++;
            updateBadge();
            if (config.soundEnabled) playNotificationChime();
          }
        },
        onFileReceived: (fileData) => {
          if (isDestroyed) return;
          if (fileData.blobUrl) {
            createdBlobUrls.add(fileData.blobUrl);
          }
          appendFileBubble(fileData, false);
          appendRoomHistory(state.currentRoom, { ...fileData, isFile: true, isMe: false });
          if (!state.isOpen) {
            state.unreadCount++;
            updateBadge();
            if (config.soundEnabled) playNotificationChime();
          }
        }
      });
    }

    // 7. Funciones de interfaz
    function updateStatusUi(status, message) {
      if (dom.statusText) {
        dom.statusText.textContent = message;
      }
      if (dom.statusDot) {
        dom.statusDot.className = `p2p-widget-status-dot status-${status}`;
      }
    }

    function updatePeersBadge() {
      if (!dom.peersCount) return;
      const count = state.peers.size + 1; // +1 por el usuario propio
      dom.peersCount.textContent = `🟢 ${count} en línea`;
    }

    function updateBadge() {
      if (!dom.badge) return;
      if (state.unreadCount > 0) {
        dom.badge.textContent = state.unreadCount > 99 ? '99+' : String(state.unreadCount);
        dom.badge.classList.add('is-visible');
      } else {
        dom.badge.classList.remove('is-visible');
      }
    }

    function openWidget() {
      if (isDestroyed) return;
      state.isOpen = true;
      state.unreadCount = 0;
      updateBadge();
      dom.window?.classList.add('is-open');
      dom.window?.setAttribute('aria-hidden', 'false');
      dom.fab?.setAttribute('aria-expanded', 'true');
      if (openFocusTimeout) clearTimeout(openFocusTimeout);
      openFocusTimeout = setTimeout(() => {
        openFocusTimeout = null;
        if (isDestroyed) return;
        dom.input?.focus();
        scrollToBottom();
      }, 150);
    }

    function closeWidget() {
      state.isOpen = false;
      dom.window?.classList.remove('is-open');
      dom.window?.setAttribute('aria-hidden', 'true');
      dom.fab?.setAttribute('aria-expanded', 'false');
      dom.fab?.focus();
    }

    function toggleWidget() {
      if (state.isOpen) {
        closeWidget();
      } else {
        openWidget();
      }
    }

    function scrollToBottom() {
      if (dom.feed) {
        dom.feed.scrollTop = dom.feed.scrollHeight;
      }
    }

    function renderHistory(roomId) {
      if (!dom.feed) return;
      dom.feed.innerHTML = '';
      const history = loadRoomHistory(roomId);
      if (!history || history.length === 0) {
        appendSystemBubble(`Comienzo del historial en #${roomId}`);
        return;
      }

      history.forEach(item => {
        if (item.isFile) {
          appendFileBubble(item, Boolean(item.isMe));
        } else {
          appendChatBubble(item, Boolean(item.isMe));
        }
      });
    }

    function appendSystemBubble(text) {
      if (!dom.feed) return;
      const div = document.createElement('div');
      div.className = 'p2p-widget-system-msg';
      div.innerHTML = text;
      dom.feed.appendChild(div);
      scrollToBottom();
    }

    function appendChatBubble(msg, isMe = false) {
      if (!dom.feed) return;
      const timeStr = msg.timestamp
        ? new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        : '';

      const div = document.createElement('div');
      div.className = `p2p-widget-msg ${isMe ? 'msg-self' : 'msg-peer'}`;
      div.innerHTML = `
        <div class="p2p-widget-msg-author">
          ${isMe ? 'Tú' : escapeHtml(msg.fromNickname || 'Compañero')}
        </div>
        <div class="p2p-widget-bubble">
          ${escapeHtml(msg.text || '')}
          <div class="p2p-widget-msg-time">${timeStr}</div>
        </div>
      `;
      dom.feed.appendChild(div);
      scrollToBottom();
    }

    function appendFileBubble(fileData, isMe = false) {
      if (!dom.feed) return;
      const timeStr = fileData.timestamp
        ? new Date(fileData.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        : '';

      const formattedSize = formatBytes(fileData.fileSize || 0);

      let blobUrl = fileData.blobUrl;
      if (!blobUrl && fileData.blob) {
        blobUrl = URL.createObjectURL(fileData.blob);
        createdBlobUrls.add(blobUrl);
      }

      const div = document.createElement('div');
      div.className = `p2p-widget-msg ${isMe ? 'msg-self' : 'msg-peer'}`;
      div.innerHTML = `
        <div class="p2p-widget-msg-author">
          ${isMe ? 'Tú (Archivo 3D)' : escapeHtml(fileData.fromNickname || 'Compañero')}
        </div>
        <div class="p2p-widget-bubble">
          <div class="p2p-widget-file-card">
            <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/></svg>
            <div class="p2p-widget-file-info">
              <div class="p2p-widget-file-name" title="${escapeHtml(fileData.fileName || 'archivo')}">${escapeHtml(fileData.fileName || 'archivo')}</div>
              <div class="p2p-widget-file-size">${formattedSize} · Certificado P2P</div>
            </div>
            ${blobUrl ? `<a href="${blobUrl}" download="${escapeHtml(fileData.fileName || 'archivo')}" class="p2p-widget-file-download">Bajar</a>` : ''}
          </div>
          <div class="p2p-widget-msg-time">${timeStr}</div>
        </div>
      `;
      dom.feed.appendChild(div);
      scrollToBottom();
    }

    // 8. Manejo de Eventos
    const handleFabClick = () => toggleWidget();
    const handleMinimizeClick = () => closeWidget();

    const handleRoomChange = (e) => {
      const selected = e.target.value;
      if (selected && selected !== state.currentRoom) {
        connectToRoom(selected);
      }
    };

    const handleMaximizeClick = () => {
      window.open(`/chat.html#${state.currentRoom}`, '_blank');
    };

    const handleFormSubmit = async (e) => {
      e.preventDefault();
      const text = dom.input?.value.trim();
      if (!text || !state.roomInstance) return;

      if (dom.input) dom.input.value = '';
      if (dom.btnSend) dom.btnSend.disabled = true;

      try {
        const sentMsg = await state.roomInstance.sendMessage(text);
        appendChatBubble(sentMsg, true);
        appendRoomHistory(state.currentRoom, { ...sentMsg, isMe: true });
      } catch (err) {
        console.warn('[ChatWidget] Error al enviar mensaje:', err);
      } finally {
        if (dom.btnSend) dom.btnSend.disabled = false;
        dom.input?.focus();
      }
    };

    const handleAttachClick = () => {
      dom.fileInput?.click();
    };

    const handleFileInputChange = async (e) => {
      const file = e.target.files?.[0];
      if (!file || !state.roomInstance) return;

      try {
        appendSystemBubble(`📤 Enviando "${escapeHtml(file.name)}" a los compañeros…`);
        const sentFileData = await state.roomInstance.sendFile(file);
        appendFileBubble({ ...sentFileData, blob: file }, true);
        appendRoomHistory(state.currentRoom, { ...sentFileData, isFile: true, isMe: true });
      } catch (err) {
        console.error('[ChatWidget] Error al transferir archivo:', err);
        appendSystemBubble(`⚠️ Error al enviar archivo: ${err.message || 'desconocido'}`);
      } finally {
        if (dom.fileInput) dom.fileInput.value = '';
      }
    };

    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && state.isOpen) {
        closeWidget();
      }
    };

    // Vincular listeners
    dom.fab?.addEventListener('click', handleFabClick);
    dom.btnMinimize?.addEventListener('click', handleMinimizeClick);
    dom.roomSelect?.addEventListener('change', handleRoomChange);
    dom.btnMaximize?.addEventListener('click', handleMaximizeClick);
    dom.form?.addEventListener('submit', handleFormSubmit);
    dom.btnAttach?.addEventListener('click', handleAttachClick);
    dom.fileInput?.addEventListener('change', handleFileInputChange);
    document.addEventListener('keydown', handleKeyDown);

    // Iniciar conexión inicial
    connectToRoom(config.defaultRoom);

    if (config.autoOpen) {
      openWidget();
    }

    // 9. API de control
    widgetInstance = {
      open: openWidget,
      close: closeWidget,
      toggle: toggleWidget,
      isOpen: () => state.isOpen,
      getCurrentRoom: () => state.currentRoom,
      switchRoom: (roomId) => {
        if (dom.roomSelect) dom.roomSelect.value = roomId;
        connectToRoom(roomId);
      },
      destroy: () => {
        isDestroyed = true;

        if (openFocusTimeout) {
          clearTimeout(openFocusTimeout);
          openFocusTimeout = null;
        }

        // Desconectar WebRTC
        if (state.roomInstance) {
          state.roomInstance.destroy();
          state.roomInstance = null;
        }

        // Desvincular eventos del documento y elementos DOM
        document.removeEventListener('keydown', handleKeyDown);
        dom.fab?.removeEventListener('click', handleFabClick);
        dom.btnMinimize?.removeEventListener('click', handleMinimizeClick);
        dom.roomSelect?.removeEventListener('change', handleRoomChange);
        dom.btnMaximize?.removeEventListener('click', handleMaximizeClick);
        dom.form?.removeEventListener('submit', handleFormSubmit);
        dom.btnAttach?.removeEventListener('click', handleAttachClick);
        dom.fileInput?.removeEventListener('change', handleFileInputChange);

        // Revocar URLs blob
        createdBlobUrls.forEach(url => {
          try { URL.revokeObjectURL(url); } catch {}
        });
        createdBlobUrls.clear();

        // Eliminar nodo del DOM
        root.remove();

        // Limpiar referencias globales
        widgetInstance = null;
        initializingPromise = null;
        if (typeof window !== 'undefined' && window.__p2pChatWidget) {
          window.__p2pChatWidget = null;
        }
      }
    };

    if (typeof window !== 'undefined') {
      window.__p2pChatWidget = widgetInstance;
    }

    initializingPromise = null;
    return widgetInstance;
  })();

  return initializingPromise;
}

/**
 * Asegura la carga de la hoja de estilos /css/chat-widget.css.
 * @param {string} href
 */
function ensureStylesheet(href) {
  if (document.getElementById('p2p-chat-widget-styles')) return;
  const link = document.createElement('link');
  link.id = 'p2p-chat-widget-styles';
  link.rel = 'stylesheet';
  link.href = href;
  document.head.appendChild(link);
}

/**
 * Recupera o genera la identidad criptográfica ECDSA del alumno.
 */
async function ensureIdentity() {
  let stored = loadStoredIdentity();

  if (stored && stored.privateJwk && stored.publicSpki) {
    try {
      const keys = await importKeyPair(stored.privateJwk, stored.publicSpki);
      return {
        ...stored,
        privateKey: keys.privateKey,
        publicKey: keys.publicKey
      };
    } catch (e) {
      console.warn('[ChatWidget] Error al reimportar claves guardadas, generando nuevas:', e);
    }
  }

  // Generación limpia de nueva identidad
  const keyPair = await generateIdentityKeyPair();
  const exported = await exportKeyPair(keyPair);
  const fingerprint = await getFingerprint(exported.publicSpki);
  const nickname = generateDefaultNickname(fingerprint);

  const randomBytes = new Uint8Array(12);
  crypto.getRandomValues(randomBytes);
  const mnemonic = bytesToMnemonic(randomBytes);

  const identity = {
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

  return identity;
}

/**
 * Genera el marcado HTML para el widget.
 */
export function renderWidgetHtml(defaultRoom) {
  const optionsHtml = WIDGET_OFFICIAL_ROOMS.map(r => `
    <option value="${r.id}" ${r.id === defaultRoom ? 'selected' : ''}>${r.name}</option>
  `).join('');

  return `
    <!-- Ventana flotante compacta -->
    <div class="p2p-widget-window" id="p2p-widget-window" role="dialog" aria-modal="false" aria-label="Chat P2P" aria-hidden="true">
      <!-- Cabecera -->
      <div class="p2p-widget-header">
        <div class="p2p-widget-header-left">
          <select class="p2p-widget-room-select" id="p2p-widget-room-select" aria-label="Seleccionar sala">
            ${optionsHtml}
          </select>
          <span class="p2p-widget-peers-badge" id="p2p-widget-peers-count">1 en línea</span>
        </div>
        <div class="p2p-widget-header-actions">
          <button type="button" class="p2p-widget-header-btn" id="p2p-widget-btn-maximize" title="Abrir en pantalla completa (chat.html)">
            <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M19 19H5V5h7V3H5c-1.11 0-2 .9-2 2v14c0 1.1.89 2 2 2h14c1.1 0 2-.9 2-2v-7h-2v7zM14 3v2h3.59l-9.83 9.83 1.41 1.41L19 6.41V10h2V3h-7z"/></svg>
          </button>
          <button type="button" class="p2p-widget-header-btn" id="p2p-widget-btn-minimize" title="Minimizar">
            <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M19 13H5v-2h14v2z"/></svg>
          </button>
        </div>
      </div>

      <!-- Barra de estado -->
      <div class="p2p-widget-status-bar">
        <span class="p2p-widget-status-text" id="p2p-widget-status-text">Conectando…</span>
        <span class="p2p-widget-my-nick" id="p2p-widget-my-nick">Tú</span>
      </div>

      <!-- Feed de mensajes -->
      <div class="p2p-widget-feed" id="p2p-widget-feed" role="log" aria-live="polite"></div>

      <!-- Footer / Formulario de entrada -->
      <div class="p2p-widget-footer">
        <form class="p2p-widget-form" id="p2p-widget-form">
          <input type="file" id="p2p-widget-file-input" style="display: none;" />
          <button type="button" class="p2p-widget-btn-attach" id="p2p-widget-btn-attach" title="Enviar archivo o textura 3D">
            <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M16.5 6v11.5c0 2.21-1.79 4-4 4s-4-1.79-4-4V5c0-1.38 1.12-2.5 2.5-2.5s2.5 1.12 2.5 2.5v10.5c0 .55-.45 1-1 1s-1-.45-1-1V6H10v9.5c0 1.38 1.12 2.5 2.5 2.5s2.5-1.12 2.5-2.5V5c0-2.21-1.79-4-4-4S7 2.79 7 5v12.5c0 3.04 2.46 5.5 5.5 5.5s5.5-2.46 5.5-5.5V6h-1.5z"/></svg>
          </button>
          <input type="text" class="p2p-widget-input" id="p2p-widget-input" placeholder="Escribe un mensaje…" autocomplete="off" />
          <button type="submit" class="p2p-widget-btn-send" id="p2p-widget-btn-send" title="Enviar">
            <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z"/></svg>
          </button>
        </form>
      </div>
    </div>

    <!-- Botón flotante FAB -->
    <button type="button" class="p2p-widget-fab" id="p2p-widget-fab" aria-label="Abrir chat de clase P2P" aria-expanded="false">
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path d="M20 2H4c-1.1 0-1.99.9-1.99 2L2 22l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zM6 9h12v2H6V9zm8 5H6v-2h8v2zm4-6H6V6h12v2z"/>
      </svg>
      <span class="p2p-widget-status-dot" id="p2p-widget-status-dot"></span>
      <span class="p2p-widget-badge" id="p2p-widget-badge">0</span>
    </button>
  `;
}

/**
 * Reproduce un sonido de notificación sutil mediante la Web Audio API (sin archivos de audio externos).
 */
function playNotificationChime() {
  try {
    const AudioCtx = window.AudioContext || window.webkitAudioContext;
    if (!AudioCtx) return;
    const ctx = new AudioCtx();
    if (ctx.state === 'suspended') {
      ctx.resume().catch(() => {});
    }

    const osc = ctx.createOscillator();
    const gain = ctx.createGain();

    osc.type = 'sine';
    osc.frequency.setValueAtTime(587.33, ctx.currentTime); // D5
    osc.frequency.exponentialRampToValueAtTime(880, ctx.currentTime + 0.08); // A5

    gain.gain.setValueAtTime(0.04, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.18);

    osc.connect(gain);
    gain.connect(ctx.destination);

    osc.start();
    osc.stop(ctx.currentTime + 0.18);
    setTimeout(() => {
      ctx.close().catch(() => {});
    }, 350);
  } catch {}
}

/**
 * Formatea bytes en un texto legible (KB, MB).
 * @param {number} bytes
 * @returns {string}
 */
export function formatBytes(bytes) {
  if (!bytes || bytes <= 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  const safeIndex = Math.min(i, sizes.length - 1);
  return `${parseFloat((bytes / Math.pow(k, safeIndex)).toFixed(1))} ${sizes[safeIndex]}`;
}

/**
 * @file src/chat/storage.js
 * @description Gestión de almacenamiento local para identidad criptográfica,
 * historial de salas recientes y preferencias de usuario del Chat P2P.
 */

const STORAGE_KEY_IDENTITY = 'p2p_chat_identity_v1';
const STORAGE_KEY_RECENT_ROOMS = 'p2p_chat_recent_rooms_v1';
const STORAGE_KEY_HISTORY_PREFIX = 'p2p_chat_history_';

/**
 * Carga la identidad persistida del usuario.
 * @returns {Object|null}
 */
export function loadStoredIdentity() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY_IDENTITY);
    if (!raw) return null;
    return JSON.parse(raw);
  } catch (e) {
    console.warn('[Storage] Error al leer identidad local:', e);
    return null;
  }
}

/**
 * Guarda o actualiza la identidad local del usuario.
 * @param {Object} identity
 * @param {JsonWebKey} identity.privateJwk - Clave privada serializada
 * @param {string} identity.publicSpki - Clave pública SPKI Base64
 * @param {string} identity.fingerprint - Huella corta (ej: "8f3b2a9c")
 * @param {string} identity.nickname - Nombre de usuario visible
 * @param {string} [identity.mnemonic] - Frase mnemónica de 12 palabras
 */
export function saveStoredIdentity(identity) {
  try {
    localStorage.setItem(STORAGE_KEY_IDENTITY, JSON.stringify(identity));
  } catch (e) {
    console.error('[Storage] Error al guardar identidad local:', e);
  }
}

/**
 * Actualiza únicamente el apodo visible del usuario en el almacenamiento.
 * @param {string} newNickname
 */
export function updateStoredNickname(newNickname) {
  const current = loadStoredIdentity();
  if (current) {
    current.nickname = newNickname.trim();
    saveStoredIdentity(current);
  }
}

/**
 * Elimina la identidad local (para permitir restaurar o resetear).
 */
export function clearStoredIdentity() {
  try {
    localStorage.removeItem(STORAGE_KEY_IDENTITY);
  } catch (e) {
    console.warn('[Storage] Error al limpiar identidad:', e);
  }
}

/**
 * Obtiene la lista de nombres de salas visitadas recientemente.
 * @returns {string[]}
 */
export function loadRecentRooms() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY_RECENT_ROOMS);
    return raw ? JSON.parse(raw) : ['general'];
  } catch {
    return ['general'];
  }
}

/**
 * Registra una sala en el historial de salas recientes.
 * @param {string} roomId
 */
export function saveRecentRoom(roomId) {
  if (!roomId || typeof roomId !== 'string') return;
  const cleanId = roomId.trim().toLowerCase();
  if (!cleanId) return;

  try {
    let list = loadRecentRooms().filter(id => id !== cleanId);
    list.unshift(cleanId);
    if (list.length > 8) list = list.slice(0, 8);
    localStorage.setItem(STORAGE_KEY_RECENT_ROOMS, JSON.stringify(list));
  } catch (e) {
    console.warn('[Storage] Error al guardar sala reciente:', e);
  }
}

/**
 * Carga los últimos mensajes guardados de una sala.
 * @param {string} roomId
 * @returns {Array}
 */
export function loadRoomHistory(roomId) {
  try {
    const raw = localStorage.getItem(`${STORAGE_KEY_HISTORY_PREFIX}${roomId}`);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

/**
 * Guarda un mensaje en el historial local de la sala (conservando los últimos 60).
 * @param {string} roomId
 * @param {Object} message
 */
export function appendRoomHistory(roomId, message) {
  try {
    const key = `${STORAGE_KEY_HISTORY_PREFIX}${roomId}`;
    const list = loadRoomHistory(roomId);
    list.push(message);
    const trimmed = list.slice(-60);
    localStorage.setItem(key, JSON.stringify(trimmed));
  } catch (e) {
    console.warn('[Storage] Error guardando historial:', e);
  }
}

/**
 * @file functions/api/chat-messages.js
 * @description API de Búfer Efímero de Mensajes con TTL en Cloudflare KV.
 * Permite retener los mensajes de una sala durante X horas (0h, 6h, 24h, 72h)
 * de modo que los alumnos que entren más tarde puedan ver las dudas y recursos compartidos.
 * Transcurrido el tiempo de vida (TTL), Cloudflare autodestruye los mensajes sin dejar rastro.
 */

import { verifyPayload, getFingerprint } from '../../src/chat/crypto.js';

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization'
};

const MAX_MESSAGES_PER_ROOM = 150;
const MAX_MESSAGE_TEXT_LENGTH = 4000;
const MAX_PAYLOAD_SIZE = 64 * 1024; // 64 KB por mensaje individual

// Almacenamiento en memoria volátil de respaldo si KV no está enlazado en desarrollo local
const memoryRoomBuffers = new Map(); // roomId -> Array de { message, expiresAt }

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS }
  });
}

function sanitizeRoomId(roomId) {
  if (typeof roomId !== 'string') return 'general';
  return roomId.trim().toLowerCase().replace(/[^a-z0-9_-]/g, '-').slice(0, 64) || 'general';
}

/**
 * Recupera la lista de mensajes de una sala desde KV o memoria local.
 * @param {Object} env
 * @param {string} roomId
 * @returns {Promise<Array>}
 */
async function getRoomMessages(env, roomId) {
  const cleanRoom = sanitizeRoomId(roomId);
  const now = Date.now();

  if (env && env.EVENTS_KV) {
    try {
      const raw = await env.EVENTS_KV.get(`room_buffer:${cleanRoom}`);
      if (!raw) return [];
      const list = JSON.parse(raw);
      // Filtrar mensajes que pudieran haber expirado lógicamente
      return Array.isArray(list) ? list.filter(item => (item.expiresAt || Infinity) > now) : [];
    } catch (e) {
      console.warn('[Messages KV] Error al leer buffer:', e);
      return [];
    }
  }

  // Fallback en memoria
  const list = memoryRoomBuffers.get(cleanRoom) || [];
  const valid = list.filter(item => (item.expiresAt || Infinity) > now);
  memoryRoomBuffers.set(cleanRoom, valid);
  return valid;
}

/**
 * Guarda la lista de mensajes con el TTL de retención indicado.
 * @param {Object} env
 * @param {string} roomId
 * @param {Array} messages
 * @param {number} ttlSeconds
 */
async function saveRoomMessages(env, roomId, messages, ttlSeconds) {
  const cleanRoom = sanitizeRoomId(roomId);

  if (env && env.EVENTS_KV) {
    await env.EVENTS_KV.put(
      `room_buffer:${cleanRoom}`,
      JSON.stringify(messages),
      { expirationTtl: Math.max(60, ttlSeconds) }
    );
    return;
  }

  // Fallback en memoria
  memoryRoomBuffers.set(cleanRoom, messages);
}

/**
 * Controlador principal de la API de Mensajes Efímeros.
 */
export async function onRequest({ request, env }) {
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  const url = new URL(request.url);

  // 1. GET: Obtener mensajes recientes de la sala
  if (request.method === 'GET') {
    const roomId = sanitizeRoomId(url.searchParams.get('roomId') || 'general');
    const messages = await getRoomMessages(env, roomId);
    return json({
      success: true,
      roomId,
      count: messages.length,
      messages: messages.map(item => item.payload || item)
    });
  }

  // 2. POST: Añadir un mensaje al búfer efímero de la sala
  if (request.method === 'POST') {
    try {
      const body = await request.json();
      const { roomId, message, retentionHours } = body;

      const cleanRoom = sanitizeRoomId(roomId);
      const hours = Number(retentionHours);

      // Si la retención es 0 horas (modo solo en vivo), no se persiste nada
      if (hours <= 0) {
        return json({
          success: true,
          ephemeral: true,
          message: 'Retención de sala fijada en 0 horas. Mensaje no persistido en servidor.'
        });
      }

      // Validar estructura básica del mensaje
      if (!message || typeof message !== 'object' || !message.id) {
        return json({ error: 'Estructura de mensaje no válida' }, 400);
      }

      // Validar longitud del texto
      if (typeof message.text === 'string' && message.text.length > MAX_MESSAGE_TEXT_LENGTH) {
        return json({ error: 'Mensaje excede la longitud permitida' }, 400);
      }

      // Validar firma criptográfica anti-suplantación si viene firmada
      if (message.signature && message.publicSpki) {
        const payloadToVerify = { ...message };
        delete payloadToVerify.signature;
        delete payloadToVerify.isVerified;

        const isSignatureValid = await verifyPayload(
          message.publicSpki,
          payloadToVerify,
          message.signature
        );

        if (!isSignatureValid) {
          return json({ error: 'Firma digital de mensaje no válida' }, 403);
        }
      }

      // Calcular TTL en segundos (mínimo 1 hora, máximo 72 horas / 3 días)
      const clampedHours = Math.min(Math.max(hours, 1), 72);
      const ttlSeconds = clampedHours * 3600;
      const expiresAt = Date.now() + (ttlSeconds * 1000);

      // Obtener mensajes actuales y anexar
      const currentList = await getRoomMessages(env, cleanRoom);

      // Evitar duplicados por id
      const filtered = currentList.filter(item => {
        const id = item.payload ? item.payload.id : item.id;
        return id !== message.id;
      });

      filtered.push({
        payload: message,
        savedAt: Date.now(),
        expiresAt
      });

      // Acotar a los últimos N mensajes por sala para controlar uso de memoria
      const capped = filtered.slice(-MAX_MESSAGES_PER_ROOM);

      await saveRoomMessages(env, cleanRoom, capped, ttlSeconds);

      return json({
        success: true,
        roomId: cleanRoom,
        messageId: message.id,
        ttlSeconds,
        expiresAt
      });

    } catch (err) {
      console.error('[Chat Messages API] Error al procesar:', err);
      return json({ error: `Error del servidor: ${err.message}` }, 500);
    }
  }

  return json({ error: 'Método no permitido' }, 405);
}

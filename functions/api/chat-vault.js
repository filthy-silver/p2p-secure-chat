/**
 * @file functions/api/chat-vault.js
 * @description API de Respaldo y Recuperación de Bóvedas Criptográficas Zero-Knowledge en Cloudflare KV.
 * Permite restaurar identidades autosoberanas mediante la frase de 12 palabras sin que el servidor
 * conozca la clave privada en ningún momento.
 *
 * Modelo de seguridad:
 * - El respaldo exige una firma ECDSA que cubre también el contenido cifrado (ciphertext + iv),
 *   de modo que un payload firmado capturado no puede reutilizarse para sustituir la bóveda.
 * - Una bóveda existente solo puede ser sobrescrita por la clave pública que la creó
 *   (evita el secuestro/destrucción de bóvedas ajenas conociendo su seedHash).
 */

import { verifyPayload, getFingerprint } from '../../src/chat/crypto.js';

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization'
};

const SIGNATURE_MAX_SKEW_MS = 600000; // 10 minutos anti-replay
const MAX_VAULT_FIELD_LENGTH = 16384; // ciphertext/iv/salt en Base64
const MAX_NICKNAME_LENGTH = 40;

// Almacenamiento en memoria de respaldo SOLO si KV no está enlazado (desarrollo local)
const memoryVaults = new Map(); // seedHash -> vaultRecord

function json(body, status) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS }
  });
}

/**
 * Con KV enlazado los errores se propagan (fail-closed) en lugar de caer a memoria por-isolate,
 * lo que provocaría respaldos "perdidos" e inconsistentes entre instancias del Worker.
 */
async function getKv(env, key) {
  if (env && env.EVENTS_KV) {
    const raw = await env.EVENTS_KV.get(key);
    return raw ? JSON.parse(raw) : null;
  }
  return memoryVaults.get(key) || null;
}

async function setKv(env, key, value, ttlSeconds = 31536000) { // 1 año por defecto
  if (env && env.EVENTS_KV) {
    await env.EVENTS_KV.put(key, JSON.stringify(value), { expirationTtl: Math.max(120, ttlSeconds) });
    return;
  }
  memoryVaults.set(key, value);
}

function isBoundedString(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= MAX_VAULT_FIELD_LENGTH;
}

/**
 * Manejador principal para /api/chat/vault
 */
export async function onRequest(context) {
  const { request, env } = context;
  const method = request.method.toUpperCase();
  const url = new URL(request.url);

  if (method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  try {
    // 1. GET: Recuperación Zero-Knowledge mediante el Hash SHA-256 de las 12 palabras
    if (method === 'GET') {
      const seedHash = (url.searchParams.get('seedHash') || '').trim().toLowerCase();

      if (!seedHash || !/^[0-9a-f]{64}$/.test(seedHash)) {
        return json({
          success: false,
          error: 'Hash SHA-256 de la semilla mnemónica inválido o ausente'
        }, 400);
      }

      const record = await getKv(env, `vault_${seedHash}`);
      if (!record) {
        return json({
          success: false,
          error: 'No se encontró ninguna bóveda vinculada a esta frase mnemónica'
        }, 404);
      }

      return json({
        success: true,
        fingerprint: record.fingerprint,
        nickname: record.nickname,
        publicSpki: record.publicSpki,
        vault: record.vault,
        updatedAt: record.updatedAt
      }, 200);
    }

    // 2. POST: Respaldo de la Bóveda Cifrada con firma criptográfica obligatoria
    if (method === 'POST') {
      const body = await request.json().catch(() => ({}));
      const { fingerprint, publicSpki, seedHash, vault, nickname, timestamp, signature } = body;

      const cleanFp = String(fingerprint || '').trim().toLowerCase();
      const cleanSeedHash = String(seedHash || '').trim().toLowerCase();

      if (!cleanFp || !publicSpki || !cleanSeedHash || !vault || !vault.ciphertext || !vault.iv) {
        return json({
          success: false,
          error: 'Datos de bóveda incompletos (requiere fingerprint, publicSpki, seedHash, vault)'
        }, 400);
      }

      if (!/^[0-9a-f]{64}$/.test(cleanSeedHash)) {
        return json({ success: false, error: 'Formato de seedHash no es un SHA-256 válido' }, 400);
      }

      if (!isBoundedString(vault.ciphertext) || !isBoundedString(vault.iv) ||
          (vault.salt != null && !isBoundedString(vault.salt))) {
        return json({ success: false, error: 'Campos de bóveda con formato o tamaño inválido' }, 400);
      }

      // 1. Validar que la huella coincida con la clave pública
      let derivedFp;
      try {
        derivedFp = await getFingerprint(publicSpki);
      } catch {
        return json({ success: false, error: 'Clave pública SPKI inválida' }, 400);
      }
      if (derivedFp !== cleanFp) {
        return json({
          success: false,
          error: 'La huella digital no coincide con la clave pública SPKI provista'
        }, 400);
      }

      // 2. Firma criptográfica del propietario (obligatoria) con frescura anti-replay
      if (!signature || typeof timestamp !== 'number') {
        return json({ success: false, error: 'Firma de autorización de respaldo requerida' }, 401);
      }
      if (!Number.isFinite(timestamp) || Math.abs(Date.now() - timestamp) > SIGNATURE_MAX_SKEW_MS) {
        return json({ success: false, error: 'Timestamp de firma expirado' }, 400);
      }

      // La firma cubre el contenido cifrado: impide sustituirlo reutilizando una firma capturada
      const isValid = await verifyPayload(
        publicSpki,
        {
          action: 'backup_vault',
          fingerprint: cleanFp,
          seedHash: cleanSeedHash,
          ciphertext: vault.ciphertext,
          iv: vault.iv,
          timestamp
        },
        signature
      );
      if (!isValid) {
        return json({ success: false, error: 'Firma de autorización de respaldo inválida' }, 401);
      }

      // 3. Una bóveda existente solo puede ser actualizada por su propietario original
      const existing = await getKv(env, `vault_${cleanSeedHash}`);
      if (existing && existing.publicSpki !== publicSpki) {
        return json({
          success: false,
          error: 'Esta bóveda pertenece a otra identidad y no puede ser sobrescrita'
        }, 403);
      }

      const safeNickname = typeof nickname === 'string'
        ? nickname.replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, MAX_NICKNAME_LENGTH)
        : '';

      const vaultRecord = {
        fingerprint: cleanFp,
        nickname: safeNickname || `Usuario#${cleanFp.slice(0, 4)}`,
        publicSpki,
        vault: {
          ciphertext: vault.ciphertext,
          iv: vault.iv,
          salt: vault.salt || null
        },
        updatedAt: Date.now()
      };

      await setKv(env, `vault_${cleanSeedHash}`, vaultRecord);
      await setKv(env, `vault_fp_${cleanFp}`, { seedHash: cleanSeedHash, updatedAt: Date.now() });

      return json({
        success: true,
        message: 'Bóveda cifrada guardada en Cloudflare con éxito (Zero-Knowledge)',
        fingerprint: cleanFp
      }, 201);
    }

    return json({ success: false, error: 'Método no permitido' }, 405);

  } catch (err) {
    console.error('[Vault API] Error interno:', err);
    // No se filtra err.message al cliente
    return json({ success: false, error: 'Error interno del servidor de bóveda' }, 500);
  }
}

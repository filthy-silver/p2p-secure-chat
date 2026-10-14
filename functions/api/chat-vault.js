/**
 * @file functions/api/chat-vault.js
 * @description API de Respaldo y Recuperación de Bóvedas Criptográficas Zero-Knowledge en Cloudflare KV.
 * Permite restaurar identidades autosoberanas mediante la frase de 12 palabras sin que el servidor
 * conozca la clave privada en ningún momento.
 */

import { verifyPayload, getFingerprint } from '../../src/chat/crypto.js';

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization'
};

// Almacenamiento en memoria de respaldo si KV no está enlazado localmente
const memoryVaults = new Map(); // seedHash -> vaultRecord

async function getKv(env, key) {
  if (env && env.EVENTS_KV) {
    try {
      const raw = await env.EVENTS_KV.get(key);
      return raw ? JSON.parse(raw) : null;
    } catch (e) {
      console.warn('[Vault API] Error al leer KV:', e);
    }
  }
  return memoryVaults.get(key) || null;
}

async function setKv(env, key, value, ttlSeconds = 31536000) { // 1 año por defecto
  if (env && env.EVENTS_KV) {
    try {
      await env.EVENTS_KV.put(key, JSON.stringify(value), { expirationTtl: Math.max(120, ttlSeconds) });
      return;
    } catch (e) {
      console.warn('[Vault API] Error al escribir en KV:', e);
    }
  }
  memoryVaults.set(key, value);
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
        return new Response(JSON.stringify({
          success: false,
          error: 'Hash SHA-256 de la semilla mnemónica inválido o ausente'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...CORS_HEADERS }
        });
      }

      const record = await getKv(env, `vault_${seedHash}`);
      if (!record) {
        return new Response(JSON.stringify({
          success: false,
          error: 'No se encontró ninguna bóveda vinculada a esta frase mnemónica'
        }), {
          status: 404,
          headers: { 'Content-Type': 'application/json', ...CORS_HEADERS }
        });
      }

      return new Response(JSON.stringify({
        success: true,
        fingerprint: record.fingerprint,
        nickname: record.nickname,
        publicSpki: record.publicSpki,
        vault: record.vault,
        updatedAt: record.updatedAt
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json', ...CORS_HEADERS }
      });
    }

    // 2. POST: Respaldo de la Bóveda Cifrada con firma criptográfica
    if (method === 'POST') {
      const body = await request.json().catch(() => ({}));
      const { fingerprint, publicSpki, seedHash, vault, nickname, timestamp, signature } = body;

      const cleanFp = String(fingerprint || '').trim().toLowerCase();
      const cleanSeedHash = String(seedHash || '').trim().toLowerCase();

      if (!cleanFp || !publicSpki || !cleanSeedHash || !vault || !vault.ciphertext || !vault.iv) {
        return new Response(JSON.stringify({
          success: false,
          error: 'Datos de bóveda incompletos (requiere fingerprint, publicSpki, seedHash, vault)'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...CORS_HEADERS }
        });
      }

      if (!/^[0-9a-f]{64}$/.test(cleanSeedHash)) {
        return new Response(JSON.stringify({
          success: false,
          error: 'Formato de seedHash no es un SHA-256 válido'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...CORS_HEADERS }
        });
      }

      // 1. Validar que la huella coincida con la clave pública
      const derivedFp = await getFingerprint(publicSpki);
      if (derivedFp !== cleanFp) {
        return new Response(JSON.stringify({
          success: false,
          error: 'La huella digital no coincide con la clave pública SPKI provista'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...CORS_HEADERS }
        });
      }

      // 2. Validar firma criptográfica del propietario (si se proporciona)
      if (signature && timestamp) {
        if (Math.abs(Date.now() - timestamp) > 600000) { // 10 minutos anti-replay
          return new Response(JSON.stringify({ success: false, error: 'Timestamp de firma expirado' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json', ...CORS_HEADERS }
          });
        }

        const isValid = await verifyPayload(
          publicSpki,
          { action: 'backup_vault', fingerprint: cleanFp, seedHash: cleanSeedHash, timestamp },
          signature
        );

        if (!isValid) {
          return new Response(JSON.stringify({ success: false, error: 'Firma de autorización de respaldo inválida' }), {
            status: 401,
            headers: { 'Content-Type': 'application/json', ...CORS_HEADERS }
          });
        }
      }

      const vaultRecord = {
        fingerprint: cleanFp,
        nickname: nickname || `Usuario#${cleanFp.slice(0, 4)}`,
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

      return new Response(JSON.stringify({
        success: true,
        message: 'Bóveda cifrada guardada en Cloudflare con éxito (Zero-Knowledge)',
        fingerprint: cleanFp
      }), {
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
      error: err.message || 'Error interno del servidor de bóveda'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...CORS_HEADERS }
    });
  }
}

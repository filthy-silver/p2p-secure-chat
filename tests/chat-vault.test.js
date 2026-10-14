/**
 * @file tests/chat-vault.test.js
 * @description Pruebas unitarias para la API de Respaldo y Restauración Zero-Knowledge en Cloudflare KV.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { onRequest as handleVaultRequest } from '../functions/api/chat-vault.js';
import {
  generateIdentityKeyPair,
  exportKeyPair,
  importKeyPair,
  getFingerprint,
  bytesToMnemonic,
  computeFileHash,
  signPayload,
  encryptPrivateKeyWithMnemonic,
  decryptPrivateKeyWithMnemonic
} from '../src/chat/crypto.js';

describe('chat-vault.js · Bóveda Criptográfica Zero-Knowledge en Cloudflare', () => {

  function createMockContext(method, urlStr, body = null) {
    const memory = new Map();
    const env = {
      EVENTS_KV: {
        async get(key) {
          return memory.get(key) || null;
        },
        async put(key, value) {
          memory.set(key, value);
        }
      }
    };

    const request = new Request(urlStr, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : null
    });

    return { context: { request, env }, memory };
  }

  it('rechaza peticiones GET con seedHash ausente o no hexadecimal', async () => {
    const { context } = createMockContext('GET', 'http://localhost/api/chat/vault');
    const res = await handleVaultRequest(context);
    const data = await res.json();

    assert.equal(res.status, 400);
    assert.equal(data.success, false);
    assert.match(data.error, /inválido o ausente/i);
  });

  it('devuelve 404 si no existe ninguna bóveda para el seedHash consultado', async () => {
    const fakeHash = 'a'.repeat(64);
    const { context } = createMockContext('GET', `http://localhost/api/chat/vault?seedHash=${fakeHash}`);
    const res = await handleVaultRequest(context);
    const data = await res.json();

    assert.equal(res.status, 404);
    assert.equal(data.success, false);
    assert.match(data.error, /no se encontró ninguna bóveda/i);
  });

  it('rechaza peticiones POST donde la huella no coincide con la clave pública', async () => {
    const keyPair = await generateIdentityKeyPair();
    const { publicSpki } = await exportKeyPair(keyPair);
    const fakeSeedHash = 'b'.repeat(64);

    const { context } = createMockContext('POST', 'http://localhost/api/chat/vault', {
      fingerprint: 'huella_falsa_123',
      publicSpki,
      seedHash: fakeSeedHash,
      vault: { ciphertext: 'test', iv: 'test' }
    });

    const res = await handleVaultRequest(context);
    const data = await res.json();

    assert.equal(res.status, 400);
    assert.equal(data.success, false);
    assert.match(data.error, /no coincide con la clave pública/i);
  });

  it('guarda una bóveda cifrada firmada y la recupera intacta mediante el seedHash (Zero-Knowledge)', async () => {
    const keyPair = await generateIdentityKeyPair();
    const { privateJwk, publicSpki } = await exportKeyPair(keyPair);
    const fingerprint = await getFingerprint(publicSpki);

    const testMnemonic = 'aguila cosmos bosque brisa cedro cielo diamante eco faro fuego galaxia hielo';
    const vault = await encryptPrivateKeyWithMnemonic(privateJwk, testMnemonic);

    const encoder = new TextEncoder();
    const seedHash = await computeFileHash(encoder.encode(testMnemonic.trim().toLowerCase()).buffer);
    const timestamp = Date.now();

    const signature = await signPayload(
      keyPair.privateKey,
      { action: 'backup_vault', fingerprint, seedHash, timestamp }
    );

    const { context: postCtx, memory } = createMockContext('POST', 'http://localhost/api/chat/vault', {
      fingerprint,
      publicSpki,
      seedHash,
      vault,
      nickname: 'Artista3D',
      timestamp,
      signature
    });

    const postRes = await handleVaultRequest(postCtx);
    const postData = await postRes.json();

    assert.equal(postRes.status, 201);
    assert.equal(postData.success, true);
    assert.equal(postData.fingerprint, fingerprint);

    // Recuperar bóveda usando únicamente el seedHash de las 12 palabras
    const sharedEnv = postCtx.env;
    const getReq = new Request(`http://localhost/api/chat/vault?seedHash=${seedHash}`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' }
    });

    const getRes = await handleVaultRequest({ request: getReq, env: sharedEnv });
    const getData = await getRes.json();

    assert.equal(getRes.status, 200);
    assert.equal(getData.success, true);
    assert.equal(getData.fingerprint, fingerprint);
    assert.equal(getData.nickname, 'Artista3D');
    assert.equal(getData.publicSpki, publicSpki);
    assert.ok(getData.vault.ciphertext);

    // El cliente descifra la clave privada JWK recuperada usando sus 12 palabras
    const decryptedJwk = await decryptPrivateKeyWithMnemonic(
      getData.vault.ciphertext,
      getData.vault.iv,
      testMnemonic
    );

    assert.deepEqual(decryptedJwk, privateJwk);

    const restoredKeys = await importKeyPair(decryptedJwk, getData.publicSpki);
    assert.ok(restoredKeys.privateKey);
    assert.ok(restoredKeys.publicKey);
  });

});

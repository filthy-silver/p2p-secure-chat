/**
 * @file tests/chat-invites.test.js
 * @description Pruebas unitarias para el Árbol Genealógico de Invitaciones, control de cupos y revocación en cascada.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { onRequest } from '../functions/api/chat-invites.js';
import {
  generateIdentityKeyPair,
  exportKeyPair,
  getFingerprint,
  signPayload,
  GENESIS_ADMIN_ROOT_FINGERPRINT
} from '../src/chat/crypto.js';

describe('chat-invites.js · Árbol de Invitaciones y Cadena de Confianza', () => {

  // Mock de entorno con KV simulado en memoria
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

  it('asigna cupo inicial de 2 a usuarios regulares y 9999 al administrador', async () => {
    const { context: userCtx } = createMockContext('GET', 'http://localhost/api/chat/invites?fingerprint=user123');
    const userRes = await onRequest(userCtx);
    const userData = await userRes.json();

    assert.equal(userRes.status, 200);
    assert.equal(userData.success, true);
    assert.equal(userData.quota, 2);
    assert.equal(userData.remainingQuota, 2);

    const { context: adminCtx } = createMockContext('GET', 'http://localhost/api/chat/invites?fingerprint=filthysilver_admin');
    const adminRes = await onRequest(adminCtx);
    const adminData = await adminRes.json();

    assert.equal(adminData.quota, 9999);
    assert.equal(adminData.remainingQuota, 9999);
  });

  it('permite crear invitaciones trazables y descuenta el cupo disponible', async () => {
    const { context } = createMockContext('POST', 'http://localhost/api/chat/invites', {
      action: 'create',
      creatorFingerprint: 'carlos_fp',
      creatorLabel: 'Carlos',
      targetLabel: 'Marta'
    });

    const res = await onRequest(context);
    const data = await res.json();

    assert.equal(res.status, 201);
    assert.equal(data.success, true);
    assert.match(data.code, /^INV-[A-Z0-9]{6}$/);
    assert.equal(data.remainingQuota, 1);
  });

  it('rechaza la creación de invitaciones cuando se agota el cupo', async () => {
    const { context: ctx1, memory } = createMockContext('POST', 'http://localhost/api/chat/invites', {
      action: 'create',
      creatorFingerprint: 'pedro_fp',
      creatorLabel: 'Pedro',
      targetLabel: 'Invitado 1'
    });
    const sharedEnv = ctx1.env;

    // Crear primera invitación (restan 1)
    await onRequest({ request: ctx1.request, env: sharedEnv });

    // Crear segunda invitación (restan 0)
    const ctx2Req = new Request('http://localhost/api/chat/invites', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        action: 'create',
        creatorFingerprint: 'pedro_fp',
        creatorLabel: 'Pedro',
        targetLabel: 'Invitado 2'
      })
    });
    await onRequest({ request: ctx2Req, env: sharedEnv });

    // Intentar crear la tercera invitación (debe fallar por cupo agotado)
    const ctx3Req = new Request('http://localhost/api/chat/invites', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        action: 'create',
        creatorFingerprint: 'pedro_fp',
        creatorLabel: 'Pedro',
        targetLabel: 'Invitado 3'
      })
    });
    const res3 = await onRequest({ request: ctx3Req, env: sharedEnv });
    const data3 = await res3.json();

    assert.equal(res3.status, 400);
    assert.equal(data3.success, false);
    assert.match(data3.error, /agotado tu cupo/i);
  });

  it('permite canjear un código y registra la filiación de linaje', async () => {
    const { context: createCtx } = createMockContext('POST', 'http://localhost/api/chat/invites', {
      action: 'create',
      creatorFingerprint: 'sara_fp',
      creatorLabel: 'Sara',
      targetLabel: 'Lucas'
    });
    const sharedEnv = createCtx.env;
    const createRes = await onRequest({ request: createCtx.request, env: sharedEnv });
    const { code } = await createRes.json();

    // Canje por parte de Lucas
    const claimReq = new Request('http://localhost/api/chat/invites', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        action: 'claim',
        code,
        userFingerprint: 'lucas_fp',
        nickname: 'Lucas'
      })
    });
    const claimRes = await onRequest({ request: claimReq, env: sharedEnv });
    const claimData = await claimRes.json();

    assert.equal(claimRes.status, 200);
    assert.equal(claimData.success, true);
    assert.equal(claimData.lineage.invitedBy, 'sara_fp');
    assert.equal(claimData.lineage.invitedByLabel, 'Sara');

    // Intentar segundo canje del mismo código debe fallar
    const doubleClaimRes = await onRequest({ request: claimReq, env: sharedEnv });
    assert.equal(doubleClaimRes.status, 410);
  });

  it('ejecuta la revocación en cascada multi-nivel (A -> B -> C)', async () => {
    const { context: initCtx } = createMockContext('GET', 'http://localhost/api/chat/invites?fingerprint=genesis');
    const sharedEnv = initCtx.env;

    // 1. Usuario A invita a Usuario B
    const createCodeReq1 = new Request('http://localhost/api/chat/invites', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'create', creatorFingerprint: 'user_a', creatorLabel: 'Usuario A', targetLabel: 'Usuario B' })
    });
    const res1 = await onRequest({ request: createCodeReq1, env: sharedEnv });
    const { code: codeAB } = await res1.json();

    const claimBReq = new Request('http://localhost/api/chat/invites', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'claim', code: codeAB, userFingerprint: 'user_b', nickname: 'Usuario B' })
    });
    await onRequest({ request: claimBReq, env: sharedEnv });

    // 2. Usuario B invita a Usuario C
    const createCodeReq2 = new Request('http://localhost/api/chat/invites', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'create', creatorFingerprint: 'user_b', creatorLabel: 'Usuario B', targetLabel: 'Usuario C' })
    });
    const res2 = await onRequest({ request: createCodeReq2, env: sharedEnv });
    const { code: codeBC } = await res2.json();

    const claimCReq = new Request('http://localhost/api/chat/invites', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'claim', code: codeBC, userFingerprint: 'user_c', nickname: 'Usuario C' })
    });
    await onRequest({ request: claimCReq, env: sharedEnv });

    // 3. Ejecutar revocación en cascada sobre Usuario A
    const cascadeReq = new Request('http://localhost/api/chat/invites', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'revoke_cascade', targetFingerprint: 'user_a' })
    });
    const cascadeRes = await onRequest({ request: cascadeReq, env: sharedEnv });
    const cascadeData = await cascadeRes.json();

    assert.equal(cascadeRes.status, 200);
    assert.equal(cascadeData.success, true);
    // Tanto B como C deben estar en los afectados suspendidos
    assert.ok(cascadeData.affectedUsers.includes('user_b'));
    assert.ok(cascadeData.affectedUsers.includes('user_c'));
  });

  it('valida la firma digital ECDSA en la creación de invitaciones (Anti-Spoofing)', async () => {
    const creatorKey = await generateIdentityKeyPair();
    const { publicSpki } = await exportKeyPair(creatorKey);
    const creatorFp = await getFingerprint(publicSpki);

    const timestamp = Date.now();
    const signature = await signPayload(
      creatorKey.privateKey,
      { action: 'create', creatorFingerprint: creatorFp, targetLabel: 'Alumno Nuevo', timestamp }
    );

    const { context } = createMockContext('POST', 'http://localhost/api/chat/invites', {
      action: 'create',
      creatorFingerprint: creatorFp,
      creatorPublicSpki: publicSpki,
      creatorLabel: 'Profesor',
      targetLabel: 'Alumno Nuevo',
      timestamp,
      signature
    });

    const res = await onRequest(context);
    const data = await res.json();

    assert.equal(res.status, 201);
    assert.equal(data.success, true);
    assert.match(data.code, /^INV-[A-Z0-9]{6}$/);
    assert.equal(data.remainingQuota, 1);
  });

  it('rechaza la creación de invitaciones si la huella no coincide con la clave pública SPKI', async () => {
    const creatorKey = await generateIdentityKeyPair();
    const { publicSpki } = await exportKeyPair(creatorKey);

    const timestamp = Date.now();
    const signature = await signPayload(
      creatorKey.privateKey,
      { action: 'create', creatorFingerprint: 'victima_falsa', targetLabel: 'Alumno', timestamp }
    );

    const { context } = createMockContext('POST', 'http://localhost/api/chat/invites', {
      action: 'create',
      creatorFingerprint: 'victima_falsa',
      creatorPublicSpki: publicSpki,
      creatorLabel: 'Atacante',
      targetLabel: 'Alumno',
      timestamp,
      signature
    });

    const res = await onRequest(context);
    const data = await res.json();

    assert.equal(res.status, 401);
    assert.equal(data.success, false);
    assert.match(data.error, /no coincide con la clave pública/i);
  });

  it('rechaza la revocación en cascada de atacantes no autorizados y la aprueba con adminSecret', async () => {
    const { context: unauthCtx } = createMockContext('POST', 'http://localhost/api/chat/invites', {
      action: 'revoke_cascade',
      targetFingerprint: 'usuario_inocente',
      adminSecret: 'clave_invalida_123'
    });

    const unauthRes = await onRequest(unauthCtx);
    assert.equal(unauthRes.status, 403);

    const { context: authCtx } = createMockContext('POST', 'http://localhost/api/chat/invites', {
      action: 'revoke_cascade',
      targetFingerprint: 'usuario_infractor',
      adminSecret: 'filthysilver3d'
    });

    const authRes = await onRequest(authCtx);
    const authData = await authRes.json();
    assert.equal(authRes.status, 200);
    assert.equal(authData.success, true);
  });

});

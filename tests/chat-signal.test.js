/**
 * @file tests/chat-signal.test.js
 * @description Pruebas unitarias para la señalización P2P (/api/chat/signal) y la verificación
 * criptográfica del Muro de Acceso (Zero-Trust).
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { onRequest, verifyPeerSignalAccess } from '../functions/api/chat-signal.js';
import {
  generateIdentityKeyPair,
  exportKeyPair,
  getFingerprint,
  signPayload,
  generateInviteToken,
  GENESIS_ADMIN_ROOT_FINGERPRINT
} from '../src/chat/crypto.js';

describe('chat-signal.js · Señalización WebRTC y Muro de Acceso Server-Side', () => {

  function createMockEnv(extraKv = {}, extraEnv = {}) {
    const memory = new Map(Object.entries(extraKv));
    return {
      EVENTS_KV: {
        async get(key) { return memory.get(key) || null; },
        async put(key, value) { memory.set(key, value); }
      },
      ...extraEnv
    };
  }

  describe('verifyPeerSignalAccess()', () => {
    it('permite el acceso al Administrador Raiz Genesis (8c196b38)', async () => {
      const env = createMockEnv();
      const res = await verifyPeerSignalAccess(env, GENESIS_ADMIN_ROOT_FINGERPRINT);
      assert.equal(res.ok, true);
      assert.equal(res.role, 'root');
    });

    it('permite el acceso a miembros registrados en KV no suspendidos', async () => {
      const env = createMockEnv({
        'user_meta_a1b2c3d4': JSON.stringify({ fingerprint: 'a1b2c3d4', banned: false })
      });
      const res = await verifyPeerSignalAccess(env, 'a1b2c3d4');
      assert.equal(res.ok, true);
      assert.equal(res.role, 'member');
    });

    it('rechaza con error a usuarios suspendidos o baneados en KV', async () => {
      const env = createMockEnv({
        'user_meta_deadbeef': JSON.stringify({ fingerprint: 'deadbeef', banned: true })
      });
      const res = await verifyPeerSignalAccess(env, 'deadbeef');
      assert.equal(res.ok, false);
      assert.match(res.error, /revocada o suspendida/i);
    });

    it('permite el acceso con un token de invitacion valido y firmado', async () => {
      const adminKp = await generateIdentityKeyPair();
      const adminExported = await exportKeyPair(adminKp);
      const adminFp = await getFingerprint(adminExported.publicSpki);

      const token = await generateInviteToken(
        adminKp.privateKey,
        adminExported.publicSpki,
        adminFp,
        'alumno_invitado',
        24
      );

      const env = createMockEnv({}, { ADMIN_FINGERPRINT: adminFp });
      const res = await verifyPeerSignalAccess(env, 'guest_peer_123', token);
      assert.equal(res.ok, true);
      assert.equal(res.role, 'invited');
    });

    it('bloquea a usuarios sin invitacion ni registro previo si KV esta activo', async () => {
      const env = createMockEnv();
      const res = await verifyPeerSignalAccess(env, 'random99');
      assert.equal(res.ok, false);
      assert.match(res.error, /invitaci[oó]n/i);
    });

    it('permite el acceso en entorno local de desarrollo cuando EVENTS_KV es undefined', async () => {
      const env = {};
      const res = await verifyPeerSignalAccess(env, 'dev_peer');
      assert.equal(res.ok, true);
      assert.equal(res.role, 'local_dev');
    });
  });

  describe('onRequest() · Endpoints HTTP de Señalizacion', () => {
    it('responde 204 con cabeceras CORS ante peticiones OPTIONS', async () => {
      const req = new Request('http://localhost/api/chat/signal', { method: 'OPTIONS' });
      const res = await onRequest({ request: req, env: {} });
      assert.equal(res.status, 204);
      assert.equal(res.headers.get('Access-Control-Allow-Origin'), '*');
    });

    it('rechaza con 403 en GET si el usuario no esta autorizado en el muro', async () => {
      const env = createMockEnv();
      const req = new Request('http://localhost/api/chat/signal?roomId=general&peerId=intruso1', {
        method: 'GET'
      });
      const res = await onRequest({ request: req, env });
      assert.equal(res.status, 403);
      const data = await res.json();
      assert.equal(data.success, false);
    });

    it('permite GET a un usuario autorizado y devuelve lista de senales', async () => {
      const env = createMockEnv({
        'user_meta_alumno01': JSON.stringify({ fingerprint: 'alumno01', banned: false })
      });
      const req = new Request('http://localhost/api/chat/signal?roomId=general&peerId=alumno01', {
        method: 'GET'
      });
      const res = await onRequest({ request: req, env });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.success, true);
      assert.ok(Array.isArray(data.signals));
    });

    it('rechaza con 403 en POST si se intenta suplantar el remitente (signal.from !== peerId)', async () => {
      const env = createMockEnv({
        'user_meta_alumno01': JSON.stringify({ fingerprint: 'alumno01', banned: false })
      });
      const req = new Request('http://localhost/api/chat/signal?roomId=general&peerId=alumno01', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          signal: {
            type: 'ANNOUNCE_PRESENCE',
            from: 'victima02'
          }
        })
      });
      const res = await onRequest({ request: req, env });
      assert.equal(res.status, 403);
      const data = await res.json();
      assert.equal(data.success, false);
      assert.match(data.error, /identidad/i);
    });

    it('acepta una senal POST valida y la entrega en GET a otros companeros', async () => {
      const env = createMockEnv({
        'user_meta_peer_a': JSON.stringify({ fingerprint: 'peer_a', banned: false }),
        'user_meta_peer_b': JSON.stringify({ fingerprint: 'peer_b', banned: false })
      });

      // Peer A envia senal
      const postReq = new Request('http://localhost/api/chat/signal?roomId=general&peerId=peer_a', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          signal: {
            type: 'ANNOUNCE_PRESENCE',
            from: 'peer_a'
          }
        })
      });
      const postRes = await onRequest({ request: postReq, env });
      assert.equal(postRes.status, 201);

      // Peer A consulta senales (no debe ver la suya propia)
      const getReqA = new Request('http://localhost/api/chat/signal?roomId=general&peerId=peer_a', {
        method: 'GET'
      });
      const getResA = await onRequest({ request: getReqA, env });
      const dataA = await getResA.json();
      assert.equal(dataA.signals.some(s => s.from === 'peer_a'), false);

      // Peer B consulta senales (debe recibir la senal de Peer A)
      const getReqB = new Request('http://localhost/api/chat/signal?roomId=general&peerId=peer_b', {
        method: 'GET'
      });
      const getResB = await onRequest({ request: getReqB, env });
      const dataB = await getResB.json();
      assert.equal(dataB.signals.some(s => s.from === 'peer_a'), true);
    });

    it('devuelve 405 ante metodos HTTP no soportados', async () => {
      const env = createMockEnv({
        'user_meta_alumno01': JSON.stringify({ fingerprint: 'alumno01', banned: false })
      });
      const req = new Request('http://localhost/api/chat/signal?roomId=general&peerId=alumno01', {
        method: 'DELETE'
      });
      const res = await onRequest({ request: req, env });
      assert.equal(res.status, 405);
    });
  });

});

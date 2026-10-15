/**
 * @file tests/chat-messages.test.js
 * @description Pruebas unitarias para la API de Búfer Efímero de Mensajes con TTL en Cloudflare KV.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { onRequest as handleMessagesRequest } from '../functions/api/chat-messages.js';
import {
  generateIdentityKeyPair,
  exportKeyPair,
  signPayload
} from '../src/chat/crypto.js';

describe('chat-messages.js · Búfer Efímero de Mensajes con TTL', () => {

  function createMockContext(method, urlStr, body = null, initialKv = new Map()) {
    const memory = initialKv;
    const kvPuts = [];
    const env = {
      EVENTS_KV: {
        async get(key) {
          return memory.get(key) || null;
        },
        async put(key, value, options) {
          memory.set(key, value);
          kvPuts.push({ key, value, options });
        }
      }
    };

    const request = new Request(urlStr, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : null
    });

    return { context: { request, env }, memory, kvPuts };
  }

  it('devuelve lista vacía en GET si la sala no tiene mensajes y el usuario está autorizado', async () => {
    const { context } = createMockContext('GET', 'http://localhost/api/chat/messages?roomId=general&peerId=8c196b38');
    const res = await handleMessagesRequest(context);
    const data = await res.json();

    assert.equal(res.status, 200);
    assert.equal(data.success, true);
    assert.equal(data.roomId, 'general');
    assert.equal(data.count, 0);
    assert.deepEqual(data.messages, []);
  });

  it('rechaza con 403 a usuarios no autorizados que intenten leer mensajes en GET', async () => {
    const { context } = createMockContext('GET', 'http://localhost/api/chat/messages?roomId=general&peerId=unauthorized');
    const res = await handleMessagesRequest(context);
    const data = await res.json();

    assert.equal(res.status, 403);
    assert.equal(data.success, false);
    assert.match(data.error, /no autorizada/i);
  });

  it('rechaza con 403 a usuarios suspendidos o baneados', async () => {
    const memory = new Map([
      ['user_meta_banned01', JSON.stringify({ fingerprint: 'banned01', banned: true })]
    ]);
    const { context: ctxGet } = createMockContext('GET', 'http://localhost/api/chat/messages?roomId=general&peerId=banned01', null, memory);
    const resGet = await handleMessagesRequest(ctxGet);
    assert.equal(resGet.status, 403);

    const { context: ctxPost } = createMockContext('POST', 'http://localhost/api/chat/messages', {
      roomId: 'general',
      retentionHours: 24,
      message: { id: 'msg-banned', text: 'Spam', senderPeerId: 'banned01' }
    }, memory);
    const resPost = await handleMessagesRequest(ctxPost);
    assert.equal(resPost.status, 403);
  });

  it('rechaza métodos no soportados con 405', async () => {
    const { context } = createMockContext('DELETE', 'http://localhost/api/chat/messages');
    const res = await handleMessagesRequest(context);
    assert.equal(res.status, 405);
  });

  it('en modo 0 horas (solo en vivo) no persiste nada en KV', async () => {
    const { context, kvPuts } = createMockContext('POST', 'http://localhost/api/chat/messages', {
      roomId: 'general',
      retentionHours: 0,
      message: { id: 'msg-live-1', text: 'Solo en vivo' }
    });

    const res = await handleMessagesRequest(context);
    const data = await res.json();

    assert.equal(res.status, 200);
    assert.equal(data.success, true);
    assert.equal(data.ephemeral, true);
    assert.equal(kvPuts.length, 0);
  });

  it('rechaza mensajes sin id o con estructura inválida', async () => {
    const { context } = createMockContext('POST', 'http://localhost/api/chat/messages', {
      roomId: 'general',
      retentionHours: 24,
      message: null
    });

    const res = await handleMessagesRequest(context);
    const data = await res.json();

    assert.equal(res.status, 400);
    assert.match(data.error, /no válida/i);
  });

  it('rechaza mensajes que excedan la longitud máxima de texto', async () => {
    const longText = 'x'.repeat(4001);
    const memory = new Map([
      ['user_meta_sender01', JSON.stringify({ fingerprint: 'sender01', banned: false })]
    ]);
    const { context } = createMockContext('POST', 'http://localhost/api/chat/messages', {
      roomId: 'general',
      retentionHours: 24,
      message: { id: 'msg-too-long', text: longText, senderPeerId: 'sender01' }
    }, memory);

    const res = await handleMessagesRequest(context);
    const data = await res.json();

    assert.equal(res.status, 400);
    assert.match(data.error, /excede la longitud/i);
  });

  it('rechaza mensajes con firma digital manipulada o inválida (Anti-Spoofing)', async () => {
    const keys = await generateIdentityKeyPair();
    const exported = await exportKeyPair(keys);

    const message = {
      id: 'msg-spoof',
      senderPeerId: '12345678',
      text: 'Texto legítimo',
      timestamp: Date.now(),
      publicSpki: exported.publicSpki,
      signature: 'aabbccdd_invalid_signature'
    };

    const memory = new Map([
      ['user_meta_12345678', JSON.stringify({ fingerprint: '12345678', banned: false })]
    ]);

    const { context } = createMockContext('POST', 'http://localhost/api/chat/messages', {
      roomId: 'general',
      retentionHours: 24,
      message
    }, memory);

    const res = await handleMessagesRequest(context);
    const data = await res.json();

    assert.equal(res.status, 403);
    assert.match(data.error, /Firma digital de mensaje no válida/i);
  });

  it('guarda exitosamente un mensaje firmado y aplica TTL en KV', async () => {
    const keys = await generateIdentityKeyPair();
    const exported = await exportKeyPair(keys);

    const rawMsg = {
      id: 'msg-valid-1',
      senderPeerId: '87654321',
      senderNickname: 'Alumno3D',
      text: 'Descarga Blender 4.3 lista en Torbox',
      timestamp: Date.now(),
      publicSpki: exported.publicSpki
    };

    const signature = await signPayload(keys.privateKey, rawMsg);
    const message = { ...rawMsg, signature };

    const initialMemory = new Map([
      ['user_meta_87654321', JSON.stringify({ fingerprint: '87654321', banned: false })]
    ]);

    const { context, kvPuts, memory } = createMockContext('POST', 'http://localhost/api/chat/messages', {
      roomId: 'torbox-ddl',
      retentionHours: 24,
      message
    }, initialMemory);

    const res = await handleMessagesRequest(context);
    const data = await res.json();

    assert.equal(res.status, 200);
    assert.equal(data.success, true);
    assert.equal(data.roomId, 'torbox-ddl');
    assert.equal(data.messageId, 'msg-valid-1');
    assert.equal(data.ttlSeconds, 24 * 3600);

    assert.equal(kvPuts.length, 1);
    assert.equal(kvPuts[0].key, 'room_buffer:torbox-ddl');
    assert.equal(kvPuts[0].options.expirationTtl, 24 * 3600);

    // Comprobar recuperación por GET con peerId autorizado
    const { context: getCtx } = createMockContext('GET', 'http://localhost/api/chat/messages?roomId=torbox-ddl&peerId=87654321', null, memory);
    const getRes = await handleMessagesRequest(getCtx);
    const getData = await getRes.json();

    assert.equal(getData.success, true);
    assert.equal(getData.count, 1);
    assert.equal(getData.messages[0].id, 'msg-valid-1');
    assert.equal(getData.messages[0].text, 'Descarga Blender 4.3 lista en Torbox');
  });

  it('acota la retención entre 1 y 72 horas para prevenir abusos', async () => {
    const memory = new Map([
      ['user_meta_clampuser', JSON.stringify({ fingerprint: 'clampuser', banned: false })]
    ]);
    const { context: ctxHigh, kvPuts: putsHigh } = createMockContext('POST', 'http://localhost/api/chat/messages', {
      roomId: 'general',
      retentionHours: 9999, // Excede 72
      message: { id: 'msg-clamp-high', text: 'Prueba clamp', senderPeerId: 'clampuser' }
    }, memory);
    const resHigh = await handleMessagesRequest(ctxHigh);
    const dataHigh = await resHigh.json();
    assert.equal(dataHigh.ttlSeconds, 72 * 3600);
    assert.equal(putsHigh[0].options.expirationTtl, 72 * 3600);

    const { context: ctxLow, kvPuts: putsLow } = createMockContext('POST', 'http://localhost/api/chat/messages', {
      roomId: 'general',
      retentionHours: 0.2, // Menor que 1
      message: { id: 'msg-clamp-low', text: 'Prueba clamp low', senderPeerId: 'clampuser' }
    }, memory);
    const resLow = await handleMessagesRequest(ctxLow);
    const dataLow = await resLow.json();
    assert.equal(dataLow.ttlSeconds, 1 * 3600);
    assert.equal(putsLow[0].options.expirationTtl, 1 * 3600);
  });

  it('funciona con respaldo en memoria si env.EVENTS_KV es undefined', async () => {
    const memoryCtx = {
      request: new Request('http://localhost/api/chat/messages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          roomId: 'mem-room',
          retentionHours: 6,
          message: { id: 'msg-mem-1', text: 'Mensaje en memoria' }
        })
      }),
      env: {}
    };

    const res = await handleMessagesRequest(memoryCtx);
    const data = await res.json();
    assert.equal(res.status, 200);
    assert.equal(data.success, true);

    const getRes = await handleMessagesRequest({
      request: new Request('http://localhost/api/chat/messages?roomId=mem-room'),
      env: {}
    });
    const getData = await getRes.json();
    assert.equal(getData.count >= 1, true);
    assert.equal(getData.messages[0].id, 'msg-mem-1');
  });

});

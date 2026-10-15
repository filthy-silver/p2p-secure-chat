/**
 * @file tests/chat-p2p.test.js
 * @description Pruebas unitarias para utilidades, sanitización, contrapresión y ciclo de vida de P2PMeshRoom.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  sanitizeFileName,
  sanitizeNickname,
  isFreshTimestamp,
  isValidPeerId,
  FILE_CHUNK_SIZE,
  DEFAULT_ICE_SERVERS,
  P2PMeshRoom
} from '../src/chat/p2p.js';
import {
  generateIdentityKeyPair,
  exportKeyPair,
  getFingerprint,
  signPayload,
  generateInviteToken,
  GENESIS_ADMIN_ROOT_FINGERPRINT
} from '../src/chat/crypto.js';

describe('chat/p2p.js · Seguridad, Sanitización y Utilidades WebRTC', () => {

  describe('sanitizeFileName()', () => {
    it('elimina caracteres peligrosos del sistema de archivos y traversal (../)', () => {
      assert.equal(sanitizeFileName('../../../etc/passwd'), 'etc_passwd');
      assert.equal(sanitizeFileName('c:\\windows\\system32\\cmd.exe'), 'c__windows_system32_cmd.exe');
      assert.equal(sanitizeFileName('modelo<3D>?*:|archivo.obj'), 'modelo_3D_____archivo.obj');
    });

    it('devuelve "archivo" ante entradas nulas, vacías o caracteres de control', () => {
      assert.equal(sanitizeFileName(''), 'archivo');
      assert.equal(sanitizeFileName(null), 'archivo');
      assert.equal(sanitizeFileName(undefined), 'archivo');
      assert.equal(sanitizeFileName('\x00\x1f\x7f'), 'archivo');
    });

    it('acota la longitud máxima a 120 caracteres', () => {
      const longName = 'a'.repeat(200) + '.blend';
      const cleaned = sanitizeFileName(longName);
      assert.ok(cleaned.length <= 120);
    });
  });

  describe('sanitizeNickname()', () => {
    it('elimina caracteres de control y recorta espacios', () => {
      assert.equal(sanitizeNickname('  Artista3D \x00\x1b '), 'Artista3D');
      assert.equal(sanitizeNickname(null), '');
      assert.equal(sanitizeNickname(undefined), '');
      assert.equal(sanitizeNickname(123), '');
    });

    it('limita la longitud a 32 caracteres', () => {
      const longNick = 'UsuarioMuyLargoConMuchosCaracteresParaChat';
      assert.ok(sanitizeNickname(longNick).length <= 32);
    });
  });

  describe('isFreshTimestamp()', () => {
    it('valida timestamps dentro de la ventana de tiempo permitida', () => {
      const now = Date.now();
      assert.equal(isFreshTimestamp(now, 5000), true);
      assert.equal(isFreshTimestamp(now - 4000, 5000), true);
      assert.equal(isFreshTimestamp(now + 4000, 5000), true);
    });

    it('rechaza timestamps fuera de la ventana o no numéricos', () => {
      const now = Date.now();
      assert.equal(isFreshTimestamp(now - 10000, 5000), false);
      assert.equal(isFreshTimestamp('123456', 5000), false);
      assert.equal(isFreshTimestamp(NaN, 5000), false);
      assert.equal(isFreshTimestamp(Infinity, 5000), false);
    });
  });

  describe('isValidPeerId()', () => {
    it('acepta huellas hexadecimales válidas de 8 caracteres', () => {
      assert.equal(isValidPeerId('8f3b2a9c'), true);
      assert.equal(isValidPeerId('00000000'), true);
      assert.equal(isValidPeerId('deadbeef'), true);
    });

    it('rechaza huellas inválidas, demasiado largas, cortas o no hex', () => {
      assert.equal(isValidPeerId('8f3b2a9'), false);
      assert.equal(isValidPeerId('8f3b2a9c0'), false);
      assert.equal(isValidPeerId('8f3b2a9z'), false);
      assert.equal(isValidPeerId(''), false);
      assert.equal(isValidPeerId(null), false);
    });
  });

  describe('FILE_CHUNK_SIZE', () => {
    it('está fijado en 16 KB (16384 bytes)', () => {
      assert.equal(FILE_CHUNK_SIZE, 16384);
    });
  });

  describe('DEFAULT_ICE_SERVERS · Resiliencia STUN y TURN para Centros Educativos', () => {
    it('incluye servidores STUN de alta disponibilidad (Cloudflare, Google, Mozilla)', () => {
      assert.ok(Array.isArray(DEFAULT_ICE_SERVERS));
      assert.ok(DEFAULT_ICE_SERVERS.length >= 2);
      const stunUrls = DEFAULT_ICE_SERVERS.map(s => s.urls).flat();
      assert.ok(stunUrls.some(u => u.includes('stun.cloudflare.com')));
      assert.ok(stunUrls.some(u => u.includes('stun.l.google.com')));
    });

    it('incorpora servidores TURN y TURNS comunitarios para superar NAT simetrico y firewalls escolares', () => {
      const turnEntry = DEFAULT_ICE_SERVERS.find(s => s.username && s.credential);
      assert.ok(turnEntry, 'Debe existir configuracion de servidor TURN con credenciales');
      assert.ok(Array.isArray(turnEntry.urls));
      assert.ok(turnEntry.urls.some(u => u.startsWith('turn:')));
      assert.ok(turnEntry.urls.some(u => u.startsWith('turns:') && u.includes('transport=tcp')));
    });

    it('P2PMeshRoom admite iceServers personalizados o aplica los servidores por defecto', () => {
      const customServers = [{ urls: 'stun:custom.stun.org:3478' }];
      const roomCustom = Object.create(P2PMeshRoom.prototype);
      roomCustom.iceServers = (Array.isArray(customServers) && customServers.length > 0)
        ? customServers
        : DEFAULT_ICE_SERVERS;
      assert.equal(roomCustom.iceServers, customServers);

      const roomDefault = Object.create(P2PMeshRoom.prototype);
      roomDefault.iceServers = (Array.isArray(null) && null.length > 0)
        ? null
        : DEFAULT_ICE_SERVERS;
      assert.equal(roomDefault.iceServers, DEFAULT_ICE_SERVERS);
    });
  });

  describe('P2PMeshRoom · Control de Contrapresión (_waitForBackpressure)', () => {
    it('devuelve inmediatamente true si bufferedAmount está por debajo del umbral', async () => {
      const room = Object.create(P2PMeshRoom.prototype);
      const mockChannel = {
        readyState: 'open',
        bufferedAmount: 1024,
        addEventListener: () => {},
        removeEventListener: () => {}
      };

      const result = await room._waitForBackpressure(mockChannel);
      assert.equal(result, true);
    });

    it('devuelve false inmediatamente si el canal no está abierto', async () => {
      const room = Object.create(P2PMeshRoom.prototype);
      const mockChannel = {
        readyState: 'closed',
        bufferedAmount: 1000000,
        addEventListener: () => {},
        removeEventListener: () => {}
      };

      const result = await room._waitForBackpressure(mockChannel);
      assert.equal(result, false);
    });

    it('espera a bufferedamountlow cuando el búfer supera el umbral y resuelve true', async () => {
      const room = Object.create(P2PMeshRoom.prototype);
      let listener = null;
      const mockChannel = {
        readyState: 'open',
        bufferedAmount: 300000, // > 256 KB
        bufferedAmountLowThreshold: 0,
        addEventListener(evt, fn) {
          if (evt === 'bufferedamountlow') listener = fn;
        },
        removeEventListener() {}
      };

      const promise = room._waitForBackpressure(mockChannel);
      assert.equal(mockChannel.bufferedAmountLowThreshold, 64 * 1024);

      // Simular que el búfer baja
      mockChannel.bufferedAmount = 32 * 1024;
      listener?.();

      const result = await promise;
      assert.equal(result, true);
    });
  });

  describe('P2PMeshRoom · Ciclo de Vida y destroy() Idempotente', () => {
    it('destroy() cierra canales, cancela temporizadores y limpia colecciones', () => {
      const room = Object.create(P2PMeshRoom.prototype);
      room.isDestroyed = false;
      room._transferCleanupInterval = 123;
      room._readyTimer = 456;
      room._cloudflareReconnectTimer = 789;
      room._nostrReconnectTimers = new Map([['relay1', 111]]);
      room.incomingFileTransfers = new Map([['f1', { receivedChunks: new Map() }]]);
      room.peers = new Map();
      room.peerMessageTimestamps = new Map([['p1', [1]]]);
      room.peerControlTimestamps = new Map([['p1', [1]]]);
      room.pendingIceCandidates = new Map([['p1', []]]);
      room.seenMessageIds = new Set(['m1']);
      room.nostrSockets = [];

      let bcClosed = false;
      room.broadcastChannel = {
        onmessage: () => {},
        close() { bcClosed = true; }
      };

      room.destroy();

      assert.equal(room.isDestroyed, true);
      assert.equal(bcClosed, true);
      assert.equal(room._nostrReconnectTimers.size, 0);
      assert.equal(room.incomingFileTransfers.size, 0);
      assert.equal(room.peers.size, 0);
      assert.equal(room.peerMessageTimestamps.size, 0);
      assert.equal(room.peerControlTimestamps.size, 0);
      assert.equal(room.seenMessageIds.size, 0);

      // Segunda llamada a destroy() no debe fallar ni causar errores (idempotencia)
      assert.doesNotThrow(() => {
        room.destroy();
      });
    });
  });

  describe('P2PMeshRoom · Blindaje Zero-Trust en Handshake (_processHandshake)', () => {
    it('cierra canales y desconecta inmediatamente a companeros sin token de invitacion', async () => {
      const room = Object.create(P2PMeshRoom.prototype);
      room.roomId = 'general';
      room.peerId = 'local123';
      room.enforceCommunityGate = true;
      room.trustedAdminFingerprints = [GENESIS_ADMIN_ROOT_FINGERPRINT];
      let disconnectedPeer = null;
      room._handlePeerDisconnected = (id) => { disconnectedPeer = id; };

      const guestKp = await generateIdentityKeyPair();
      const guestExp = await exportKeyPair(guestKp);
      const guestFp = await getFingerprint(guestExp.publicSpki);

      let dcClosed = false;
      let pcClosed = false;
      const peerObj = {
        profile: { id: guestFp },
        dataChannel: { close() { dcClosed = true; } },
        peerConnection: { close() { pcClosed = true; } }
      };

      const timestamp = Date.now();
      const signature = await signPayload(
        guestKp.privateKey,
        { type: 'HELLO_HANDSHAKE', roomId: 'general', from: guestFp, to: 'local123', timestamp }
      );

      await room._processHandshake({
        publicSpki: guestExp.publicSpki,
        timestamp,
        signature
        // Sin token de comunidad
      }, guestFp, peerObj);

      assert.equal(dcClosed, true);
      assert.equal(pcClosed, true);
      assert.equal(disconnectedPeer, guestFp);
    });

    it('acepta y mantiene conectado a un companero con token de invitacion valido', async () => {
      const room = Object.create(P2PMeshRoom.prototype);
      room.roomId = 'general';
      room.peerId = 'local123';
      room.enforceCommunityGate = true;

      const adminKp = await generateIdentityKeyPair();
      const adminExp = await exportKeyPair(adminKp);
      const adminFp = await getFingerprint(adminExp.publicSpki);
      room.trustedAdminFingerprints = [adminFp];

      let disconnectedPeer = null;
      room._handlePeerDisconnected = (id) => { disconnectedPeer = id; };

      const guestKp = await generateIdentityKeyPair();
      const guestExp = await exportKeyPair(guestKp);
      const guestFp = await getFingerprint(guestExp.publicSpki);

      const token = await generateInviteToken(
        adminKp.privateKey,
        adminExp.publicSpki,
        adminFp,
        'alumno_verificado',
        24
      );

      let dcClosed = false;
      const peerObj = {
        profile: { id: guestFp },
        dataChannel: { close() { dcClosed = true; } },
        peerConnection: { close() { } }
      };

      const timestamp = Date.now();
      const signature = await signPayload(
        guestKp.privateKey,
        { type: 'HELLO_HANDSHAKE', roomId: 'general', from: guestFp, to: 'local123', timestamp }
      );

      await room._processHandshake({
        publicSpki: guestExp.publicSpki,
        timestamp,
        signature,
        communityToken: token
      }, guestFp, peerObj);

      assert.equal(dcClosed, false);
      assert.equal(disconnectedPeer, null);
      assert.equal(peerObj.profile.communityToken, token);
    });
  });

});

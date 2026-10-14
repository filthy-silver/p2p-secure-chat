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
  P2PMeshRoom
} from '../src/chat/p2p.js';

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

});

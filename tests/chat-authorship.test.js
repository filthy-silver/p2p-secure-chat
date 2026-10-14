/**
 * @file tests/chat-authorship.test.js
 * @description Pruebas unitarias para el cómputo de Hash SHA-256 y Certificados de Autoría (Proof of Authorship).
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  generateIdentityKeyPair,
  exportKeyPair,
  getFingerprint,
  computeFileHash,
  createFileAuthorshipCertificate,
  verifyFileAuthorshipCertificate
} from '../src/chat/crypto.js';

describe('chat/crypto.js · Certificado Criptográfico de Autoría (Proof of Authorship)', () => {

  it('calcula correctamente el Hash SHA-256 de un ArrayBuffer binario', async () => {
    const encoder = new TextEncoder();
    const data = encoder.encode('Escena_Blender_3D_Animacion_V1');
    const hash = await computeFileHash(data.buffer);

    assert.equal(typeof hash, 'string');
    assert.equal(hash.length, 64);
    assert.match(hash, /^[0-9a-f]{64}$/);
  });

  it('genera un Certificado de Autoría firmado y lo valida exitosamente', async () => {
    const authorKeyPair = await generateIdentityKeyPair();
    const { publicSpki } = await exportKeyPair(authorKeyPair);
    const authorFp = await getFingerprint(publicSpki);

    const encoder = new TextEncoder();
    const mockFileBuffer = encoder.encode('Contenido del modelo 3D en formato GLTF');
    const fileHash = await computeFileHash(mockFileBuffer.buffer);

    const certificate = await createFileAuthorshipCertificate(
      fileHash,
      'personaje_guerrero.glb',
      mockFileBuffer.byteLength,
      authorKeyPair.privateKey,
      publicSpki,
      'Carlos#8f3b'
    );

    assert.ok(certificate.certificatePayload);
    assert.ok(certificate.signature);
    assert.equal(certificate.certificatePayload.fileHash, fileHash);

    const verifyResult = await verifyFileAuthorshipCertificate(certificate, fileHash);
    assert.equal(verifyResult.valid, true);
    assert.equal(verifyResult.authorNickname, 'Carlos#8f3b');
    assert.equal(verifyResult.fileHash, fileHash);
  });

  it('rechaza el Certificado de Autoría si el archivo fue modificado o sustituido', async () => {
    const authorKeyPair = await generateIdentityKeyPair();
    const { publicSpki } = await exportKeyPair(authorKeyPair);

    const originalBuffer = new TextEncoder().encode('Archivo original 100% mio');
    const originalHash = await computeFileHash(originalBuffer.buffer);

    const certificate = await createFileAuthorshipCertificate(
      originalHash,
      'textura_original.png',
      originalBuffer.byteLength,
      authorKeyPair.privateKey,
      publicSpki,
      'Sara#4e21'
    );

    // Intentamos validar contra un archivo falso/manipulado
    const tamperedBuffer = new TextEncoder().encode('Archivo modificado por un tercero');
    const tamperedHash = await computeFileHash(tamperedBuffer.buffer);

    const verifyResult = await verifyFileAuthorshipCertificate(certificate, tamperedHash);
    assert.equal(verifyResult.valid, false);
    assert.match(verifyResult.error, /no coincide/i);
  });

  it('rechaza el certificado si la firma digital fue alterada', async () => {
    const authorKeyPair = await generateIdentityKeyPair();
    const { publicSpki } = await exportKeyPair(authorKeyPair);

    const buffer = new TextEncoder().encode('Render Final Iluminacion');
    const fileHash = await computeFileHash(buffer.buffer);

    const certificate = await createFileAuthorshipCertificate(
      fileHash,
      'render_final.exr',
      buffer.byteLength,
      authorKeyPair.privateKey,
      publicSpki,
      'Lucas#9f8a'
    );

    // Alterar firma
    certificate.signature = certificate.signature.slice(0, -4) + 'AAAA';

    const verifyResult = await verifyFileAuthorshipCertificate(certificate, fileHash);
    assert.equal(verifyResult.valid, false);
    assert.match(verifyResult.error, /inválida o alterada/i);
  });

});

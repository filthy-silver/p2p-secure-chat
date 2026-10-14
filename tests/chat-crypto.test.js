/**
 * @file tests/chat-crypto.test.js
 * @description Pruebas unitarias para el motor criptográfico y de identidad del Chat P2P.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  generateIdentityKeyPair,
  exportKeyPair,
  importKeyPair,
  getFingerprint,
  generateDefaultNickname,
  signPayload,
  verifyPayload,
  bytesToMnemonic,
  mnemonicToBytes,
  bufferToHex,
  hexToBuffer,
  canonicalJsonString,
  encryptPrivateKeyWithMnemonic,
  decryptPrivateKeyWithMnemonic,
  createModeratorCertificate,
  verifyModeratorCertificate,
  isAuthorizedModerator,
  generateInviteToken,
  verifyInviteToken,
  signAdminModerationAction,
  WORDLIST,
  GENESIS_ADMIN_ROOT_FINGERPRINT
} from '../src/chat/crypto.js';

describe('chat/crypto.js · Motor Criptográfico Autosoberano', () => {

  it('convierte correctamente entre Buffer y Hexadecimal', () => {
    const raw = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    const hex = bufferToHex(raw);
    assert.equal(hex, 'deadbeef');

    const back = hexToBuffer(hex);
    assert.deepEqual(Array.from(back), [0xde, 0xad, 0xbe, 0xef]);
  });

  it('genera un par de claves ECDSA y las exporta/importa correctamente', async () => {
    const keyPair = await generateIdentityKeyPair();
    assert.ok(keyPair.privateKey);
    assert.ok(keyPair.publicKey);

    const exported = await exportKeyPair(keyPair);
    assert.ok(exported.privateJwk);
    assert.ok(typeof exported.publicSpki === 'string');

    const imported = await importKeyPair(exported.privateJwk, exported.publicSpki);
    assert.ok(imported.privateKey);
    assert.ok(imported.publicKey);
  });

  it('deriva un fingerprint determinista y de longitud fija (8 caracteres)', async () => {
    const keyPair = await generateIdentityKeyPair();
    const { publicSpki } = await exportKeyPair(keyPair);

    const fp1 = await getFingerprint(publicSpki);
    const fp2 = await getFingerprint(publicSpki);

    assert.equal(fp1.length, 8);
    assert.equal(fp1, fp2);
    assert.match(fp1, /^[0-9a-f]{8}$/);
  });

  it('genera un apodo por defecto determinista según el fingerprint', () => {
    const name1 = generateDefaultNickname('8f3b2a9c');
    const name2 = generateDefaultNickname('8f3b2a9c');
    assert.equal(name1, name2);
    assert.ok(name1.includes('#8f3b'));
  });

  it('firma un payload y lo verifica exitosamente con la clave pública', async () => {
    const keyPair = await generateIdentityKeyPair();
    const { publicSpki } = await exportKeyPair(keyPair);

    const message = {
      text: '¡Hola desde P2P!',
      roomId: 'general',
      timestamp: 1728921600000
    };

    const signature = await signPayload(keyPair.privateKey, message);
    assert.ok(typeof signature === 'string');
    assert.ok(signature.length > 20);

    const isValid = await verifyPayload(publicSpki, message, signature);
    assert.equal(isValid, true);
  });

  it('falla la verificación si el contenido del mensaje fue alterado (Anti-Tampering)', async () => {
    const keyPair = await generateIdentityKeyPair();
    const { publicSpki } = await exportKeyPair(keyPair);

    const originalMessage = {
      text: 'Transferir 10 créditos',
      timestamp: 1728921600000
    };

    const signature = await signPayload(keyPair.privateKey, originalMessage);

    const tamperedMessage = {
      text: 'Transferir 1000 créditos (alterado)',
      timestamp: 1728921600000
    };

    const isValid = await verifyPayload(publicSpki, tamperedMessage, signature);
    assert.equal(isValid, false);
  });

  it('convierte 12 bytes a frase mnemónica de 12 palabras y viceversa de forma bidireccional', () => {
    const originalBytes = new Uint8Array([10, 25, 42, 88, 120, 200, 15, 33, 99, 144, 210, 255]);
    const mnemonic = bytesToMnemonic(originalBytes);

    const words = mnemonic.split(' ');
    assert.equal(words.length, 12);

    const restoredBytes = mnemonicToBytes(mnemonic);
    assert.deepEqual(Array.from(restoredBytes), Array.from(originalBytes));
  });

  it('lanza error si la frase mnemónica contiene palabras no válidas o longitud incorrecta', () => {
    assert.throws(() => {
      mnemonicToBytes('palabra_inexistente_xyz otra');
    });

    assert.throws(() => {
      bytesToMnemonic(new Uint8Array([1, 2, 3])); // menos de 12 bytes
    });
  });

  it('genera y valida tokens de invitación a la comunidad (Invite-Only)', async () => {
    const adminKey = await generateIdentityKeyPair();
    const { publicSpki } = await exportKeyPair(adminKey);
    const adminFp = await getFingerprint(publicSpki);

    const token = await generateInviteToken(adminKey.privateKey, publicSpki, adminFp, 'alumno_test', 24);
    assert.ok(typeof token === 'string');

    const result = await verifyInviteToken(token);
    assert.equal(result.valid, true);
    assert.equal(result.payload.invitedLabel, 'alumno_test');
    assert.equal(result.payload.adminFingerprint, adminFp);
  });

  it('rechaza tokens de invitación que hayan expirado', async () => {
    const adminKey = await generateIdentityKeyPair();
    const { publicSpki } = await exportKeyPair(adminKey);
    const adminFp = await getFingerprint(publicSpki);

    // Token con expiración negativa (-1 hora)
    const token = await generateInviteToken(adminKey.privateKey, publicSpki, adminFp, 'alumno_expirado', -1);
    const result = await verifyInviteToken(token);
    assert.equal(result.valid, false);
    assert.match(result.reason, /expirado/i);
  });

  it('firma y valida acciones de moderación administrativa (KICK)', async () => {
    const adminKey = await generateIdentityKeyPair();
    const { publicSpki } = await exportKeyPair(adminKey);

    const { actionPayload, signature } = await signAdminModerationAction(
      adminKey.privateKey,
      'ADMIN_KICK',
      { targetPeerId: '8f3b2a9c', reason: 'Spam masivo' }
    );

    const isValid = await verifyPayload(publicSpki, actionPayload, signature);
    assert.equal(isValid, true);
  });

  it('produce JSON canónico idéntico independientemente del orden de inserción de claves', () => {
    const objA = { z: 1, a: 2, m: { y: 'hola', x: 'mundo' } };
    const objB = { a: 2, m: { x: 'mundo', y: 'hola' }, z: 1 };

    const canonA = canonicalJsonString(objA);
    const canonB = canonicalJsonString(objB);

    assert.equal(canonA, canonB);
    assert.equal(canonA, '{"a":2,"m":{"x":"mundo","y":"hola"},"z":1}');
  });

  it('cifra y descifra la clave privada JWK usando las 12 palabras mnemónicas (Bóveda Criptográfica)', async () => {
    const keyPair = await generateIdentityKeyPair();
    const { privateJwk } = await exportKeyPair(keyPair);

    const testMnemonic = 'aguila cosmos bosque brisa cedro cielo diamante eco faro fuego galaxia hielo';
    const vault = await encryptPrivateKeyWithMnemonic(privateJwk, testMnemonic);

    assert.ok(vault.ciphertext);
    assert.ok(vault.iv);

    const decryptedJwk = await decryptPrivateKeyWithMnemonic(vault.ciphertext, vault.iv, testMnemonic);
    assert.deepEqual(decryptedJwk, privateJwk);
  });

  it('falla el descifrado de la clave privada si se usa una frase mnemónica incorrecta', async () => {
    const keyPair = await generateIdentityKeyPair();
    const { privateJwk } = await exportKeyPair(keyPair);

    const realMnemonic = 'aguila cosmos bosque brisa cedro cielo diamante eco faro fuego galaxia hielo';
    const wrongMnemonic = 'ancla arena astro atlas aurora bahia barco barro base bisonte buho cabo';

    const vault = await encryptPrivateKeyWithMnemonic(privateJwk, realMnemonic);

    await assert.rejects(async () => {
      await decryptPrivateKeyWithMnemonic(vault.ciphertext, vault.iv, wrongMnemonic);
    });
  });

  it('emite y valida exitosamente un Certificado de Delegación de Moderador firmado por la raíz', async () => {
    const rootKey = await generateIdentityKeyPair();
    const { publicSpki: rootSpki } = await exportKeyPair(rootKey);
    const rootFp = await getFingerprint(rootSpki);

    const modKey = await generateIdentityKeyPair();
    const { publicSpki: modSpki } = await exportKeyPair(modKey);
    const modFp = await getFingerprint(modSpki);

    const cert = await createModeratorCertificate(
      rootKey.privateKey,
      rootSpki,
      modSpki,
      'general',
      ['KICK', 'DELETE_MESSAGE'],
      24
    );

    assert.ok(cert.signature);
    assert.equal(cert.certificatePayload.rootFingerprint, rootFp);
    assert.equal(cert.certificatePayload.moderatorFingerprint, modFp);

    const verifyRes = await verifyModeratorCertificate(cert, [rootFp]);
    assert.equal(verifyRes.valid, true);
    assert.equal(verifyRes.payload.moderatorFingerprint, modFp);
  });

  it('rechaza certificados de moderador si han expirado o fueron emitidos por una raíz no autorizada', async () => {
    const rootKey = await generateIdentityKeyPair();
    const { publicSpki: rootSpki } = await exportKeyPair(rootKey);
    const rootFp = await getFingerprint(rootSpki);

    const modKey = await generateIdentityKeyPair();
    const { publicSpki: modSpki } = await exportKeyPair(modKey);

    // Certificado expirado (-1 hora)
    const expiredCert = await createModeratorCertificate(
      rootKey.privateKey,
      rootSpki,
      modSpki,
      '*',
      ['KICK'],
      -1
    );

    const expiredRes = await verifyModeratorCertificate(expiredCert, [rootFp]);
    assert.equal(expiredRes.valid, false);
    assert.match(expiredRes.error, /expirado/i);

    // Certificado firmado por raíz desconocida
    const validCert = await createModeratorCertificate(
      rootKey.privateKey,
      rootSpki,
      modSpki,
      '*',
      ['KICK'],
      24
    );
    const unknownRootRes = await verifyModeratorCertificate(validCert, ['otra_raiz_invalida']);
    assert.equal(unknownRootRes.valid, false);
    assert.match(unknownRootRes.error, /no está en la lista de administradores/i);
  });

  it('valida autorizaciones con isAuthorizedModerator y previene la usurpación de moderador', async () => {
    const rootKey = await generateIdentityKeyPair();
    const { publicSpki: rootSpki } = await exportKeyPair(rootKey);
    const rootFp = await getFingerprint(rootSpki);

    const modKey = await generateIdentityKeyPair();
    const { publicSpki: modSpki } = await exportKeyPair(modKey);

    const attackerKey = await generateIdentityKeyPair();
    const { publicSpki: attackerSpki } = await exportKeyPair(attackerKey);

    // 1. El Administrador Raíz siempre está autorizado
    const rootAuth = await isAuthorizedModerator(rootSpki, 'general', 'KICK', [rootFp]);
    assert.equal(rootAuth.authorized, true);
    assert.equal(rootAuth.role, 'root');

    // 2. Un atacante sin certificado es rechazado
    const attackerAuth = await isAuthorizedModerator(attackerSpki, 'general', 'KICK', [rootFp]);
    assert.equal(attackerAuth.authorized, false);
    assert.equal(attackerAuth.role, 'none');

    // 3. Moderador delegado con certificado válido solo para DELETE_MESSAGE en sala 'general'
    const modCert = await createModeratorCertificate(
      rootKey.privateKey,
      rootSpki,
      modSpki,
      'general',
      ['DELETE_MESSAGE'],
      48
    );

    // Autorizado para DELETE_MESSAGE en 'general'
    const modAuthOk = await isAuthorizedModerator(modSpki, 'general', 'DELETE_MESSAGE', [rootFp], modCert);
    assert.equal(modAuthOk.authorized, true);
    assert.equal(modAuthOk.role, 'delegated');

    // Rechazado si intenta KICK (permiso no concedido en el certificado)
    const modAuthKick = await isAuthorizedModerator(modSpki, 'general', 'KICK', [rootFp], modCert);
    assert.equal(modAuthKick.authorized, false);
    assert.match(modAuthKick.reason, /permiso KICK no concedido/i);

    // Rechazado si intenta actuar en una sala diferente ('ocio-gaming')
    const modAuthRoom = await isAuthorizedModerator(modSpki, 'ocio-gaming', 'DELETE_MESSAGE', [rootFp], modCert);
    assert.equal(modAuthRoom.authorized, false);
    assert.match(modAuthRoom.reason, /no válido para la sala/i);

    // Rechazado si un atacante intenta presentar el certificado del moderador legítimo
    const stolenCertAuth = await isAuthorizedModerator(attackerSpki, 'general', 'DELETE_MESSAGE', [rootFp], modCert);
    assert.equal(stolenCertAuth.authorized, false);
    assert.match(stolenCertAuth.reason, /no corresponde a este moderador/i);
  });

  it('el diccionario mnemónico tiene exactamente 256 palabras únicas (byte↔palabra biyectivo)', () => {
    assert.equal(WORDLIST.length, 256);
    assert.equal(new Set(WORDLIST).size, 256);

    const allBytes = new Uint8Array(12);
    for (let start = 0; start < 256; start += 12) {
      for (let i = 0; i < 12; i++) allBytes[i] = (start + i) % 256;
      assert.deepEqual(Array.from(mnemonicToBytes(bytesToMnemonic(allBytes))), Array.from(allBytes));
    }
  });

  it('el JSON canónico omite propiedades undefined igual que JSON.stringify (firmas estables tras el transporte)', async () => {
    const keyPair = await generateIdentityKeyPair();
    const { publicSpki } = await exportKeyPair(keyPair);

    const payload = { type: 'ADMIN_KICK', targetPeerId: 'abcd1234', reason: undefined, timestamp: 1 };
    const signature = await signPayload(keyPair.privateKey, payload);

    // El receptor recibe el payload tras JSON.stringify/parse: `reason` desaparece
    const transported = JSON.parse(JSON.stringify(payload));
    assert.equal(canonicalJsonString(payload), canonicalJsonString(transported));
    assert.equal(await verifyPayload(publicSpki, transported, signature), true);
  });

  it('los tokens de invitación admiten caracteres internacionales Unicode y detectan huella falsificada o emisor no confiable', async () => {
    const adminKey = await generateIdentityKeyPair();
    const { publicSpki } = await exportKeyPair(adminKey);
    const adminFp = await getFingerprint(publicSpki);

    const token = await generateInviteToken(adminKey.privateKey, publicSpki, adminFp, 'María Peña & José (CFGS 3D)', 1);
    const ok = await verifyInviteToken(token, [adminFp]);
    assert.equal(ok.valid, true);
    assert.equal(ok.payload.invitedLabel, 'María Peña & José (CFGS 3D)');

    // Emisor no incluido en la lista de confianza
    const untrusted = await verifyInviteToken(token, ['00000000']);
    assert.equal(untrusted.valid, false);
    assert.match(untrusted.reason, /no es un administrador de confianza/i);

    // Huella declarada ≠ huella de la clave que firma (suplantación del administrador raíz)
    const spoofed = await generateInviteToken(adminKey.privateKey, publicSpki, GENESIS_ADMIN_ROOT_FINGERPRINT, 'x', 1);
    const spoofRes = await verifyInviteToken(spoofed, [GENESIS_ADMIN_ROOT_FINGERPRINT]);
    assert.equal(spoofRes.valid, false);
    assert.match(spoofRes.reason, /no coincide con su clave pública/i);
  });

  it('un certificado de moderador sin expiresAt numérico es rechazado', async () => {
    const rootKey = await generateIdentityKeyPair();
    const { publicSpki: rootSpki } = await exportKeyPair(rootKey);
    const rootFp = await getFingerprint(rootSpki);
    const modKey = await generateIdentityKeyPair();
    const { publicSpki: modSpki } = await exportKeyPair(modKey);

    const cert = await createModeratorCertificate(rootKey.privateKey, rootSpki, modSpki, '*', ['KICK'], 24);
    delete cert.certificatePayload.expiresAt;
    cert.signature = await signPayload(rootKey.privateKey, cert.certificatePayload); // re-firmado por la raíz

    const res = await verifyModeratorCertificate(cert, [rootFp]);
    assert.equal(res.valid, false);
    assert.match(res.error, /expirado/i);
  });

});

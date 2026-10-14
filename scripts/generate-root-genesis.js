/**
 * @file scripts/generate-root-genesis.js
 * @description Script de Ceremonia Génesis para la creación de la Identidad Raíz autosoberana 'FilthySilver'.
 * Genera el par de claves asimétricas ECDSA P-256, deriva la frase mnemónica de 12 palabras,
 * calcula el Root Fingerprint (Trust Anchor) y exporta el archivo de respaldo seguro.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  generateIdentityKeyPair,
  exportKeyPair,
  getFingerprint,
  bytesToMnemonic,
  encryptPrivateKeyWithMnemonic
} from '../src/chat/crypto.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PROJECT_ROOT = path.resolve(__dirname, '..');

async function main() {
  console.log('\n======================================================');
  console.log('CEREMONIA GENESIS: CREACION DE USUARIO ROOT');
  console.log('   Identidad Autosoberana: FilthySilver');
  console.log('======================================================\n');

  console.log('1. Generando par de claves asimetricas ECDSA P-256 con Web Crypto...');
  const keyPair = await generateIdentityKeyPair();
  const { privateJwk, publicSpki } = await exportKeyPair(keyPair);

  console.log('2. Calculando huella digital publica (Root Fingerprint)...');
  const fingerprint = await getFingerprint(publicSpki);

  console.log('3. Generando entropia y frase mnemonica maestra de 12 palabras...');
  const randomBytes = new Uint8Array(12);
  crypto.getRandomValues(randomBytes);
  const mnemonic = bytesToMnemonic(randomBytes);

  console.log('4. Cifrando clave privada para Boveda Zero-Knowledge (AES-GCM-256)...');
  const vaultPackage = await encryptPrivateKeyWithMnemonic(privateJwk, mnemonic);

  const rootIdentity = {
    nickname: 'FilthySilver',
    fingerprint,
    mnemonic,
    publicSpki,
    privateJwk,
    role: 'genesis_root',
    vault: vaultPackage,
    createdAt: new Date().toISOString()
  };

  const outputPath = path.join(PROJECT_ROOT, 'filthysilver-root-identity.json');
  fs.writeFileSync(outputPath, JSON.stringify(rootIdentity, null, 2), 'utf-8');

  console.log('\n======================================================');
  console.log('USUARIO ROOT "FilthySilver" CREADO CON EXITO');
  console.log('======================================================');
  console.log(`- Apodo:            FilthySilver`);
  console.log(`- Root Fingerprint: 0x${fingerprint} (ID Criptografico: ${fingerprint})`);
  console.log(`- Archivo Seguro:   filthysilver-root-identity.json (Ignorado en git)`);
  console.log('\nFRASE MAESTRA DE 12 PALABRAS (GUARDA ESTO EN LUGAR SEGURO):');
  console.log('------------------------------------------------------');
  console.log(`   ${mnemonic}`);
  console.log('------------------------------------------------------');
  console.log('\nInstrucciones para activar tu usuario Root:');
  console.log('1. Abre tu aplicacion de chat (/chat.html)');
  console.log('2. Pulsa en "Mi Identidad" -> "Restaurar Identidad"');
  console.log('3. Pega tus 12 palabras');
  console.log('4. Listo: tendras poderes de Administrador Raiz Genesis en cualquier sala.\n');

  return fingerprint;
}

main().catch(err => {
  console.error('Error durante la Ceremonia Genesis:', err);
  process.exit(1);
});

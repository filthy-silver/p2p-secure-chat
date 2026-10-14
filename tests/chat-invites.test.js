/**
 * @file tests/chat-invites.test.js
 * @description Pruebas unitarias para el Árbol Genealógico de Invitaciones, control de cupos,
 * revocación en cascada y las defensas anti-suplantación de la API.
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

const URL_API = 'http://localhost/api/chat/invites';
const ADMIN_SECRET = 'secreto-de-prueba-solo-en-env';

describe('chat-invites.js · Árbol de Invitaciones y Cadena de Confianza', () => {

  /** Entorno con KV simulado en memoria (ADMIN_SECRET solo existe si se configura). */
  function createEnv(extra = {}) {
    const memory = new Map();
    return {
      memory,
      env: {
        EVENTS_KV: {
          async get(key) { return memory.get(key) || null; },
          async put(key, value) { memory.set(key, value); }
        },
        ...extra
      }
    };
  }

  function post(env, body) {
    const request = new Request(URL_API, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    return onRequest({ request, env });
  }

  function get(env, fingerprint) {
    const request = new Request(`${URL_API}?fingerprint=${encodeURIComponent(fingerprint)}`, { method: 'GET' });
    return onRequest({ request, env });
  }

  /** Identidad criptográfica real (clave ECDSA + SPKI + huella derivada). */
  async function createUser() {
    const keyPair = await generateIdentityKeyPair();
    const { publicSpki } = await exportKeyPair(keyPair);
    const fp = await getFingerprint(publicSpki);
    return { keyPair, publicSpki, fp };
  }

  async function signedCreate(env, user, targetLabel = 'Invitado', creatorLabel = 'Creador') {
    const timestamp = Date.now();
    const signature = await signPayload(
      user.keyPair.privateKey,
      { action: 'create', creatorFingerprint: user.fp, targetLabel, timestamp }
    );
    return post(env, {
      action: 'create',
      creatorFingerprint: user.fp,
      creatorPublicSpki: user.publicSpki,
      creatorLabel,
      targetLabel,
      timestamp,
      signature
    });
  }

  async function signedClaim(env, user, code, nickname = 'Nuevo') {
    const timestamp = Date.now();
    const signature = await signPayload(
      user.keyPair.privateKey,
      { action: 'claim', code, userFingerprint: user.fp, timestamp }
    );
    return post(env, {
      action: 'claim',
      code,
      userFingerprint: user.fp,
      userPublicSpki: user.publicSpki,
      nickname,
      timestamp,
      signature
    });
  }

  it('asigna cupo inicial de 2 a usuarios regulares y 9999 al administrador raíz (sin persistir en GET)', async () => {
    const { env, memory } = createEnv();

    const userRes = await get(env, 'user123');
    const userData = await userRes.json();
    assert.equal(userRes.status, 200);
    assert.equal(userData.success, true);
    assert.equal(userData.quota, 2);
    assert.equal(userData.remainingQuota, 2);

    const adminRes = await get(env, GENESIS_ADMIN_ROOT_FINGERPRINT);
    const adminData = await adminRes.json();
    assert.equal(adminData.quota, 9999);
    assert.equal(adminData.remainingQuota, 9999);

    // Un GET anónimo no debe escribir nada en KV
    assert.equal(memory.size, 0);
  });

  it('ya no concede privilegios de administrador a alias de texto (admin, filthysilver...)', async () => {
    const { env } = createEnv();
    for (const alias of ['filthysilver_admin', 'admin', 'filthysilver']) {
      const data = await (await get(env, alias)).json();
      assert.equal(data.quota, 2, `El alias "${alias}" no debe tener cupo de administrador`);
    }
  });

  it('rechaza huellas con formato inválido en GET', async () => {
    const { env } = createEnv();
    const res = await get(env, 'a'.repeat(200));
    assert.equal(res.status, 400);
  });

  it('permite crear invitaciones trazables firmadas y descuenta el cupo disponible', async () => {
    const { env } = createEnv();
    const carlos = await createUser();

    const res = await signedCreate(env, carlos, 'Marta', 'Carlos');
    const data = await res.json();

    assert.equal(res.status, 201);
    assert.equal(data.success, true);
    assert.match(data.code, /^INV-[A-Z0-9]{6}$/);
    assert.equal(data.remainingQuota, 1);
    assert.equal(data.inviteRecord.creatorFingerprint, carlos.fp);
  });

  it('rechaza la creación de invitaciones SIN firma digital (Anti-Spoofing)', async () => {
    const { env } = createEnv();
    for (const spoofedFp of ['carlos_fp', 'admin', GENESIS_ADMIN_ROOT_FINGERPRINT]) {
      const res = await post(env, {
        action: 'create',
        creatorFingerprint: spoofedFp,
        creatorLabel: 'Atacante',
        targetLabel: 'Sybil'
      });
      assert.equal(res.status, 401);
    }
  });

  it('rechaza la creación de invitaciones cuando se agota el cupo', async () => {
    const { env } = createEnv();
    const pedro = await createUser();

    assert.equal((await signedCreate(env, pedro, 'Invitado 1')).status, 201);
    assert.equal((await signedCreate(env, pedro, 'Invitado 2')).status, 201);

    const res3 = await signedCreate(env, pedro, 'Invitado 3');
    const data3 = await res3.json();

    assert.equal(res3.status, 400);
    assert.equal(data3.success, false);
    assert.match(data3.error, /agotado tu cupo/i);
  });

  it('el administrador configurado en el entorno no tiene límite de cupo', async () => {
    const admin = await createUser();
    const { env } = createEnv({ ADMIN_FINGERPRINT: admin.fp });

    for (let i = 0; i < 4; i++) {
      const res = await signedCreate(env, admin, `Invitado ${i}`);
      assert.equal(res.status, 201);
    }
  });

  it('permite canjear un código firmado y registra la filiación de linaje (410 en segundo canje)', async () => {
    const { env } = createEnv();
    const sara = await createUser();
    const lucas = await createUser();

    const createRes = await signedCreate(env, sara, 'Lucas', 'Sara');
    const { code } = await createRes.json();

    const claimRes = await signedClaim(env, lucas, code, 'Lucas');
    const claimData = await claimRes.json();

    assert.equal(claimRes.status, 200);
    assert.equal(claimData.success, true);
    assert.equal(claimData.lineage.invitedBy, sara.fp);
    assert.equal(claimData.lineage.invitedByLabel, 'Sara');

    // Segundo canje del mismo código (por otra identidad) debe fallar con 410
    const otro = await createUser();
    const doubleClaimRes = await signedClaim(env, otro, code, 'Otro');
    assert.equal(doubleClaimRes.status, 410);
  });

  it('rechaza el canje sin firma o con una firma de otra identidad (nadie registra huellas ajenas)', async () => {
    const { env } = createEnv();
    const sara = await createUser();
    const victima = await createUser();
    const atacante = await createUser();

    const { code } = await (await signedCreate(env, sara, 'X', 'Sara')).json();

    // Sin firma
    const unsigned = await post(env, { action: 'claim', code, userFingerprint: victima.fp, nickname: 'Víctima' });
    assert.equal(unsigned.status, 401);

    // Firma válida del atacante pero reclamando la huella de la víctima
    const timestamp = Date.now();
    const signature = await signPayload(
      atacante.keyPair.privateKey,
      { action: 'claim', code, userFingerprint: victima.fp, timestamp }
    );
    const spoofed = await post(env, {
      action: 'claim',
      code,
      userFingerprint: victima.fp,
      userPublicSpki: atacante.publicSpki,
      timestamp,
      signature
    });
    assert.equal(spoofed.status, 401);
  });

  it('ejecuta la revocación en cascada multi-nivel (A -> B -> C) y bloquea la evasión de baneo', async () => {
    const { env } = createEnv({ ADMIN_SECRET });
    const userA = await createUser();
    const userB = await createUser();
    const userC = await createUser();

    // 1. Usuario A invita a Usuario B
    const { code: codeAB } = await (await signedCreate(env, userA, 'Usuario B', 'Usuario A')).json();
    assert.equal((await signedClaim(env, userB, codeAB, 'Usuario B')).status, 200);

    // 2. Usuario B invita a Usuario C
    const { code: codeBC } = await (await signedCreate(env, userB, 'Usuario C', 'Usuario B')).json();
    assert.equal((await signedClaim(env, userC, codeBC, 'Usuario C')).status, 200);

    // A conserva una invitación sin canjear que debe quedar inutilizada por la cascada
    const { code: codeLibre } = await (await signedCreate(env, userA, 'Pendiente', 'Usuario A')).json();

    // 3. Ejecutar revocación en cascada sobre Usuario A
    const cascadeRes = await post(env, { action: 'revoke_cascade', targetFingerprint: userA.fp, adminSecret: ADMIN_SECRET });
    const cascadeData = await cascadeRes.json();

    assert.equal(cascadeRes.status, 200);
    assert.equal(cascadeData.success, true);
    assert.ok(cascadeData.affectedUsers.includes(userB.fp));
    assert.ok(cascadeData.affectedUsers.includes(userC.fp));

    // Invitación revocada: no puede canjearse
    const intruso = await createUser();
    assert.equal((await signedClaim(env, intruso, codeLibre, 'Intruso')).status, 410);

    // Un usuario baneado no puede crear invitaciones ni re-registrarse para "desbanearse"
    assert.equal((await signedCreate(env, userB, 'Otro')).status, 403);
    const fresh = await createUser();
    const { code: codeFresh } = await (await signedCreate(env, fresh, 'Reingreso', 'Fresh')).json();
    assert.equal((await signedClaim(env, userB, codeFresh, 'Usuario B')).status, 403);
  });

  it('valida la firma digital ECDSA en la creación de invitaciones (Anti-Spoofing)', async () => {
    const { env } = createEnv();
    const profesor = await createUser();

    const res = await signedCreate(env, profesor, 'Alumno Nuevo', 'Profesor');
    const data = await res.json();

    assert.equal(res.status, 201);
    assert.equal(data.success, true);
    assert.match(data.code, /^INV-[A-Z0-9]{6}$/);
    assert.equal(data.remainingQuota, 1);
  });

  it('rechaza la creación de invitaciones si la huella no coincide con la clave pública SPKI', async () => {
    const { env } = createEnv();
    const atacante = await createUser();

    const timestamp = Date.now();
    const signature = await signPayload(
      atacante.keyPair.privateKey,
      { action: 'create', creatorFingerprint: 'victima_falsa', targetLabel: 'Alumno', timestamp }
    );

    const res = await post(env, {
      action: 'create',
      creatorFingerprint: 'victima_falsa',
      creatorPublicSpki: atacante.publicSpki,
      creatorLabel: 'Atacante',
      targetLabel: 'Alumno',
      timestamp,
      signature
    });
    const data = await res.json();

    assert.equal(res.status, 401);
    assert.equal(data.success, false);
    assert.match(data.error, /no coincide con la clave pública/i);
  });

  it('rechaza solicitudes firmadas con timestamp caducado (anti-replay)', async () => {
    const { env } = createEnv();
    const user = await createUser();
    const timestamp = Date.now() - 3600 * 1000;
    const signature = await signPayload(
      user.keyPair.privateKey,
      { action: 'create', creatorFingerprint: user.fp, targetLabel: 'X', timestamp }
    );
    const res = await post(env, {
      action: 'create',
      creatorFingerprint: user.fp,
      creatorPublicSpki: user.publicSpki,
      targetLabel: 'X',
      timestamp,
      signature
    });
    assert.equal(res.status, 400);
  });

  it('rechaza la revocación en cascada de atacantes no autorizados y la aprueba solo con ADMIN_SECRET del entorno', async () => {
    const { env } = createEnv({ ADMIN_SECRET });

    const wrong = await post(env, { action: 'revoke_cascade', targetFingerprint: 'usuario_inocente', adminSecret: 'clave_invalida_123' });
    assert.equal(wrong.status, 403);

    // Sin credencial: nunca autorizado (antes existía un bypass "de tests")
    const anon = await post(env, { action: 'revoke_cascade', targetFingerprint: 'usuario_inocente' });
    assert.equal(anon.status, 403);

    // Declarar una huella de administrador sin firma no basta
    const spoof = await post(env, {
      action: 'revoke_cascade',
      targetFingerprint: 'usuario_inocente',
      requesterFingerprint: GENESIS_ADMIN_ROOT_FINGERPRINT,
      creatorFingerprint: GENESIS_ADMIN_ROOT_FINGERPRINT
    });
    assert.equal(spoof.status, 403);

    const authRes = await post(env, { action: 'revoke_cascade', targetFingerprint: 'usuario_infractor', adminSecret: ADMIN_SECRET });
    const authData = await authRes.json();
    assert.equal(authRes.status, 200);
    assert.equal(authData.success, true);
  });

  it('NO existe secreto de administrador por defecto: sin ADMIN_SECRET configurado todo adminSecret es rechazado', async () => {
    const { env } = createEnv(); // sin ADMIN_SECRET
    for (const guess of ['filthysilver3d', 'admin', '', 'undefined']) {
      const res = await post(env, { action: 'revoke_cascade', targetFingerprint: 'victima', adminSecret: guess });
      assert.equal(res.status, 403);
    }
  });

  it('acepta la revocación firmada por el administrador configurado y rechaza firmas de terceros', async () => {
    const admin = await createUser();
    const intruso = await createUser();
    const { env } = createEnv({ ADMIN_FINGERPRINT: admin.fp });

    async function signedRevoke(signer, claimedAdminFp) {
      const timestamp = Date.now();
      const signature = await signPayload(
        signer.keyPair.privateKey,
        { action: 'revoke_cascade', targetFingerprint: 'objetivo', timestamp }
      );
      return post(env, {
        action: 'revoke_cascade',
        targetFingerprint: 'objetivo',
        adminFingerprint: claimedAdminFp,
        adminPublicSpki: signer.publicSpki,
        timestamp,
        signature
      });
    }

    assert.equal((await signedRevoke(admin, admin.fp)).status, 200);
    // El intruso firma con su propia clave pero declara la huella del administrador: 403
    assert.equal((await signedRevoke(intruso, admin.fp)).status, 403);
  });

});

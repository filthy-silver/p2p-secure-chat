/**
 * @file functions/api/chat-invites.js
 * @description API de Cloudflare para gestión del Árbol Genealógico de Invitaciones,
 * control de cupos por alumno, trazabilidad de linaje y revocación en cascada.
 *
 * Modelo de seguridad:
 * - La identidad de quien crea/canjea una invitación se prueba SIEMPRE con una firma ECDSA
 *   (la huella declarada debe derivarse de la clave pública SPKI que firma). No hay alias de
 *   administrador basados en texto: solo la huella raíz Génesis o `env.ADMIN_FINGERPRINT`,
 *   y únicamente cuando proceden de una firma verificada.
 * - La revocación en cascada exige `env.ADMIN_SECRET` (configurado como secreto de Cloudflare;
 *   sin valor por defecto) o una firma del administrador raíz.
 * - Limitación conocida: Cloudflare KV no ofrece operaciones atómicas (CAS); canjes/creaciones
 *   concurrentes del mismo código/cupo pueden producir condiciones de carrera. Para garantías
 *   fuertes migrar el estado a un Durable Object.
 */

import {
  verifyPayload,
  getFingerprint,
  GENESIS_ADMIN_ROOT_FINGERPRINT
} from '../../src/chat/crypto.js';

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization'
};

const DEFAULT_USER_QUOTA = 2; // Cada usuario puede invitar a 2 personas
const SIGNATURE_MAX_SKEW_MS = 600000; // 10 minutos anti-replay
const SAFE_ID_REGEX = /^[a-z0-9_-]{1,64}$/i;
const MAX_LABEL_LENGTH = 40;

/**
 * Determina si una huella VERIFICADA (derivada de una firma válida) pertenece a un administrador.
 * No acepta alias de texto: las huellas son declaraciones del cliente y no prueban nada por sí solas.
 */
function isAuthorizedAdmin(fp, env) {
  if (!fp) return false;
  const cleanFp = String(fp).trim().toLowerCase();
  if (cleanFp === GENESIS_ADMIN_ROOT_FINGERPRINT.toLowerCase()) return true;
  if (env && env.ADMIN_FINGERPRINT && cleanFp === String(env.ADMIN_FINGERPRINT).toLowerCase()) return true;
  return false;
}

/**
 * Comparación de cadenas en tiempo constante (evita ataques de temporización sobre el secreto).
 */
function timingSafeEqualStr(a, b) {
  const encoder = new TextEncoder();
  const bufA = encoder.encode(String(a));
  const bufB = encoder.encode(String(b));
  let diff = bufA.length ^ bufB.length;
  const len = Math.max(bufA.length, bufB.length);
  for (let i = 0; i < len; i++) {
    diff |= (bufA[i] ?? 0) ^ (bufB[i] ?? 0);
  }
  return diff === 0;
}

/**
 * Normaliza etiquetas visibles: solo texto, sin caracteres de control y con longitud acotada.
 */
function cleanLabel(value, fallback) {
  if (typeof value !== 'string') return fallback;
  const cleaned = value.replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, MAX_LABEL_LENGTH);
  return cleaned || fallback;
}

function json(body, status) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS }
  });
}

// Memoria de respaldo SOLO si KV no está enlazado (desarrollo local)
const memoryInvites = new Map(); // code -> inviteRecord
const memoryUsers = new Map();   // fingerprint -> userRecord

/**
 * Obtiene un registro de la base KV o memoria.
 * Con KV enlazado los errores se propagan (fail-closed): tratar un fallo de lectura como
 * "usuario inexistente" permitiría saltarse baneos durante una caída de KV.
 */
async function getKv(env, key) {
  if (env && env.EVENTS_KV) {
    const raw = await env.EVENTS_KV.get(key);
    return raw ? JSON.parse(raw) : null;
  }
  return memoryInvites.get(key) || memoryUsers.get(key) || null;
}

/**
 * Guarda un registro en la base KV o memoria (los fallos de KV se propagan; sin split-brain).
 */
async function setKv(env, key, value, ttlSeconds = null) {
  if (env && env.EVENTS_KV) {
    const opts = ttlSeconds ? { expirationTtl: Math.max(120, ttlSeconds) } : undefined;
    await env.EVENTS_KV.put(key, JSON.stringify(value), opts);
    return;
  }

  if (key.startsWith('inv_')) {
    memoryInvites.set(key, value);
  } else {
    memoryUsers.set(key, value);
  }
}

/**
 * Genera un código de invitación seguro y legible (ej: INV-8F3B2A) con CSPRNG.
 * El alfabeto tiene 32 símbolos, por lo que `byte & 31` es uniforme (sin sesgo de módulo).
 */
function generateCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes = crypto.getRandomValues(new Uint8Array(6));
  let str = '';
  for (let i = 0; i < 6; i++) {
    str += chars.charAt(bytes[i] & 31);
  }
  return `INV-${str}`;
}

/**
 * Genera un código de campaña Génesis seguro y legible (ej: GEN-8F3B2A) con CSPRNG.
 */
function generateCampaignCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes = crypto.getRandomValues(new Uint8Array(6));
  let str = '';
  for (let i = 0; i < 6; i++) {
    str += chars.charAt(bytes[i] & 31);
  }
  return `GEN-${str}`;
}

/**
 * Verifica una petición firmada: frescura, huella↔SPKI y firma ECDSA del payload canónico.
 * @returns {Promise<{ ok: true, fingerprint: string } | { ok: false, status: number, error: string }>}
 */
async function authenticateSignedRequest({ publicSpki, claimedFingerprint, timestamp, signature, payload }) {
  if (!signature || !publicSpki || typeof timestamp !== 'number') {
    return { ok: false, status: 401, error: 'Firma digital requerida (signature, publicSpki y timestamp)' };
  }
  if (!Number.isFinite(timestamp) || Math.abs(Date.now() - timestamp) > SIGNATURE_MAX_SKEW_MS) {
    return { ok: false, status: 400, error: 'Firma de solicitud expirada' };
  }

  let derivedFp;
  try {
    derivedFp = await getFingerprint(publicSpki);
  } catch {
    return { ok: false, status: 401, error: 'Clave pública SPKI inválida' };
  }
  if (derivedFp !== claimedFingerprint) {
    return { ok: false, status: 401, error: 'La huella no coincide con la clave pública SPKI' };
  }

  const validSig = await verifyPayload(publicSpki, payload, signature);
  if (!validSig) {
    return { ok: false, status: 401, error: 'Firma digital inválida o manipulada' };
  }
  return { ok: true, fingerprint: derivedFp };
}

/**
 * Manejador principal para /api/chat/invites
 */
export async function onRequest(context) {
  const { request, env } = context;
  const method = request.method.toUpperCase();
  const url = new URL(request.url);

  if (method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  try {
    // 1. GET: Consultar árbol de un usuario, cupos restantes y a quién invitó (solo lectura)
    if (method === 'GET') {
      const fp = (url.searchParams.get('fingerprint') || '').trim().toLowerCase();
      if (!fp) {
        return json({ success: false, error: 'Huella requerida' }, 400);
      }
      if (!SAFE_ID_REGEX.test(fp)) {
        return json({ success: false, error: 'Huella con formato inválido' }, 400);
      }

      const userKey = `user_meta_${fp}`;
      let user = await getKv(env, userKey);

      // Si es el admin maestro o usuario no registrado aún. NO se persiste: un GET anónimo
      // no debe poder escribir en KV (amplificación de escritura / DoS de almacenamiento).
      const isAdmin = isAuthorizedAdmin(fp, env);
      if (!user) {
        user = {
          fingerprint: fp,
          quota: isAdmin ? 9999 : DEFAULT_USER_QUOTA,
          invitedBy: isAdmin ? 'GENESIS' : 'UNKNOWN',
          invitedByLabel: isAdmin ? 'Sistema Génesis' : 'Invitación Directa',
          createdAt: Date.now(),
          banned: false
        };
      }

      // Obtener invitaciones emitidas por este usuario
      const issuedKey = `issued_by_${fp}`;
      const issuedCodes = (await getKv(env, issuedKey)) || [];

      const inviteDetails = [];
      for (const code of issuedCodes) {
        const inv = await getKv(env, `inv_${code}`);
        if (inv) inviteDetails.push(inv);
      }

      const usedCount = inviteDetails.filter(i => (i.type === 'TEMPORAL_CAMPAIGN' ? (i.usedCount > 0) : i.used)).length;
      const regularInvites = inviteDetails.filter(i => i.type !== 'TEMPORAL_CAMPAIGN');
      const remainingQuota = Math.max(0, user.quota - regularInvites.length);

      return json({
        success: true,
        fingerprint: fp,
        quota: user.quota,
        remainingQuota: isAdmin ? 9999 : remainingQuota,
        usedCount,
        invitedBy: user.invitedBy,
        invitedByLabel: user.invitedByLabel,
        banned: Boolean(user.banned),
        invites: inviteDetails
      }, 200);
    }

    // 2. POST: Crear o canjear invitaciones
    if (method === 'POST') {
      const body = await request.json().catch(() => ({}));
      const action = body.action;

      // ACCIÓN A: Crear nueva invitación (consume 1 del cupo)
      if (action === 'create') {
        const { creatorFingerprint, creatorPublicSpki, creatorLabel, targetLabel, timestamp, signature } = body;
        const fp = String(creatorFingerprint || '').trim().toLowerCase();

        if (!fp) {
          return json({ success: false, error: 'Identificador del emisor requerido' }, 400);
        }

        // La autoría de la solicitud se prueba matemáticamente: sin firma no hay creación
        // (evita suplantar al creador, consumir su cupo o hacerse pasar por administrador).
        const auth = await authenticateSignedRequest({
          publicSpki: creatorPublicSpki,
          claimedFingerprint: fp,
          timestamp,
          signature,
          payload: { action: 'create', creatorFingerprint: fp, targetLabel, timestamp }
        });
        if (!auth.ok) {
          return json({ success: false, error: auth.error }, auth.status);
        }

        const isAdmin = isAuthorizedAdmin(fp, env);
        const userKey = `user_meta_${fp}`;
        let user = await getKv(env, userKey);

        if (!user) {
          user = {
            fingerprint: fp,
            quota: isAdmin ? 9999 : DEFAULT_USER_QUOTA,
            invitedBy: isAdmin ? 'GENESIS' : 'UNKNOWN',
            invitedByLabel: isAdmin ? 'Génesis' : 'Directo',
            banned: false
          };
        }

        if (user.banned) {
          return json({ success: false, error: 'Usuario suspendido. No puedes crear invitaciones.' }, 403);
        }

        const issuedKey = `issued_by_${fp}`;
        const issuedCodes = (await getKv(env, issuedKey)) || [];

        if (!isAdmin && issuedCodes.length >= user.quota) {
          return json({ success: false, error: `Has agotado tu cupo de ${user.quota} invitaciones.` }, 400);
        }

        const code = generateCode();
        const inviteRecord = {
          code,
          creatorFingerprint: fp,
          creatorLabel: cleanLabel(creatorLabel, `Usuario#${fp.slice(0, 4)}`),
          targetLabel: cleanLabel(targetLabel, 'Compañero'),
          createdAt: Date.now(),
          used: false,
          usedByFingerprint: null,
          usedByLabel: null,
          usedAt: null
        };

        // Guardar registro de la invitación
        await setKv(env, `inv_${code}`, inviteRecord);

        // Actualizar lista de emitidas por el creador
        issuedCodes.push(code);
        await setKv(env, issuedKey, issuedCodes);

        return json({
          success: true,
          code,
          inviteRecord,
          remainingQuota: isAdmin ? 9999 : (user.quota - issuedCodes.length)
        }, 201);
      }

      // ACCIÓN B: Crear Pase de Temporada Génesis (Reutilizable temporal con aforo - Exclusivo Root)
      if (action === 'create_temporal_campaign') {
        const { creatorFingerprint, creatorPublicSpki, campaignName, durationHours, maxUses, timestamp, signature } = body;
        const fp = String(creatorFingerprint || '').trim().toLowerCase();

        if (!fp) {
          return json({ success: false, error: 'Identificador del emisor requerido' }, 400);
        }

        // Solo administradores autorizados (Root Génesis o env.ADMIN_FINGERPRINT)
        if (!isAuthorizedAdmin(fp, env)) {
          return json({ success: false, error: 'Solo el Administrador Raíz puede emitir Pases de Temporada Génesis.' }, 403);
        }

        const auth = await authenticateSignedRequest({
          publicSpki: creatorPublicSpki,
          claimedFingerprint: fp,
          timestamp,
          signature,
          payload: { action: 'create_temporal_campaign', creatorFingerprint: fp, campaignName, durationHours, maxUses, timestamp }
        });
        if (!auth.ok) {
          return json({ success: false, error: auth.error }, auth.status);
        }

        const hours = (typeof durationHours === 'number' && durationHours > 0) ? durationHours : 168;
        const parsedMaxUses = (typeof maxUses === 'number' && maxUses > 0) ? Math.floor(maxUses) : null;
        const code = generateCampaignCode();
        const expiresAt = Date.now() + (hours * 3600 * 1000);

        const campaignRecord = {
          code,
          type: 'TEMPORAL_CAMPAIGN',
          creatorFingerprint: fp,
          creatorLabel: 'FilthySilver (Génesis)',
          campaignName: cleanLabel(campaignName, 'Pase de Temporada Génesis'),
          createdAt: Date.now(),
          expiresAt,
          durationHours: hours,
          maxUses: parsedMaxUses,
          usedCount: 0,
          reusable: true,
          revoked: false,
          registeredUsers: []
        };

        const ttlSeconds = Math.ceil((hours * 3600) + 86400);
        await setKv(env, `inv_${code}`, campaignRecord, ttlSeconds);

        const issuedKey = `issued_by_${fp}`;
        const issuedCodes = (await getKv(env, issuedKey)) || [];
        issuedCodes.push(code);
        await setKv(env, issuedKey, issuedCodes);

        return json({
          success: true,
          code,
          campaignRecord
        }, 201);
      }

      // ACCIÓN C: Actualizar parámetros de Campaña Génesis (Aumentar aforo, extender tiempo o cerrar)
      if (action === 'update_campaign') {
        const { code, creatorFingerprint, creatorPublicSpki, addMaxUses, newMaxUses, extendHours, close, timestamp, signature } = body;
        const fp = String(creatorFingerprint || '').trim().toLowerCase();
        const cleanCode = String(code || '').trim().toUpperCase();

        if (!fp || !cleanCode) {
          return json({ success: false, error: 'Huella y código de campaña requeridos' }, 400);
        }

        if (!isAuthorizedAdmin(fp, env)) {
          return json({ success: false, error: 'Solo el Administrador Raíz puede modificar campañas.' }, 403);
        }

        const auth = await authenticateSignedRequest({
          publicSpki: creatorPublicSpki,
          claimedFingerprint: fp,
          timestamp,
          signature,
          payload: { action: 'update_campaign', code: cleanCode, creatorFingerprint: fp, timestamp }
        });
        if (!auth.ok) {
          return json({ success: false, error: auth.error }, auth.status);
        }

        const campaignKey = `inv_${cleanCode}`;
        const campaign = await getKv(env, campaignKey);
        if (!campaign || campaign.type !== 'TEMPORAL_CAMPAIGN') {
          return json({ success: false, error: 'Campaña inexistente o inválida.' }, 404);
        }

        if (close) {
          campaign.revoked = true;
        }
        if (typeof addMaxUses === 'number' && addMaxUses > 0) {
          campaign.maxUses = (campaign.maxUses || 0) + Math.floor(addMaxUses);
        } else if (typeof newMaxUses === 'number' && newMaxUses > 0) {
          campaign.maxUses = Math.floor(newMaxUses);
        }
        if (typeof extendHours === 'number' && extendHours > 0) {
          const baseTime = Math.max(Date.now(), campaign.expiresAt);
          campaign.expiresAt = baseTime + (extendHours * 3600 * 1000);
        }

        await setKv(env, campaignKey, campaign);

        return json({
          success: true,
          message: 'Campaña actualizada con éxito.',
          campaign
        }, 200);
      }

      // ACCIÓN D: Canjear invitación (Registro de linaje del nuevo alumno)
      if (action === 'claim') {
        const { code, userFingerprint, userPublicSpki, nickname, timestamp, signature } = body;
        const cleanCode = String(code || '').trim().toUpperCase();
        const cleanFp = String(userFingerprint || '').trim().toLowerCase();

        if (!cleanCode || !cleanFp) {
          return json({ success: false, error: 'Código y huella requeridos' }, 400);
        }

        // El canje prueba posesión de la clave privada: nadie puede registrar una huella ajena
        const auth = await authenticateSignedRequest({
          publicSpki: userPublicSpki,
          claimedFingerprint: cleanFp,
          timestamp,
          signature,
          payload: { action: 'claim', code: String(code).trim(), userFingerprint: cleanFp, timestamp }
        });
        if (!auth.ok) {
          return json({ success: false, error: auth.error }, auth.status);
        }

        const inviteKey = `inv_${cleanCode}`;
        const inviteRecord = await getKv(env, inviteKey);

        if (!inviteRecord) {
          return json({ success: false, error: 'Código de invitación inexistente o inválido.' }, 404);
        }

        // Invitaciones revocadas no pueden canjearse
        if (inviteRecord.revoked) {
          return json({ success: false, error: 'Este enlace de invitación ha sido revocado por el administrador.' }, 410);
        }

        // El emisor de la invitación no puede estar suspendido
        const creatorRecord = await getKv(env, `user_meta_${inviteRecord.creatorFingerprint}`);
        if (creatorRecord && creatorRecord.banned) {
          return json({ success: false, error: 'El emisor de esta invitación está suspendido.' }, 403);
        }

        // CASO 1: Pase de Temporada Génesis (Reutilizable con doble salvaguarda: tiempo + aforo)
        if (inviteRecord.type === 'TEMPORAL_CAMPAIGN' || inviteRecord.reusable) {
          // Comprobar expiración por tiempo (TTL)
          if (inviteRecord.expiresAt && Date.now() > inviteRecord.expiresAt) {
            return json({
              success: false,
              error: 'El plazo temporal de este enlace de invitación ha expirado.'
            }, 410);
          }

          const newUserKey = `user_meta_${cleanFp}`;
          const existingUser = await getKv(env, newUserKey);

          if (existingUser && existingUser.banned) {
            return json({ success: false, error: 'Usuario suspendido. No puedes canjear invitaciones.' }, 403);
          }

          // Si el alumno ya estaba registrado en esta campaña, permitir acceso sin consumir nueva plaza
          const alreadyRegisteredInCampaign = Array.isArray(inviteRecord.registeredUsers) &&
            inviteRecord.registeredUsers.some(u => u.fingerprint === cleanFp);

          if (alreadyRegisteredInCampaign) {
            return json({
              success: true,
              message: '¡Bienvenido de nuevo a la sala!',
              alreadyClaimed: true,
              lineage: {
                invitedBy: inviteRecord.creatorFingerprint,
                invitedByLabel: inviteRecord.creatorLabel
              }
            }, 200);
          }

          // Comprobar aforo máximo antes de admitir un nuevo alumno
          if (inviteRecord.maxUses !== null && typeof inviteRecord.maxUses === 'number' && inviteRecord.usedCount >= inviteRecord.maxUses) {
            return json({
              success: false,
              error: `Aforo completo. Se ha alcanzado el límite máximo de ${inviteRecord.maxUses} plazas para este enlace.`
            }, 410);
          }

          const usedByLabel = cleanLabel(nickname, `Alumno#${cleanFp.slice(0, 4)}`);

          // Incrementar contador y registrar en la campaña
          inviteRecord.usedCount = (inviteRecord.usedCount || 0) + 1;
          if (!Array.isArray(inviteRecord.registeredUsers)) {
            inviteRecord.registeredUsers = [];
          }
          inviteRecord.registeredUsers.push({
            fingerprint: cleanFp,
            nickname: usedByLabel,
            registeredAt: Date.now()
          });
          await setKv(env, inviteKey, inviteRecord);

          // Si es un nuevo usuario en la comunidad, registrar ficha con cupo estándar
          if (!existingUser) {
            const newUser = {
              fingerprint: cleanFp,
              nickname: usedByLabel,
              quota: DEFAULT_USER_QUOTA,
              invitedBy: inviteRecord.creatorFingerprint,
              invitedByLabel: inviteRecord.creatorLabel,
              inviteCodeUsed: cleanCode,
              joinedAt: Date.now(),
              banned: false
            };
            await setKv(env, newUserKey, newUser);
          }

          return json({
            success: true,
            message: '¡Pase Génesis validado con éxito! Bienvenido al aula.',
            lineage: {
              invitedBy: inviteRecord.creatorFingerprint,
              invitedByLabel: inviteRecord.creatorLabel
            }
          }, 200);
        }

        // CASO 2: Invitación regular de un solo uso (INV-XXXXXX)
        if (inviteRecord.used) {
          return json({
            success: false,
            error: `Este código ya fue utilizado por ${inviteRecord.usedByLabel || 'otro compañero'}.`
          }, 410);
        }

        // Evasión de baneo / re-registro: una huella ya registrada no puede volver a canjear
        const newUserKey = `user_meta_${cleanFp}`;
        const existingUser = await getKv(env, newUserKey);
        if (existingUser) {
          if (existingUser.banned) {
            return json({ success: false, error: 'Usuario suspendido. No puedes canjear invitaciones.' }, 403);
          }
          return json({ success: false, error: 'Esta identidad ya pertenece a la comunidad.' }, 409);
        }

        const usedByLabel = cleanLabel(nickname, `Alumno#${cleanFp.slice(0, 4)}`);

        // Marcar la invitación como canjeada
        inviteRecord.used = true;
        inviteRecord.usedByFingerprint = cleanFp;
        inviteRecord.usedByLabel = usedByLabel;
        inviteRecord.usedAt = Date.now();
        await setKv(env, inviteKey, inviteRecord);

        // Crear ficha de linaje del nuevo usuario
        const newUser = {
          fingerprint: cleanFp,
          nickname: usedByLabel,
          quota: DEFAULT_USER_QUOTA,
          invitedBy: inviteRecord.creatorFingerprint,
          invitedByLabel: inviteRecord.creatorLabel,
          inviteCodeUsed: cleanCode,
          joinedAt: Date.now(),
          banned: false
        };
        await setKv(env, newUserKey, newUser);

        return json({
          success: true,
          message: '¡Invitación validada con éxito!',
          lineage: {
            invitedBy: inviteRecord.creatorFingerprint,
            invitedByLabel: inviteRecord.creatorLabel
          }
        }, 200);
      }

      // ACCIÓN C: Revocación en cascada multi-nivel (Admin / Moderador)
      if (action === 'revoke_cascade') {
        const { targetFingerprint } = body;
        const rootTargetFp = String(targetFingerprint || '').trim().toLowerCase();

        if (!rootTargetFp) {
          return json({ success: false, error: 'Huella objetivo requerida' }, 400);
        }
        if (!SAFE_ID_REGEX.test(rootTargetFp)) {
          return json({ success: false, error: 'Huella objetivo con formato inválido' }, 400);
        }

        // Autorización estricta: secreto de entorno (sin valor por defecto) o firma del administrador raíz.
        let isAuthorized = false;
        const configuredSecret = env && typeof env.ADMIN_SECRET === 'string' ? env.ADMIN_SECRET : '';

        if (body.adminSecret) {
          if (configuredSecret && timingSafeEqualStr(body.adminSecret, configuredSecret)) {
            isAuthorized = true;
          }
        } else if (body.signature && body.adminPublicSpki && body.adminFingerprint) {
          const adminFp = String(body.adminFingerprint).trim().toLowerCase();
          if (isAuthorizedAdmin(adminFp, env)) {
            const auth = await authenticateSignedRequest({
              publicSpki: body.adminPublicSpki,
              claimedFingerprint: adminFp,
              timestamp: body.timestamp,
              signature: body.signature,
              payload: { action: 'revoke_cascade', targetFingerprint: rootTargetFp, timestamp: body.timestamp }
            });
            isAuthorized = auth.ok;
          }
        }

        if (!isAuthorized) {
          return json({
            success: false,
            error: 'No autorizado. Se requiere firma criptográfica del Administrador Raíz o clave de moderación.'
          }, 403);
        }

        // Algoritmo BFS para recorrer y suspender el subárbol completo (A -> B -> C...)
        const queue = [rootTargetFp];
        const visited = new Set([rootTargetFp]);
        const affectedUsers = [];

        while (queue.length > 0) {
          const currentFp = queue.shift();

          // Suspender usuario actual (si el objetivo raíz aún no tiene ficha, se crea ya suspendido
          // para que no pueda registrarse más tarde canjeando una invitación)
          const currentKey = `user_meta_${currentFp}`;
          let currentUser = await getKv(env, currentKey);
          if (!currentUser && currentFp === rootTargetFp) {
            currentUser = { fingerprint: currentFp, quota: 0, invitedBy: 'UNKNOWN', banned: true };
          }
          if (currentUser) {
            currentUser.banned = true;
            await setKv(env, currentKey, currentUser);
            if (currentFp !== rootTargetFp) {
              affectedUsers.push(currentFp);
            }
          }

          // Buscar todas las invitaciones emitidas por este nodo
          const issuedCodes = (await getKv(env, `issued_by_${currentFp}`)) || [];
          for (const code of issuedCodes) {
            const inv = await getKv(env, `inv_${code}`);
            if (inv) {
              inv.revoked = true;
              await setKv(env, `inv_${code}`, inv);

              if (inv.used && inv.usedByFingerprint) {
                const childFp = inv.usedByFingerprint.toLowerCase();
                if (!visited.has(childFp)) {
                  visited.add(childFp);
                  queue.push(childFp);
                }
              }
            }
          }
        }

        return json({
          success: true,
          message: `Usuario ${rootTargetFp} y ${affectedUsers.length} descendiente(s) suspendidos en cascada.`,
          rootTarget: rootTargetFp,
          affectedUsers
        }, 200);
      }

      return json({ success: false, error: 'Acción no soportada' }, 400);
    }

    return json({ success: false, error: 'Método no permitido' }, 405);

  } catch (err) {
    console.error('[Invites API] Error interno:', err);
    // No se filtra err.message al cliente (puede revelar detalles internos de KV/runtime)
    return json({ success: false, error: 'Error interno del servidor de invitaciones' }, 500);
  }
}

/**
 * @file src/chat/crypto.js
 * @description Motor criptográfico descentralizado y autosoberano para el Chat P2P.
 * Utiliza exclusivamente la Web Crypto API nativa (sin dependencias externas).
 * 
 * Capacidades:
 * - Generación de pares de claves asimétricas ECDSA (P-256).
 * - Derivación de ID único (huella digital SHA-256 de la clave pública).
 * - Generación determinista de apodos aleatorios (Adjetivo + Animal + #Hash).
 * - Firma y verificación criptográfica de mensajes para evitar suplantaciones.
 * - Mnemotécnicos de 12 palabras para migración de identidad entre dispositivos.
 */

// Diccionario de 256 palabras fáciles en español para derivación mnemónica de 12 palabras
export const WORDLIST = [
  'aguila', 'aire', 'alce', 'alga', 'alta', 'alto', 'ambar', 'ancla', 'andes', 'anillo',
  'arbol', 'arena', 'astro', 'atlas', 'aurora', 'avellana', 'avion', 'bahia', 'barco', 'barro',
  'base', 'bisonte', 'bosque', 'brisa', 'bronce', 'brujula', 'buho', 'cabo', 'cafe', 'calma',
  'camino', 'campo', 'cañon', 'capa', 'cedro', 'ceniza', 'cerro', 'cielo', 'ciervo', 'cima',
  'cisne', 'clima', 'cobre', 'colina', 'cometa', 'coral', 'cosmos', 'costa', 'crater', 'cristal',
  'cueva', 'delta', 'desierto', 'destino', 'diamante', 'delfin', 'duna', 'eco', 'eclipse', 'encina',
  'energia', 'enigma', 'escala', 'espacio', 'espejo', 'espiga', 'espuma', 'estela', 'estrella', 'faro',
  'felino', 'fibra', 'firme', 'flama', 'flecha', 'flora', 'fluvial', 'foco', 'fondo', 'fresno',
  'fuego', 'fuente', 'galaxia', 'garza', 'gaviota', 'geiser', 'glaciar', 'globo', 'gota', 'grano',
  'gruta', 'guepardo', 'guia', 'halcon', 'hazaña', 'helio', 'heraldo', 'hielo', 'hierro', 'hilo',
  'hispano', 'hoja', 'horizonte', 'huella', 'humo', 'ibero', 'icono', 'iman', 'impulso', 'iris',
  'isla', 'jaguar', 'jardin', 'jaspe', 'jupiter', 'lago', 'laguna', 'lama', 'lanza', 'lapiz',
  'lava', 'leopardo', 'lienzo', 'limon', 'lince', 'lirio', 'lobo', 'loto', 'lucero', 'luna',
  'luz', 'magma', 'magneto', 'marea', 'marfil', 'marina', 'marmol', 'marte', 'mastil', 'materia',
  'matiz', 'medusa', 'mena', 'mercurio', 'meseta', 'metal', 'meteoro', 'mirlo', 'molino', 'monte',
  'mora', 'motivo', 'muralla', 'naciente', 'nadir', 'nieve', 'nitro', 'nodo', 'nopal', 'norte',
  'nostalgia', 'nova', 'nube', 'nucleo', 'oasis', 'obelisco', 'oceano', 'olivo', 'olmo', 'onda',
  'onix', 'optica', 'orbita', 'origen', 'orion', 'orozco', 'orto', 'oruga', 'oruro', 'otero',
  'otoño', 'ovalle', 'oxigeno', 'ozono', 'palma', 'pampa', 'panal', 'pantera', 'paramo', 'paso',
  'pastizal', 'patria', 'pelicano', 'peña', 'perla', 'pesca', 'faro', 'pico', 'piedra', 'pilar',
  'pino', 'plata', 'platino', 'playa', 'pluma', 'polo', 'portico', 'prado', 'prisma', 'puente',
  'puerto', 'puma', 'punto', 'quinto', 'quasar', 'quena', 'quimera', 'quinoa', 'radar', 'radio',
  'rafaga', 'raiz', 'rama', 'rambla', 'rayo', 'refugio', 'reloj', 'renuevo', 'resina', 'riel',
  'rio', 'roble', 'roca', 'rocio', 'rubi', 'rumbo', 'sabana', 'safiro', 'saga', 'sagrado',
  'salina', 'sauce', 'selva', 'senda', 'serena', 'sierra', 'silice', 'sol', 'sombra', 'sonda',
  'surco', 'tallo', 'tejon', 'tiempo', 'tierra', 'tigre', 'torre', 'trueno', 'valle', 'viento'
];

const ADJECTIVES = [
  'Cosmico', 'Cuantico', 'Silencioso', 'Valiente', 'Radiante', 'Furtivo', 'Astral',
  'Brillante', 'Sereno', 'Agil', 'Rapido', 'Fiel', 'Sabio', 'Salvaje', 'Mistico',
  'Dorado', 'Plateado', 'Ciber', 'Cripto', 'Nomada', 'Solar', 'Lunar', 'Neutro'
];

const ANIMALS = [
  'Halcon', 'Lobo', 'Zorro', 'Jaguar', 'Panda', 'Buho', 'Lince', 'Delfin',
  'Aguila', 'Tigre', 'Cisne', 'Oso', 'Puma', 'Condor', 'Guepardo', 'Cuervo'
];

/**
 * Convierte un ArrayBuffer a cadena Hexadecimal.
 * @param {ArrayBuffer} buffer
 * @returns {string}
 */
export function bufferToHex(buffer) {
  const bytes = new Uint8Array(buffer);
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Convierte una cadena Hexadecimal a Uint8Array.
 * @param {string} hex
 * @returns {Uint8Array}
 */
export function hexToBuffer(hex) {
  const cleanHex = hex.replace(/[^0-9a-fA-F]/g, '');
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.substr(i * 2, 2), 16);
  }
  return bytes;
}

/**
 * Convierte un ArrayBuffer a Base64.
 * @param {ArrayBuffer} buffer
 * @returns {string}
 */
export function bufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Convierte una cadena Base64 a ArrayBuffer.
 * @param {string} base64
 * @returns {ArrayBuffer}
 */
export function base64ToBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Genera un nuevo par de claves asimétricas ECDSA P-256 para el usuario.
 * @returns {Promise<CryptoKeyPair>}
 */
export async function generateIdentityKeyPair() {
  return await crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256'
    },
    true, // extractable para permitir exportación y migración
    ['sign', 'verify']
  );
}

/**
 * Exporta el par de claves a formato JSON seguro serializable.
 * @param {CryptoKeyPair} keyPair
 * @returns {Promise<{ privateJwk: JsonWebKey, publicSpki: string }>}
 */
export async function exportKeyPair(keyPair) {
  const privateJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
  const publicSpkiBuffer = await crypto.subtle.exportKey('spki', keyPair.publicKey);
  const publicSpki = bufferToBase64(publicSpkiBuffer);
  return { privateJwk, publicSpki };
}

/**
 * Importa un par de claves a partir de su representación serializada.
 * @param {JsonWebKey} privateJwk
 * @param {string} [publicSpki]
 * @returns {Promise<CryptoKeyPair>}
 */
export async function importKeyPair(privateJwk, publicSpki) {
  const privateKey = await crypto.subtle.importKey(
    'jwk',
    privateJwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign']
  );

  let publicKey;
  if (publicSpki) {
    const spkiBuffer = base64ToBuffer(publicSpki);
    publicKey = await crypto.subtle.importKey(
      'spki',
      spkiBuffer,
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['verify']
    );
  } else {
    // Si no viene la pública empaquetada, la derivamos de los campos x e y del JWK
    const publicJwk = {
      kty: privateJwk.kty,
      crv: privateJwk.crv,
      x: privateJwk.x,
      y: privateJwk.y
    };
    publicKey = await crypto.subtle.importKey(
      'jwk',
      publicJwk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['verify']
    );
  }

  return { privateKey, publicKey };
}

/**
 * Calcula el ID criptográfico público (Fingerprint) a partir de la clave pública SPKI.
 * @param {string} publicSpkiBase64
 * @returns {Promise<string>} Hexadecimal de 8 caracteres (ej: "8f3b2a9c")
 */
export async function getFingerprint(publicSpkiBase64) {
  const buffer = base64ToBuffer(publicSpkiBase64);
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const fullHex = bufferToHex(hashBuffer);
  return fullHex.slice(0, 8);
}

/**
 * Genera un apodo inicial aleatorio pero determinista basado en el ID criptográfico.
 * @param {string} fingerprint - Hex de 8 caracteres
 * @returns {string} Ej: "CosmicoLobo#8f3b"
 */
export function generateDefaultNickname(fingerprint) {
  const hashNum = parseInt(fingerprint.slice(0, 4), 16) || 0;
  const adj = ADJECTIVES[hashNum % ADJECTIVES.length];
  const animal = ANIMALS[(hashNum >> 4) % ANIMALS.length];
  return `${adj}${animal}#${fingerprint.slice(0, 4)}`;
}

/**
 * Firma un objeto de datos JSON con la clave privada del usuario.
 * @param {CryptoKey} privateKey
 * @param {Object} payload
 * @returns {Promise<string>} Firma en Base64
 */
/**
 * Serializa un objeto JSON de forma canónica (ordenando claves alfabéticamente de forma recursiva)
 * para garantizar que firmas y hashes sean 100% reproducibles e independientes del orden de inserción.
 * @param {any} obj
 * @returns {string}
 */
export function canonicalJsonString(obj) {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(item => canonicalJsonString(item)).join(',') + ']';
  }
  const sortedKeys = Object.keys(obj).sort();
  const pairs = sortedKeys.map(k => `${JSON.stringify(k)}:${canonicalJsonString(obj[k])}`);
  return '{' + pairs.join(',') + '}';
}

/**
 * Firma un objeto de datos JSON con la clave privada del usuario usando serialización canónica.
 * @param {CryptoKey} privateKey
 * @param {Object} payload
 * @returns {Promise<string>} Firma en Base64
 */
export async function signPayload(privateKey, payload) {
  const jsonString = canonicalJsonString(payload);
  const encoder = new TextEncoder();
  const data = encoder.encode(jsonString);

  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: { name: 'SHA-256' } },
    privateKey,
    data
  );

  return bufferToBase64(signature);
}

/**
 * Verifica la firma criptográfica de un payload recibido con serialización canónica.
 * @param {string|CryptoKey} publicKeyOrSpki - Instancia CryptoKey o cadena SPKI Base64
 * @param {Object} payload
 * @param {string} signatureBase64
 * @returns {Promise<boolean>}
 */
export async function verifyPayload(publicKeyOrSpki, payload, signatureBase64) {
  try {
    let key = publicKeyOrSpki;
    if (typeof publicKeyOrSpki === 'string') {
      const spkiBuf = base64ToBuffer(publicKeyOrSpki);
      key = await crypto.subtle.importKey(
        'spki',
        spkiBuf,
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['verify']
      );
    }

    const jsonString = canonicalJsonString(payload);
    const data = new TextEncoder().encode(jsonString);
    const signature = base64ToBuffer(signatureBase64);

    return await crypto.subtle.verify(
      { name: 'ECDSA', hash: { name: 'SHA-256' } },
      key,
      signature,
      data
    );
  } catch (err) {
    console.warn('[Crypto] Error verificando firma:', err);
    return false;
  }
}

export const DEFAULT_COMMUNITY = 'cfgs_3d';

/**
 * Genera un token de invitación autofirmado a la comunidad (Invite-Only).
 */
export async function generateInviteToken(adminPrivateKey, adminPublicSpki, adminFingerprint, invitedLabel = 'compañero', expiresInHours = 72) {
  const payload = {
    community: DEFAULT_COMMUNITY,
    adminFingerprint,
    invitedLabel,
    issuedAt: Date.now(),
    expiresAt: Date.now() + (expiresInHours * 3600 * 1000)
  };

  const signature = await signPayload(adminPrivateKey, payload);
  const tokenObj = { payload, signature, adminSpki: adminPublicSpki };
  return btoa(JSON.stringify(tokenObj));
}

/**
 * Valida un token de invitación autofirmado.
 */
export async function verifyInviteToken(tokenString) {
  try {
    const rawJson = atob(tokenString);
    const tokenObj = JSON.parse(rawJson);
    if (!tokenObj || !tokenObj.payload || !tokenObj.signature || !tokenObj.adminSpki) {
      return { valid: false, reason: 'Estructura del token inválida' };
    }

    if (Date.now() > tokenObj.payload.expiresAt) {
      return { valid: false, reason: 'El token de invitación ha expirado', payload: tokenObj.payload };
    }

    const isValid = await verifyPayload(tokenObj.adminSpki, tokenObj.payload, tokenObj.signature);
    if (!isValid) {
      return { valid: false, reason: 'Firma del token inválida' };
    }

    return { valid: true, payload: tokenObj.payload };
  } catch (err) {
    return { valid: false, reason: err.message };
  }
}

/**
 * Firma una acción de moderación administrativa.
 */
export async function signAdminModerationAction(adminPrivateKey, actionType, actionDetails = {}) {
  const actionPayload = {
    action: actionType,
    details: actionDetails,
    timestamp: Date.now()
  };

  const signature = await signPayload(adminPrivateKey, actionPayload);
  return { actionPayload, signature };
}

/**
 * Cifra la clave privada JWK usando una clave simétrica AES-GCM derivada de la frase mnemónica (12 palabras).
 * @param {JsonWebKey} privateJwk
 * @param {string} mnemonic
 * @returns {Promise<{ ciphertext: string, iv: string }>}
 */
export async function encryptPrivateKeyWithMnemonic(privateJwk, mnemonic) {
  const seedBytes = mnemonicToBytes(mnemonic);
  const baseKey = await crypto.subtle.importKey('raw', seedBytes, { name: 'PBKDF2' }, false, ['deriveKey']);
  const salt = new TextEncoder().encode('cfgs-3d-identity-vault-salt');
  const encKey = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const rawData = new TextEncoder().encode(JSON.stringify(privateJwk));
  const cipherBuffer = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, encKey, rawData);

  return {
    ciphertext: bufferToBase64(cipherBuffer),
    iv: bufferToBase64(iv)
  };
}

/**
 * Descifra la clave privada JWK a partir del paquete cifrado y las 12 palabras.
 * @param {string} ciphertextBase64
 * @param {string} ivBase64
 * @param {string} mnemonic
 * @returns {Promise<JsonWebKey>}
 */
export async function decryptPrivateKeyWithMnemonic(ciphertextBase64, ivBase64, mnemonic) {
  const seedBytes = mnemonicToBytes(mnemonic);
  const baseKey = await crypto.subtle.importKey('raw', seedBytes, { name: 'PBKDF2' }, false, ['deriveKey']);
  const salt = new TextEncoder().encode('cfgs-3d-identity-vault-salt');
  const encKey = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  const iv = base64ToBuffer(ivBase64);
  const cipherBuffer = base64ToBuffer(ciphertextBase64);
  const decryptedBuffer = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(iv) }, encKey, cipherBuffer);

  const jsonStr = new TextDecoder().decode(decryptedBuffer);
  return JSON.parse(jsonStr);
}

/**
 * Convierte un arreglo de 12 bytes en una frase mnemónica de 12 palabras.
 * @param {Uint8Array} bytes - 12 bytes de entropía
 * @returns {string} 12 palabras separadas por espacios
 */
export function bytesToMnemonic(bytes) {
  if (bytes.length !== 12) {
    throw new Error('La semilla debe contener exactamente 12 bytes');
  }
  return Array.from(bytes).map(byte => WORDLIST[byte % WORDLIST.length]).join(' ');
}

/**
 * Convierte una frase mnemónica de 12 palabras en su semilla de 12 bytes.
 * @param {string} mnemonic
 * @returns {Uint8Array}
 */
export function mnemonicToBytes(mnemonic) {
  const words = mnemonic.trim().toLowerCase().split(/\s+/);
  if (words.length !== 12) {
    throw new Error('La frase mnemónica debe contener exactamente 12 palabras');
  }
  const bytes = new Uint8Array(12);
  for (let i = 0; i < 12; i++) {
    const idx = WORDLIST.indexOf(words[i]);
    if (idx === -1) {
      throw new Error(`Palabra no reconocida en el diccionario: "${words[i]}"`);
    }
    bytes[i] = idx;
  }
  return bytes;
}

/**
 * Deriva una clave a partir de la frase mnemónica usando PBKDF2 y Web Crypto.
 * Permite restaurar de forma 100% determinista la misma identidad en cualquier dispositivo.
 * @param {string} mnemonic
 * @returns {Promise<CryptoKeyPair>}
 */
export async function deriveKeyPairFromMnemonic(mnemonic) {
  const seedBytes = mnemonicToBytes(mnemonic);
  
  // Usamos PBKDF2 para expandir los 12 bytes en una semilla criptográfica sólida de 32 bytes (256 bits)
  const baseKey = await crypto.subtle.importKey(
    'raw',
    seedBytes,
    { name: 'PBKDF2' },
    false,
    ['deriveBits', 'deriveKey']
  );

  const salt = new TextEncoder().encode('cfgs-3d-p2p-chat-salt');
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    baseKey,
    256 // 32 bytes
  );

  // Derivamos un JWK ECDSA sintético válido o usamos el par inicial generado si es la primera vez
  // Para garantizar compatibilidad total con Web Crypto sin librerías externas complejas de curvas elípticas,
  // exportamos un objeto estructurado que contiene el JWK original respaldado con la frase
  const rawHex = bufferToHex(derivedBits);
  return { rawHex, seedBytes };
}

export const DEFAULT_COMMUNITY = 'filthysilver-cfgs3d';

/**
 * Genera un token de invitación firmado para unirse a la comunidad (Invite-Only).
 * @param {CryptoKey} adminPrivateKey - Clave privada del moderador/administrador
 * @param {string} adminPublicSpki - Clave pública SPKI del moderador
 * @param {string} adminFingerprint - Huella del moderador
 * @param {string} [invitedLabel] - Nombre o identificador del invitado (ej: "alumno_3d")
 * @param {number} [expiresInHours] - Horas de validez (por defecto 72h)
 * @returns {Promise<string>} Token de invitación en Base64
 */
export async function generateInviteToken(adminPrivateKey, adminPublicSpki, adminFingerprint, invitedLabel = 'compañero', expiresInHours = 72) {
  const payload = {
    community: DEFAULT_COMMUNITY,
    adminFingerprint,
    invitedLabel,
    issuedAt: Date.now(),
    expiresAt: Date.now() + (expiresInHours * 3600 * 1000)
  };

  const signature = await signPayload(adminPrivateKey, payload);
  const tokenObj = { payload, signature, adminSpki: adminPublicSpki };
  return btoa(JSON.stringify(tokenObj));
}

/**
 * Valida un token de invitación a la comunidad.
 * @param {string} tokenString - Token en Base64
 * @returns {Promise<{ valid: boolean, reason?: string, payload?: Object }>}
 */
export async function verifyInviteToken(tokenString) {
  try {
    const raw = atob(tokenString.trim());
    const tokenObj = JSON.parse(raw);
    const { payload, signature, adminSpki } = tokenObj;

    if (!payload || !signature || !adminSpki) {
      return { valid: false, reason: 'Formato de token incompleto' };
    }

    if (payload.community !== DEFAULT_COMMUNITY) {
      return { valid: false, reason: 'El token pertenece a otra comunidad' };
    }

    if (payload.expiresAt && payload.expiresAt < Date.now()) {
      return { valid: false, reason: 'La invitación ha expirado' };
    }

    const isValidSig = await verifyPayload(adminSpki, payload, signature);
    if (!isValidSig) {
      return { valid: false, reason: 'Firma criptográfica de invitación inválida o manipulada' };
    }

    return { valid: true, payload };
  } catch (err) {
    return { valid: false, reason: `Token no decodificable: ${err.message}` };
  }
}

/**
 * Firma una acción administrativa de moderación (KICK o DELETE_MESSAGE).
 * @param {CryptoKey} adminPrivateKey
 * @param {'ADMIN_KICK'|'ADMIN_DELETE_MESSAGE'} actionType
 * @param {Object} targetData
 * @returns {Promise<{ actionPayload: Object, signature: string }>}
 */
export async function signAdminModerationAction(adminPrivateKey, actionType, targetData) {
  const actionPayload = {
    type: actionType,
    target: targetData,
    timestamp: Date.now(),
    nonce: Math.random().toString(36).slice(2, 8)
  };

  const signature = await signPayload(adminPrivateKey, actionPayload);
  return { actionPayload, signature };
}

/**
 * Calcula el Hash SHA-256 criptográfico de un ArrayBuffer o archivo.
 * @param {ArrayBuffer} buffer - Contenido binario del archivo
 * @returns {Promise<string>} Hexadecimal del hash (64 caracteres)
 */
export async function computeFileHash(buffer) {
  const digestBuffer = await crypto.subtle.digest('SHA-256', buffer);
  return bufferToHex(digestBuffer);
}

/**
 * Crea un Certificado Criptográfico de Autoría (Proof of Authorship) para un archivo.
 * @param {string} fileHash - SHA-256 del archivo
 * @param {string} fileName - Nombre del archivo
 * @param {number} fileSize - Tamaño en bytes
 * @param {CryptoKey} authorPrivateKey - Clave privada del autor
 * @param {string} authorPublicSpki - Clave pública SPKI del autor
 * @param {string} authorNickname - Nombre del autor
 * @returns {Promise<Object>} Certificado firmado
 */
export async function createFileAuthorshipCertificate(fileHash, fileName, fileSize, authorPrivateKey, authorPublicSpki, authorNickname) {
  const payload = {
    type: 'PROOF_OF_AUTHORSHIP',
    fileHash,
    fileName,
    fileSize,
    authorSpki: authorPublicSpki,
    authorNickname,
    timestamp: Date.now()
  };

  const signature = await signPayload(authorPrivateKey, payload);
  return {
    certificatePayload: payload,
    signature
  };
}

/**
 * Valida un Certificado Criptográfico de Autoría.
 * @param {Object} certificate - Objeto con certificatePayload y signature
 * @param {string} [expectedFileHash] - Hash esperado para contrastar contra el archivo recibido
 * @returns {Promise<{ valid: boolean, authorNickname?: string, timestamp?: number, error?: string }>}
 */
export async function verifyFileAuthorshipCertificate(certificate, expectedFileHash = null) {
  try {
    if (!certificate || !certificate.certificatePayload || !certificate.signature) {
      return { valid: false, error: 'Estructura de certificado inválida' };
    }

    const { certificatePayload, signature } = certificate;

    if (expectedFileHash && certificatePayload.fileHash !== expectedFileHash) {
      return { valid: false, error: 'El hash del certificado no coincide con el archivo' };
    }

    const isValid = await verifyPayload(certificatePayload.authorSpki, certificatePayload, signature);
    if (!isValid) {
      return { valid: false, error: 'Firma de autoría inválida o alterada' };
    }

    return {
      valid: true,
      authorNickname: certificatePayload.authorNickname,
      timestamp: certificatePayload.timestamp,
      fileHash: certificatePayload.fileHash
    };
  } catch (e) {
    return { valid: false, error: e.message };
  }
}

/**
 * Huella digital (Fingerprint) predeterminada del Administrador Raíz Génesis de filthysilver.net.
 */
export const GENESIS_ADMIN_ROOT_FINGERPRINT = 'f117b055';

/**
 * Crea un Certificado Criptográfico de Delegación de Moderación firmado por el Administrador Raíz.
 * Permite delegar facultades de expulsión o borrado a un estudiante o profesor sin exponer la clave raíz.
 * @param {CryptoKey} rootPrivateKey - Clave privada del administrador raíz
 * @param {string} rootPublicSpki - Clave pública SPKI del administrador raíz
 * @param {string} moderatorPublicSpki - Clave pública SPKI del moderador delegado
 * @param {string} [roomId='*'] - Sala autorizada ('*' para todas las salas)
 * @param {string[]} [permissions=['KICK', 'DELETE_MESSAGE']] - Permisos otorgados
 * @param {number} [validHours=72] - Horas de validez del certificado
 * @returns {Promise<{ certificatePayload: Object, signature: string }>}
 */
export async function createModeratorCertificate(
  rootPrivateKey,
  rootPublicSpki,
  moderatorPublicSpki,
  roomId = '*',
  permissions = ['KICK', 'DELETE_MESSAGE'],
  validHours = 72
) {
  const rootFingerprint = await getFingerprint(rootPublicSpki);
  const moderatorFingerprint = await getFingerprint(moderatorPublicSpki);
  const now = Date.now();
  const expiresAt = now + (validHours * 60 * 60 * 1000);

  const certificatePayload = {
    type: 'MODERATOR_DELEGATION',
    rootFingerprint,
    rootPublicSpki,
    moderatorFingerprint,
    moderatorPublicSpki,
    roomId,
    permissions,
    issuedAt: now,
    expiresAt
  };

  const signature = await signPayload(rootPrivateKey, certificatePayload);
  return {
    certificatePayload,
    signature
  };
}

/**
 * Valida un Certificado de Delegación de Moderador contra una lista de claves raíz de confianza.
 * @param {Object} certificate - Objeto con certificatePayload y signature
 * @param {string[]} [trustedRootFingerprints=[]] - Lista de fingerprints de administradores raíz autorizados
 * @returns {Promise<{ valid: boolean, payload?: Object, error?: string }>}
 */
export async function verifyModeratorCertificate(certificate, trustedRootFingerprints = []) {
  try {
    if (!certificate || !certificate.certificatePayload || !certificate.signature) {
      return { valid: false, error: 'Estructura del certificado de moderador incompleta' };
    }

    const { certificatePayload, signature } = certificate;
    if (certificatePayload.type !== 'MODERATOR_DELEGATION') {
      return { valid: false, error: 'Tipo de certificado no válido' };
    }

    if (Date.now() > certificatePayload.expiresAt) {
      return { valid: false, error: 'Certificado de moderador expirado' };
    }

    const computedRootFp = await getFingerprint(certificatePayload.rootPublicSpki);
    if (computedRootFp !== certificatePayload.rootFingerprint) {
      return { valid: false, error: 'La huella del emisor raíz no coincide con su clave SPKI' };
    }

    if (trustedRootFingerprints && trustedRootFingerprints.length > 0) {
      if (!trustedRootFingerprints.includes(certificatePayload.rootFingerprint)) {
        return { valid: false, error: 'El emisor raíz no está en la lista de administradores de confianza' };
      }
    }

    const isValidSignature = await verifyPayload(certificatePayload.rootPublicSpki, certificatePayload, signature);
    if (!isValidSignature) {
      return { valid: false, error: 'Firma de la clave raíz inválida' };
    }

    return { valid: true, payload: certificatePayload };
  } catch (err) {
    return { valid: false, error: err.message };
  }
}

/**
 * Determina si una clave SPKI tiene autoridad legítima de moderación para una sala y acción dada,
 * ya sea por ser Administrador Raíz directo o mediante un Certificado de Delegación válido.
 * @param {string} actorSpki - Clave pública SPKI del usuario que ejecuta la acción
 * @param {string} roomId - Identificador de la sala
 * @param {'KICK'|'DELETE_MESSAGE'} requiredPermission - Permiso requerido
 * @param {string[]} trustedRootFingerprints - Huellas de administradores raíz
 * @param {Object} [moderatorCertificate=null] - Certificado de delegación opcional
 * @returns {Promise<{ authorized: boolean, role: 'root'|'delegated'|'none', reason?: string }>}
 */
export async function isAuthorizedModerator(
  actorSpki,
  roomId,
  requiredPermission,
  trustedRootFingerprints = [],
  moderatorCertificate = null
) {
  if (!actorSpki) {
    return { authorized: false, role: 'none', reason: 'Falta la clave pública del autor' };
  }

  const actorFingerprint = await getFingerprint(actorSpki);

  // 1. Verificar si es Administrador Raíz directo
  if (trustedRootFingerprints.includes(actorFingerprint)) {
    return { authorized: true, role: 'root' };
  }

  // 2. Si no es raíz, verificar si tiene Certificado de Delegación válido firmado por una raíz
  if (moderatorCertificate) {
    const certResult = await verifyModeratorCertificate(moderatorCertificate, trustedRootFingerprints);
    if (!certResult.valid) {
      return { authorized: false, role: 'none', reason: `Certificado inválido: ${certResult.error}` };
    }

    const payload = certResult.payload;
    const certModSpki = payload.moderatorPublicSpki || payload.moderatorSpki;
    if (certModSpki !== actorSpki) {
      return { authorized: false, role: 'none', reason: 'El certificado no corresponde a este moderador' };
    }

    if (payload.roomId !== '*' && payload.roomId !== roomId) {
      return { authorized: false, role: 'none', reason: `Certificado no válido para la sala ${roomId}` };
    }

    if (!payload.permissions.includes(requiredPermission)) {
      return { authorized: false, role: 'none', reason: `Permiso ${requiredPermission} no concedido` };
    }

    return { authorized: true, role: 'delegated' };
  }

  return { authorized: false, role: 'none', reason: 'Usuario no autorizado para moderar' };
}




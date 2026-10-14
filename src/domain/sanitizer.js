/**
 * @file sanitizer.js
 * @description Utilidades de sanitización para prevenir vulnerabilidades XSS e inyecciones de código.
 */

/**
 * Escapa caracteres HTML para prevenir inyecciones XSS en contenido introducido por usuarios o fuentes externas.
 * @param {string} str
 * @returns {string} Cadena segura con entidades HTML escapadas.
 */
export function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Sanitiza una URL para prevenir inyecciones XSS y ataques de protocolo (ej. javascript:, data:, vbscript:).
 * Solo permite protocolos estrictamente seguros http:// y https://.
 * @param {string} url
 * @returns {string} URL segura o cadena vacía si no es válida.
 */
export function sanitizeUrl(url) {
  if (!url || typeof url !== 'string') return '';
  const trimmed = url.trim();
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
      return parsed.href.replace(/"/g, '&quot;').replace(/'/g, '&#039;');
    }
  } catch {
    // Si la URL no es válida, se descarta
  }
  return '';
}

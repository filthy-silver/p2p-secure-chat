import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { sanitizeUrl, escapeHtml } from '../src/domain/sanitizer.js';

describe('sanitizer.js · Sanitización de URLs contra XSS', () => {

  it('permite URLs válidas bajo protocolo HTTPS', () => {
    const validHttps = 'https://aules.edu.gva.es/fp/mod/assign/view.php?id=12345';
    assert.equal(sanitizeUrl(validHttps), validHttps);
  });

  it('permite URLs válidas bajo protocolo HTTP', () => {
    const validHttp = 'http://ejemplo.educacion.es/recurso';
    assert.equal(sanitizeUrl(validHttp), validHttp);
  });

  it('bloquea inyecciones de script con esquema javascript:', () => {
    assert.equal(sanitizeUrl('javascript:alert(document.cookie)'), '');
    assert.equal(sanitizeUrl('JAVASCRIPT:alert(1)'), '');
    assert.equal(sanitizeUrl('javascript:void(0)'), '');
  });

  it('bloquea inyecciones de datos con esquema data:', () => {
    assert.equal(sanitizeUrl('data:text/html,<script>alert(1)</script>'), '');
  });

  it('bloquea esquemas vbscript: y file:', () => {
    assert.equal(sanitizeUrl('vbscript:msgbox(1)'), '');
    assert.equal(sanitizeUrl('file:///C:/Windows/win.ini'), '');
  });

  it('escapa comillas dobles y simples para evitar escape de atributos HTML', () => {
    const malicious = 'https://aules.edu.gva.es/test" onclick="alert(1)';
    const sanitized = sanitizeUrl(malicious);
    assert.ok(!sanitized.includes('"'));
  });

  it('devuelve cadena vacía ante valores nulos, indefinidos o vacíos', () => {
    assert.equal(sanitizeUrl(null), '');
    assert.equal(sanitizeUrl(undefined), '');
    assert.equal(sanitizeUrl(''), '');
    assert.equal(sanitizeUrl('   '), '');
  });

  it('escapa entidades HTML con escapeHtml', () => {
    assert.equal(escapeHtml('<script>alert("xss")</script>'), '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;');
    assert.equal(escapeHtml('Tom & Jerry'), 'Tom &amp; Jerry');
    assert.equal(escapeHtml(null), '');
  });

});

/**
 * @file tests/chat-widget.test.js
 * @description Pruebas unitarias para el controlador del Widget Flotante de Chat P2P (chat-widget.js).
 */

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { formatBytes, renderWidgetHtml, WIDGET_OFFICIAL_ROOMS } from '../src/chat/chat-widget.js';

describe('chat-widget.js · Utilidades y Renderizado HTML', () => {

  describe('formatBytes()', () => {
    it('devuelve "0 B" ante valores nulos, negativos o cero', () => {
      assert.equal(formatBytes(0), '0 B');
      assert.equal(formatBytes(-10), '0 B');
      assert.equal(formatBytes(null), '0 B');
      assert.equal(formatBytes(undefined), '0 B');
    });

    it('formatea correctamente bytes inferiores a 1 KB', () => {
      assert.equal(formatBytes(512), '512 B');
      assert.equal(formatBytes(999), '999 B');
    });

    it('formatea correctamente Kilobytes y Megabytes', () => {
      assert.equal(formatBytes(1024), '1 KB');
      assert.equal(formatBytes(1536), '1.5 KB');
      assert.equal(formatBytes(1048576), '1 MB');
      assert.equal(formatBytes(2621440), '2.5 MB');
    });

    it('formatea correctamente Gigabytes', () => {
      assert.equal(formatBytes(1073741824), '1 GB');
      assert.equal(formatBytes(5368709120), '5 GB');
    });
  });

  describe('renderWidgetHtml()', () => {
    it('genera la estructura HTML del widget con todos sus componentes clave', () => {
      const html = renderWidgetHtml('general');

      assert.ok(html.includes('id="p2p-widget-window"'), 'Debe contener la ventana flotante');
      assert.ok(html.includes('id="p2p-widget-fab"'), 'Debe contener el botón flotante FAB');
      assert.ok(html.includes('id="p2p-widget-feed"'), 'Debe contener el feed de mensajes');
      assert.ok(html.includes('id="p2p-widget-form"'), 'Debe contener el formulario de entrada');
      assert.ok(html.includes('id="p2p-widget-btn-attach"'), 'Debe contener el botón de adjuntar archivos');
      assert.ok(html.includes('id="p2p-widget-status-dot"'), 'Debe contener el indicador de estado');
      assert.ok(html.includes('id="p2p-widget-badge"'), 'Debe contener el badge numérico');
    });

    it('marca como seleccionada la sala por defecto indicada', () => {
      const htmlGeneral = renderWidgetHtml('general');
      assert.ok(htmlGeneral.includes('value="general" selected'), 'general debe estar seleccionado');

      const htmlDudas = renderWidgetHtml('dudas-3d');
      assert.ok(htmlDudas.includes('value="dudas-3d" selected'), 'dudas-3d debe estar seleccionado');
      assert.ok(!htmlDudas.includes('value="general" selected'), 'general no debe estar seleccionado');
    });

    it('incluye todas las salas oficiales definidas en WIDGET_OFFICIAL_ROOMS', () => {
      const html = renderWidgetHtml('general');
      for (const room of WIDGET_OFFICIAL_ROOMS) {
        assert.ok(html.includes(`value="${room.id}"`), `Debe incluir la opción para la sala ${room.id}`);
        assert.ok(html.includes(room.name), `Debe mostrar el nombre ${room.name}`);
      }
    });

    it('incorpora atributos esenciales de accesibilidad WAI-ARIA', () => {
      const html = renderWidgetHtml('general');
      assert.ok(html.includes('role="dialog"'), 'Debe definir role="dialog"');
      assert.ok(html.includes('aria-label="Chat P2P"'), 'Debe incluir aria-label en la ventana');
      assert.ok(html.includes('aria-expanded="false"'), 'El FAB debe arrancar con aria-expanded="false"');
      assert.ok(html.includes('aria-live="polite"'), 'El feed debe ser un área aria-live="polite"');
    });
  });

});

describe('chat-widget.js · Ciclo de Vida y Comportamiento en Entorno Mock DOM', () => {

  let originalDocument;
  let originalWindow;
  let mockDomTree;
  let eventListeners;

  beforeEach(() => {
    originalDocument = globalThis.document;
    originalWindow = globalThis.window;

    eventListeners = new Map();
    mockDomTree = new Map();

    const createMockElement = (tag, id = '') => {
      const el = {
        tagName: tag.toUpperCase(),
        id,
        className: '',
        attributes: new Map(),
        children: [],
        innerHTML: '',
        style: {},
        classList: {
          classes: new Set(),
          add(c) { this.classes.add(c); el.className = Array.from(this.classes).join(' '); },
          remove(c) { this.classes.delete(c); el.className = Array.from(this.classes).join(' '); },
          contains(c) { return this.classes.has(c); }
        },
        setAttribute(k, v) { this.attributes.set(k, String(v)); },
        getAttribute(k) { return this.attributes.get(k) || null; },
        appendChild(child) { this.children.push(child); return child; },
        remove() {
          if (mockDomTree.has(this.id)) mockDomTree.delete(this.id);
        },
        querySelector(selector) {
          if (selector.startsWith('#')) {
            const searchId = selector.slice(1);
            if (this.id === searchId) return this;
            for (const child of this.children) {
              if (child.id === searchId) return child;
              const found = child.querySelector?.(selector);
              if (found) return found;
            }
          }
          // Soporte mínimo de selectores para los tests
          return createMockElement('div');
        },
        addEventListener(event, handler) {
          if (!eventListeners.has(event)) eventListeners.set(event, []);
          eventListeners.get(event).push(handler);
        },
        removeEventListener(event, handler) {
          if (eventListeners.has(event)) {
            const list = eventListeners.get(event).filter(h => h !== handler);
            eventListeners.set(event, list);
          }
        },
        focus() {}
      };
      if (id) mockDomTree.set(id, el);
      return el;
    };

    const mockBody = createMockElement('body');
    const mockHead = createMockElement('head');

    globalThis.document = {
      body: mockBody,
      head: mockHead,
      createElement: (tag) => createMockElement(tag),
      getElementById: (id) => mockDomTree.get(id) || null,
      addEventListener: (event, handler) => {
        if (!eventListeners.has(event)) eventListeners.set(event, []);
        eventListeners.get(event).push(handler);
      },
      removeEventListener: (event, handler) => {
        if (eventListeners.has(event)) {
          const list = eventListeners.get(event).filter(h => h !== handler);
          eventListeners.set(event, list);
        }
      }
    };

    globalThis.window = {
      open: () => {},
      __p2pChatWidget: null
    };
  });

  afterEach(() => {
    globalThis.document = originalDocument;
    globalThis.window = originalWindow;
  });

  it('falla con mensaje explicativo si se invoca sin document/window', async () => {
    globalThis.document = undefined;
    globalThis.window = undefined;

    const { initChatWidget } = await import('../src/chat/chat-widget.js');
    await assert.rejects(
      async () => { await initChatWidget(); },
      /El widget requiere un entorno de navegador con DOM/
    );
  });

});

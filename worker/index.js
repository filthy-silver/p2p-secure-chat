/**
 * @file worker/index.js
 * @description Cloudflare Worker para el Chat P2P Descentralizado (p2p-secure-chat).
 */

import { onRequest as handleChatInvitesRequest } from '../functions/api/chat-invites.js';
import { onRequest as handleChatVaultRequest } from '../functions/api/chat-vault.js';
import { onRequest as handleChatSignalRequest } from '../functions/api/chat-signal.js';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Endpoint del Árbol de Invitaciones y Trazabilidad
    if (url.pathname === '/api/chat/invites' || url.pathname.startsWith('/api/chat/invites/')) {
      return handleChatInvitesRequest({ request, env, ctx });
    }

    // Endpoint de Bóveda Criptográfica Zero-Knowledge
    if (url.pathname === '/api/chat/vault' || url.pathname.startsWith('/api/chat/vault/')) {
      return handleChatVaultRequest({ request, env, ctx });
    }

    // Endpoint de Señalización WebRTC (WebSockets y HTTP)
    if (url.pathname === '/api/chat/signal' || url.pathname.startsWith('/api/chat/signal/')) {
      return handleChatSignalRequest({ request, env, ctx });
    }

    // Health check
    if (url.pathname === '/api/health') {
      return new Response(JSON.stringify({ status: 'ok', service: 'p2p-secure-chat', time: new Date().toISOString() }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Bloqueo de rutas y archivos sensibles
    const SENSITIVE_PATTERNS = [
      /^\/\.dev\.vars/i,
      /^\/\.git/i,
      /^\/wrangler\.toml/i,
      /^\/package\.json/i,
      /^\/_headers/i,
      /^\/worker\//i,
      /^\/functions\//i
    ];
    if (SENSITIVE_PATTERNS.some(p => p.test(url.pathname))) {
      return new Response('Not Found', { status: 404 });
    }

    // Despacho de assets estáticos con cabeceras de seguridad CSP
    if (env.ASSETS) {
      let targetReq = request;
      if (url.pathname === '/chat' || url.pathname.startsWith('/chat/')) {
        targetReq = new Request(new URL('/index.html', request.url), request);
      }
      const response = await env.ASSETS.fetch(targetReq);
      const headers = new Headers(response.headers);
      headers.set('X-Content-Type-Options', 'nosniff');
      headers.set('X-Frame-Options', 'DENY');
      headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
      headers.set('Content-Security-Policy', "default-src 'self'; connect-src 'self' wss: https: stun:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; object-src 'none';");

      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers
      });
    }

    return new Response('Not Found', { status: 404 });
  }
};

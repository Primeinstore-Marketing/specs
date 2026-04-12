/**
 * Primedia Instore Specs — Cloudflare Worker
 * Routes:
 *   GET  /           → return specs from KV (public)
 *   PUT  /           → update specs in KV (JWT required)
 *   POST /api/login  → authenticate, return JWT
 *   POST /api/change-password → change password (JWT required)
 *   OPTIONS *        → CORS preflight
 *
 * KV keys:
 *   specs-data         existing specs JSON
 *   auth:password_hash saltHex:hashHex (PBKDF2-SHA256, 100k iterations)
 *   auth:jwt_secret    32-byte hex secret for HMAC-SHA256 JWT
 */

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,PUT,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
};

function json(body, status = 200, extra = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS, ...extra },
  });
}

/* ── Crypto helpers ─────────────────────────────────────────── */

function hexToBytes(hex) {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < arr.length; i++) arr[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return arr;
}

function bytesToHex(buf) {
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function randomHex(bytes) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return bytesToHex(arr);
}

async function hashPassword(password, saltHex) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: hexToBytes(saltHex), iterations: 100000, hash: 'SHA-256' },
    keyMaterial, 256
  );
  return bytesToHex(bits);
}

async function verifyPassword(password, stored) {
  const [saltHex, hashHex] = stored.split(':');
  const derived = await hashPassword(password, saltHex);
  // constant-time compare
  if (derived.length !== hashHex.length) return false;
  let diff = 0;
  for (let i = 0; i < derived.length; i++) diff |= derived.charCodeAt(i) ^ hashHex.charCodeAt(i);
  return diff === 0;
}

/* ── JWT (HMAC-SHA256, 8-hour expiry) ───────────────────────── */

function b64url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecode(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}

async function signJwt(payload, secretHex) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const enc = new TextEncoder();
  const hp = b64url(enc.encode(JSON.stringify(header))) + '.' + b64url(enc.encode(JSON.stringify(payload)));
  const key = await crypto.subtle.importKey('raw', hexToBytes(secretHex), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(hp));
  return hp + '.' + b64url(sig);
}

async function verifyJwt(token, secretHex) {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', hexToBytes(secretHex), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify('HMAC', key, b64urlDecode(parts[2]), enc.encode(parts[0] + '.' + parts[1]));
  if (!ok) return null;
  const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(parts[1])));
  if (payload.exp < Math.floor(Date.now() / 1000)) return null; // expired
  return payload;
}

/* ── KV helpers ─────────────────────────────────────────────── */

async function getOrCreateSecret(KV) {
  let secret = await KV.get('auth:jwt_secret');
  if (!secret) {
    secret = await randomHex(32);
    await KV.put('auth:jwt_secret', secret);
  }
  return secret;
}

async function getOrCreatePasswordHash(KV) {
  let stored = await KV.get('auth:password_hash');
  if (!stored) {
    // First run: hash default password and store it
    const salt = await randomHex(16);
    const hash = await hashPassword('primedia2025', salt);
    stored = salt + ':' + hash;
    await KV.put('auth:password_hash', stored);
  }
  return stored;
}

/* ── Auth middleware ────────────────────────────────────────── */

async function requireAuth(request, KV) {
  const auth = request.headers.get('Authorization') || '';
  if (!auth.startsWith('Bearer ')) return null;
  const token = auth.slice(7);
  const secret = await KV.get('auth:jwt_secret');
  if (!secret) return null;
  return verifyJwt(token, secret);
}

/* ── Main handler ───────────────────────────────────────────── */

export default {
  async fetch(request, env) {
    const KV = env.SPECS_DATA;
    const url = new URL(request.url);
    const method = request.method.toUpperCase();

    // CORS preflight
    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS });
    }

    /* GET / — return specs (public) */
    if (method === 'GET' && url.pathname === '/') {
      const data = await KV.get('specs-data');
      return new Response(data || '{}', {
        headers: { 'Content-Type': 'application/json', ...CORS },
      });
    }

    /* PUT / — update specs (JWT required) */
    if (method === 'PUT' && url.pathname === '/') {
      const payload = await requireAuth(request, KV);
      if (!payload) return json({ error: 'Unauthorized' }, 401);
      const body = await request.text();
      await KV.put('specs-data', body);
      return json({ ok: true });
    }

    /* POST /api/login */
    if (method === 'POST' && url.pathname === '/api/login') {
      let body;
      try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
      const { username, password } = body || {};
      if (username !== 'admin' || !password) return json({ error: 'Invalid credentials' }, 401);

      const stored = await getOrCreatePasswordHash(KV);
      const valid = await verifyPassword(password, stored);
      if (!valid) return json({ error: 'Invalid credentials' }, 401);

      const secret = await getOrCreateSecret(KV);
      const exp = Math.floor(Date.now() / 1000) + 8 * 3600; // 8 hours
      const token = await signJwt({ sub: 'admin', exp }, secret);
      return json({ token });
    }

    /* POST /api/change-password */
    if (method === 'POST' && url.pathname === '/api/change-password') {
      const authPayload = await requireAuth(request, KV);
      if (!authPayload) return json({ error: 'Unauthorized' }, 401);

      let body;
      try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
      const { currentPassword, newPassword } = body || {};
      if (!currentPassword || !newPassword) return json({ error: 'Missing fields' }, 400);
      if (newPassword.length < 6) return json({ error: 'Password must be at least 6 characters' }, 400);

      const stored = await getOrCreatePasswordHash(KV);
      const valid = await verifyPassword(currentPassword, stored);
      if (!valid) return json({ error: 'Current password is incorrect' }, 401);

      const salt = await randomHex(16);
      const hash = await hashPassword(newPassword, salt);
      await KV.put('auth:password_hash', salt + ':' + hash);
      return json({ ok: true });
    }

    return json({ error: 'Not found' }, 404);
  },
};

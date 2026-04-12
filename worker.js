/**
 * Primedia Instore Specs — Cloudflare Worker
 *
 * KV keys:
 *   user:{username}   JSON {passwordHash, role, createdAt}
 *   auth:jwt_secret   32-byte hex
 *   data              existing specs JSON
 *   auth:password_hash  legacy → auto-migrated to user:admin on first use
 */

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,PUT,POST,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
};

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS },
  });
}

/* ── Crypto ─────────────────────────────────────────────────── */

function hexToBytes(hex) {
  const a = new Uint8Array(hex.length / 2);
  for (let i = 0; i < a.length; i++) a[i] = parseInt(hex.slice(i*2, i*2+2), 16);
  return a;
}
function bytesToHex(buf) {
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2,'0')).join('');
}
async function randomHex(n) {
  const a = new Uint8Array(n); crypto.getRandomValues(a); return bytesToHex(a);
}
async function hashPassword(password, saltHex) {
  const enc = new TextEncoder();
  const km = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name:'PBKDF2', salt:hexToBytes(saltHex), iterations:100000, hash:'SHA-256' }, km, 256
  );
  return bytesToHex(bits);
}
async function verifyPassword(password, stored) {
  const [saltHex, hashHex] = stored.split(':');
  const derived = await hashPassword(password, saltHex);
  if (derived.length !== hashHex.length) return false;
  let diff = 0;
  for (let i = 0; i < derived.length; i++) diff |= derived.charCodeAt(i) ^ hashHex.charCodeAt(i);
  return diff === 0;
}

/* ── JWT ────────────────────────────────────────────────────── */

function b64url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function b64urlDecode(s) {
  s = s.replace(/-/g,'+').replace(/_/g,'/');
  while (s.length%4) s+='=';
  return Uint8Array.from(atob(s), c=>c.charCodeAt(0));
}
async function signJwt(payload, secretHex) {
  const enc = new TextEncoder();
  const header = { alg:'HS256', typ:'JWT' };
  const hp = b64url(enc.encode(JSON.stringify(header))) + '.' + b64url(enc.encode(JSON.stringify(payload)));
  const key = await crypto.subtle.importKey('raw', hexToBytes(secretHex), {name:'HMAC',hash:'SHA-256'}, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(hp));
  return hp + '.' + b64url(sig);
}
async function verifyJwt(token, secretHex) {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', hexToBytes(secretHex), {name:'HMAC',hash:'SHA-256'}, false, ['verify']);
  const ok = await crypto.subtle.verify('HMAC', key, b64urlDecode(parts[2]), enc.encode(parts[0]+'.'+parts[1]));
  if (!ok) return null;
  const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(parts[1])));
  if (payload.exp < Math.floor(Date.now()/1000)) return null;
  return payload;
}

/* ── KV helpers ─────────────────────────────────────────────── */

async function getSecret(KV) {
  let s = await KV.get('auth:jwt_secret');
  if (!s) { s = await randomHex(32); await KV.put('auth:jwt_secret', s); }
  return s;
}
async function getUser(KV, username) {
  const raw = await KV.get('user:' + username);
  return raw ? JSON.parse(raw) : null;
}
async function putUser(KV, username, data) {
  await KV.put('user:' + username, JSON.stringify(data));
}
async function listUsers(KV) {
  const list = await KV.list({ prefix: 'user:' });
  const users = [];
  for (const key of list.keys) {
    const raw = await KV.get(key.name);
    if (raw) {
      const u = JSON.parse(raw);
      users.push({ username: key.name.replace('user:', ''), role: u.role, createdAt: u.createdAt });
    }
  }
  return users;
}
async function ensureAdminUser(KV) {
  const existing = await getUser(KV, 'admin');
  if (existing) return existing;
  const legacyHash = await KV.get('auth:password_hash');
  let passwordHash;
  if (legacyHash) {
    passwordHash = legacyHash;
  } else {
    const salt = await randomHex(16);
    const hash = await hashPassword('primedia2025', salt);
    passwordHash = salt + ':' + hash;
  }
  const adminUser = { passwordHash, role: 'admin', createdAt: Date.now() };
  await putUser(KV, 'admin', adminUser);
  return adminUser;
}

/* ── Auth middleware ────────────────────────────────────────── */

async function requireAuth(request, KV, requireAdmin = false) {
  const auth = request.headers.get('Authorization') || '';
  if (!auth.startsWith('Bearer ')) return null;
  const token = auth.slice(7);
  const secret = await KV.get('auth:jwt_secret');
  if (!secret) return null;
  const payload = await verifyJwt(token, secret);
  if (!payload) return null;
  if (requireAdmin && payload.role !== 'admin') return null;
  return payload;
}

/* ── Main handler ───────────────────────────────────────────── */

export default {
  async fetch(request, env) {
    const KV = env.SPECS_DATA;
    const url = new URL(request.url);
    const method = request.method.toUpperCase();
    const path = url.pathname;

    if (method === 'OPTIONS') return new Response(null, { status:204, headers:CORS });

    /* GET / — public spec data */
    if (method === 'GET' && path === '/') {
      const data = await KV.get('data');
      return new Response(data || '{}', { headers: {'Content-Type':'application/json',...CORS} });
    }

    /* PUT / — save spec data (any authenticated user) */
    if (method === 'PUT' && path === '/') {
      const auth = await requireAuth(request, KV);
      if (!auth) return json({ error: 'Unauthorized' }, 401);
      const body = await request.text();
      await KV.put('data', body);
      return json({ ok: true });
    }

    /* POST /api/login */
    if (method === 'POST' && path === '/api/login') {
      let body; try { body = await request.json(); } catch { return json({ error:'Invalid JSON' }, 400); }
      const { username, password } = body || {};
      if (!username || !password) return json({ error:'Missing credentials' }, 400);
      await ensureAdminUser(KV);
      const user = await getUser(KV, username.toLowerCase().trim());
      if (!user) return json({ error:'Invalid username or password' }, 401);
      const valid = await verifyPassword(password, user.passwordHash);
      if (!valid) return json({ error:'Invalid username or password' }, 401);
      const secret = await getSecret(KV);
      const exp = Math.floor(Date.now()/1000) + 8*3600;
      const token = await signJwt({ sub: username.toLowerCase().trim(), role: user.role, exp }, secret);
      return json({ token, role: user.role });
    }

    /* POST /api/change-password — JWT required */
    if (method === 'POST' && path === '/api/change-password') {
      const auth = await requireAuth(request, KV);
      if (!auth) return json({ error:'Unauthorized' }, 401);
      let body; try { body = await request.json(); } catch { return json({ error:'Invalid JSON' }, 400); }
      const { currentPassword, newPassword } = body || {};
      if (!currentPassword || !newPassword) return json({ error:'Missing fields' }, 400);
      if (newPassword.length < 6) return json({ error:'Password must be at least 6 characters' }, 400);
      const user = await getUser(KV, auth.sub);
      if (!user) return json({ error:'User not found' }, 404);
      const valid = await verifyPassword(currentPassword, user.passwordHash);
      if (!valid) return json({ error:'Current password is incorrect' }, 401);
      const salt = await randomHex(16);
      const hash = await hashPassword(newPassword, salt);
      user.passwordHash = salt + ':' + hash;
      await putUser(KV, auth.sub, user);
      return json({ ok: true });
    }

    /* POST /api/users — create user (admin only) */
    if (method === 'POST' && path === '/api/users') {
      const auth = await requireAuth(request, KV, true);
      if (!auth) return json({ error:'Unauthorized' }, 401);
      let body; try { body = await request.json(); } catch { return json({ error:'Invalid JSON' }, 400); }
      const { username, password, role } = body || {};
      if (!username || !password) return json({ error:'Username and password required' }, 400);
      if (password.length < 6) return json({ error:'Password must be at least 6 characters' }, 400);
      const uname = username.toLowerCase().trim().replace(/[^a-z0-9_]/g, '');
      if (!uname) return json({ error:'Invalid username' }, 400);
      const existing = await getUser(KV, uname);
      if (existing) return json({ error:'Username already exists' }, 409);
      const salt = await randomHex(16);
      const hash = await hashPassword(password, salt);
      await putUser(KV, uname, {
        passwordHash: salt + ':' + hash,
        role: role === 'admin' ? 'admin' : 'viewer',
        createdAt: Date.now()
      });
      return json({ ok: true, username: uname });
    }

    /* GET /api/users — list users (admin only) */
    if (method === 'GET' && path === '/api/users') {
      const auth = await requireAuth(request, KV, true);
      if (!auth) return json({ error:'Unauthorized' }, 401);
      const users = await listUsers(KV);
      return json({ users });
    }

    /* DELETE /api/users/:username — remove user (admin only) */
    if (method === 'DELETE' && path.startsWith('/api/users/')) {
      const auth = await requireAuth(request, KV, true);
      if (!auth) return json({ error:'Unauthorized' }, 401);
      const target = path.replace('/api/users/', '').toLowerCase();
      if (target === auth.sub) return json({ error:'Cannot delete your own account' }, 400);
      if (target === 'admin') return json({ error:'Cannot delete the primary admin account' }, 400);
      const user = await getUser(KV, target);
      if (!user) return json({ error:'User not found' }, 404);
      await KV.delete('user:' + target);
      return json({ ok: true });
    }

    return json({ error:'Not found' }, 404);
  },
};

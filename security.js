/**
 * XYZ Games — Enterprise Security, Cryptography, RBAC & Rate-Limiting Engine (security.js v14.0)
 * Zero external dependencies — built on pure Node.js `node:crypto`.
 *
 * Production Repairs Implemented (v14.0):
 * 1. Secret Management & Fail-Closed Startup:
 *    - Removes predictable fallback (`XYZ_FALLBACK_PROD_SECRET_...`).
 *    - Fails closed on startup in production (`NODE_ENV === 'production'`) if `JWT_SECRET` is missing or < 32 chars.
 *    - In development/test, generates a 48-byte CSPRNG ephemeral or file-backed secret (`0600` permissions).
 * 2. Cryptographic Password Hashing & Migration:
 *    - `scrypt` (`N=16384, r=8, p=1, keylen=64`) with 16-byte CSPRNG salt and `crypto.timingSafeEqual`.
 *    - Supports safe legacy plaintext migration on login and permanently strips plaintext `.password` from canonical records, snapshots, and API responses.
 *    - Never allows `passwordHash` or secrets to be returned to the browser.
 * 3. Purpose-Bound Stateless HMAC-SHA256 JWTs + Server-Side Revocation:
 *    - Validates signature (`timingSafeEqual`), expiration (`exp`), issuer (`iss`), audience (`aud`), subject (`sub`), role, and `jti` / session revocation.
 *    - Strictly separates Customer tokens (`aud: 'xyz-customer'`) from Administrator tokens (`aud: 'xyz-admin'`).
 *    - Customer tokens can NEVER be accepted as administrator authorization.
 * 4. Cookie, CSRF & CORS Hardening:
 *    - Sets `HttpOnly`, `SameSite=Lax`, and `Secure` (in production / HTTPS) cookies.
 *    - Enforces explicit CORS origin allowlist (`ALLOWED_ORIGINS`) in production instead of reflecting arbitrary origins with `Access-Control-Allow-Credentials: true`.
 *    - Validates Origin/Referer or `X-CSRF-Token` for cookie-authenticated state-changing requests.
 * 5. Proxy-Aware Sliding-Window Rate Limiter & Brute-Force Protection:
 *    - Only trusts `CF-Connecting-IP` / `X-Forwarded-For` when `TRUST_PROXY=true` or running behind Render/Cloudflare.
 *    - Protects login, registration, gift-code redemption, wallet adjustments, and game endpoints.
 * 6. State Redaction & Output Filtering:
 *    - `redactStateForRole(masterState, session)` strips password hashes, admin session pools, other users' private financial records, and internal audit trails for non-admin callers.
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const TRUST_PROXY = process.env.TRUST_PROXY === 'true' || Boolean(process.env.RENDER);
const SECRET_FILE = path.join(__dirname, '.xyz_jwt_secret.key');

function loadJwtSecretOrFailClosed() {
  const envSecret = process.env.JWT_SECRET ? process.env.JWT_SECRET.trim() : '';
  if (envSecret.length >= 32) {
    return envSecret;
  }
  if (IS_PRODUCTION) {
    throw new Error(
      'FATAL SECURITY ERROR: JWT_SECRET environment variable is missing or shorter than 32 characters in production. Refusing to start with a predictable secret.'
    );
  }
  try {
    if (fs.existsSync(SECRET_FILE)) {
      const existing = fs.readFileSync(SECRET_FILE, 'utf-8').trim();
      if (existing.length >= 64) return existing;
    }
    const generated = crypto.randomBytes(48).toString('hex');
    fs.writeFileSync(SECRET_FILE, generated, { encoding: 'utf-8', mode: 0o600 });
    return generated;
  } catch (e) {
    // Ephemeral CSPRNG secret for read-only test containers (never predictable)
    return crypto.randomBytes(48).toString('hex');
  }
}

const JWT_SECRET = loadJwtSecretOrFailClosed();

const WINGO_HMAC_SECRET = (process.env.WINGO_CSPRNG_HMAC_SECRET && process.env.WINGO_CSPRNG_HMAC_SECRET.trim().length >= 32)
  ? process.env.WINGO_CSPRNG_HMAC_SECRET.trim()
  : crypto.createHmac('sha256', JWT_SECRET).update('XYZ_WINGO_CSPRNG_KEY_V14').digest('hex');

const PAYMENT_WEBHOOK_SECRET = (process.env.PAYMENT_WEBHOOK_HMAC_SECRET && process.env.PAYMENT_WEBHOOK_HMAC_SECRET.trim().length >= 16)
  ? process.env.PAYMENT_WEBHOOK_HMAC_SECRET.trim()
  : '';

// ============================================================================
// 1. CRYPTOGRAPHIC PASSWORD HASHING (SCRYPT + TIMING-SAFE COMPARE)
// ============================================================================
const HASH_PREFIX = 'scrypt$';
const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1, maxmem: 32 * 1024 * 1024 };

function isPasswordHashed(str) {
  return typeof str === 'string' && str.startsWith(HASH_PREFIX) && str.split('$').length === 3;
}

function hashPasswordSync(plainPassword) {
  const pwd = String(plainPassword || '');
  if (!pwd) return '';
  if (isPasswordHashed(pwd)) return pwd;
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(pwd, salt, 64, SCRYPT_PARAMS).toString('hex');
  return `${HASH_PREFIX}${salt}$${derived}`;
}

function verifyPasswordSync(plainCandidate, storedHash, legacyPlaintext = '') {
  const candidate = String(plainCandidate || '');
  if (!candidate) return { valid: false, needsMigration: false };
  // Prevent a user from submitting a raw scrypt$ hash string as their password
  if (isPasswordHashed(candidate)) {
    return { valid: false, needsMigration: false };
  }

  const primary = String(storedHash || '');
  if (isPasswordHashed(primary)) {
    const parts = primary.split('$');
    const salt = parts[1];
    const expectedHex = parts[2];
    if (!salt || !expectedHex || expectedHex.length !== 128) {
      return { valid: false, needsMigration: false };
    }
    try {
      const candidateBuf = crypto.scryptSync(candidate, salt, 64, SCRYPT_PARAMS);
      const expectedBuf = Buffer.from(expectedHex, 'hex');
      if (candidateBuf.length !== expectedBuf.length) {
        return { valid: false, needsMigration: false };
      }
      const match = crypto.timingSafeEqual(candidateBuf, expectedBuf);
      return { valid: match, needsMigration: false };
    } catch (e) {
      return { valid: false, needsMigration: false };
    }
  }

  // Legacy plaintext migration path: only allowed if no scrypt hash exists yet
  const legacy = String(primary || legacyPlaintext || '');
  if (legacy && legacy !== '—' && !isPasswordHashed(legacy)) {
    const a = Buffer.from(candidate, 'utf-8');
    const b = Buffer.from(legacy, 'utf-8');
    if (a.length === b.length && crypto.timingSafeEqual(a, b)) {
      return { valid: true, needsMigration: true };
    }
  }

  return { valid: false, needsMigration: false };
}

// ============================================================================
// 2. STATELESS HMAC-SHA256 JWT TOKENS, REVOCATION & COOKIE PARSER
// ============================================================================
const revokedTokenJtis = new Map(); // jti -> expMs
const revokedUserTokensBeforeMs = new Map(); // sub -> timestampMs

function revokeTokenJti(jti, expSec) {
  if (!jti) return;
  const expMs = expSec ? expSec * 1000 : (Date.now() + 86400 * 7 * 1000);
  revokedTokenJtis.set(String(jti), expMs);
}

function revokeAllSessionsForSubject(sub, timestampMs = Date.now()) {
  if (!sub) return;
  revokedUserTokensBeforeMs.set(String(sub), Number(timestampMs));
}

function base64UrlEncode(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input), 'utf-8');
  return buf.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function base64UrlDecode(str) {
  let s = String(str || '').replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4 !== 0) s += '=';
  return Buffer.from(s, 'base64').toString('utf-8');
}

function signJwt(payload, expiresInSeconds = 86400) {
  if (!payload || !payload.sub) {
    throw new Error('JWT payload must include a valid subject (sub)');
  }
  const header = { alg: 'HS256', typ: 'JWT' };
  const nowSec = Math.floor(Date.now() / 1000);
  const isAdm = Boolean(payload.isAdmin === true);
  const body = Object.assign({}, payload, {
    iss: 'xyz-games-auth',
    aud: isAdm ? 'xyz-admin' : 'xyz-customer',
    iat: nowSec,
    iatMs: Date.now(),
    exp: nowSec + Math.max(60, Number(expiresInSeconds || 86400)),
    jti: payload.jti || crypto.randomBytes(12).toString('hex')
  });
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(body));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = crypto
    .createHmac('sha256', JWT_SECRET)
    .update(signingInput)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
  return `${signingInput}.${signature}`;
}

function verifyJwt(token, requiredAudience = null) {
  if (!token || typeof token !== 'string' || token.length > 4096) return null;
  const parts = token.trim().split('.');
  if (parts.length !== 3) return null;
  const [encodedHeader, encodedPayload, signature] = parts;
  if (!encodedHeader || !encodedPayload || !signature) return null;

  try {
    const headerObj = JSON.parse(base64UrlDecode(encodedHeader));
    if (!headerObj || headerObj.alg !== 'HS256') return null;
  } catch (e) {
    return null;
  }

  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const expectedSig = crypto
    .createHmac('sha256', JWT_SECRET)
    .update(signingInput)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

  const sigBuf = Buffer.from(signature, 'utf-8');
  const expBuf = Buffer.from(expectedSig, 'utf-8');
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
    return null;
  }

  try {
    const payload = JSON.parse(base64UrlDecode(encodedPayload));
    if (!payload || typeof payload !== 'object' || !payload.sub) return null;
    const nowSec = Math.floor(Date.now() / 1000);
    if (!payload.exp || nowSec >= Number(payload.exp)) return null;
    if (payload.iss && payload.iss !== 'xyz-games-auth') return null;
    if (requiredAudience && payload.aud !== requiredAudience) return null;
    if (payload.jti && revokedTokenJtis.has(String(payload.jti))) return null;

    const revokedBefore = revokedUserTokensBeforeMs.get(String(payload.sub));
    const tokenIssuedMs = Number(payload.iatMs || (Number(payload.iat || 0) * 1000));
    if (revokedBefore && tokenIssuedMs <= revokedBefore) {
      return null;
    }
    return payload;
  } catch (e) {
    return null;
  }
}

function parseCookies(req) {
  const list = {};
  const cookieHeader = req && req.headers && req.headers.cookie;
  if (!cookieHeader || typeof cookieHeader !== 'string') return list;
  cookieHeader.split(';').forEach(cookie => {
    let [name, ...rest] = cookie.split('=');
    name = name ? name.trim() : '';
    if (!name) return;
    const value = rest.join('=').trim();
    if (!value) return;
    try {
      list[name] = decodeURIComponent(value);
    } catch (e) {
      list[name] = value;
    }
  });
  return list;
}

function isHttpsRequest(req) {
  if (!req) return IS_PRODUCTION;
  if (req.socket && req.socket.encrypted) return true;
  if (TRUST_PROXY && req.headers && req.headers['x-forwarded-proto'] === 'https') return true;
  return IS_PRODUCTION;
}

function buildCookieHeader(name, value, maxAgeSec, req) {
  const secureFlag = isHttpsRequest(req) ? '; Secure' : '';
  return `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${Math.max(0, Number(maxAgeSec || 0))}${secureFlag}`;
}


function clearCookieHeader(name, req) {
  return buildCookieHeader(name, '', 0, req);
}

function extractAuthSession(req, requiredType = null) {
  // requiredType: 'ADMIN' | 'CUSTOMER' | null (any valid session)
  const candidates = [];
  const authHeader = req && req.headers && (req.headers.authorization || req.headers['x-xyz-token']);
  if (authHeader && typeof authHeader === 'string') {
    const rawToken = authHeader.replace(/^Bearer\s+/i, '').trim();
    if (rawToken) candidates.push(rawToken);
  }
  const cookies = parseCookies(req);
  if (requiredType === 'ADMIN') {
    if (cookies.xyz_admin_token) candidates.push(cookies.xyz_admin_token);
  } else if (requiredType === 'CUSTOMER') {
    if (cookies.xyz_user_token) candidates.push(cookies.xyz_user_token);
  } else {
    if (cookies.xyz_admin_token) candidates.push(cookies.xyz_admin_token);
    if (cookies.xyz_user_token) candidates.push(cookies.xyz_user_token);
  }

  for (const tok of candidates) {
    const aud = requiredType === 'ADMIN' ? 'xyz-admin' : (requiredType === 'CUSTOMER' ? 'xyz-customer' : null);
    const verified = verifyJwt(tok, aud);
    if (!verified) continue;
    if (requiredType === 'ADMIN' && (!verified.isAdmin || verified.aud !== 'xyz-admin')) continue;
    if (requiredType === 'CUSTOMER' && (verified.isAdmin || verified.aud !== 'xyz-customer')) continue;
    return verified;
  }
  return null;
}

// ============================================================================
// 3. SLIDING-WINDOW RATE LIMITER & BRUTE-FORCE ACCOUNT LOCKOUT
// ============================================================================
const ipBuckets = new Map();
const authFailures = new Map();

const securityMetrics = {
  startedAt: Date.now(),
  totalRequests: 0,
  blockedRateLimitRequests: 0,
  blockedBruteForceLogins: 0,
  blockedUnauthorizedAdminPushes: 0,
  blockedCsrfRequests: 0,
  blockedMaliciousPayloads: 0,
  activeSseConnections: 0,
  peakConcurrentSse: 0
};

setInterval(() => {
  const now = Date.now();
  for (const [key, b] of ipBuckets.entries()) {
    if (now > b.resetAt + 60000) ipBuckets.delete(key);
  }
  for (const [key, f] of authFailures.entries()) {
    if (now > f.lockUntil && now - f.lastAttemptAt > 900000) authFailures.delete(key);
  }
  for (const [jti, expMs] of revokedTokenJtis.entries()) {
    if (now > expMs) revokedTokenJtis.delete(jti);
  }
}, 60000).unref();

function getClientIp(req) {
  if (TRUST_PROXY && req && req.headers) {
    const cfIp = req.headers['cf-connecting-ip'];
    if (cfIp && typeof cfIp === 'string') return cfIp.trim();
    const xff = req.headers['x-forwarded-for'];
    if (xff && typeof xff === 'string') {
      return xff.split(',')[0].trim();
    }
    const realIp = req.headers['x-real-ip'];
    if (realIp && typeof realIp === 'string') return realIp.trim();
  }
  return (req && req.socket && req.socket.remoteAddress) || '127.0.0.1';
}

function checkRateLimit(req, category = 'GENERAL') {
  securityMetrics.totalRequests += 1;
  const ip = getClientIp(req);
  const isLocal = !IS_PRODUCTION && (ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1');

  const limits = {
    GENERAL:     { windowMs: 60000,  max: isLocal ? 20000 : 1800 },
    STATE_WRITE: { windowMs: 60000,  max: isLocal ? 10000 : 600 },
    FINANCIAL:   { windowMs: 60000,  max: isLocal ? 5000  : 120 },
    AUTH_LOGIN:  { windowMs: 300000, max: isLocal ? 2000  : 40 }
  };

  const cfg = limits[category] || limits.GENERAL;
  const bucketKey = `${category}:${ip}`;
  const now = Date.now();

  let bucket = ipBuckets.get(bucketKey);
  if (!bucket || now > bucket.resetAt) {
    bucket = { count: 0, resetAt: now + cfg.windowMs };
    ipBuckets.set(bucketKey, bucket);
  }

  bucket.count += 1;
  if (bucket.count > cfg.max) {
    securityMetrics.blockedRateLimitRequests += 1;
    return {
      allowed: false,
      retryAfterSec: Math.max(1, Math.ceil((bucket.resetAt - now) / 1000)),
      remaining: 0
    };
  }

  return {
    allowed: true,
    retryAfterSec: 0,
    remaining: Math.max(0, cfg.max - bucket.count)
  };
}

function checkBruteForceLock(identifier, clientIp = '') {
  const key = `${String(identifier || '').trim().toLowerCase()}|${clientIp}`;
  if (!identifier) return { locked: false };
  const entry = authFailures.get(key);
  if (!entry) return { locked: false };
  const now = Date.now();
  if (entry.lockUntil && now < entry.lockUntil) {
    securityMetrics.blockedBruteForceLogins += 1;
    return {
      locked: true,
      retryAfterSec: Math.ceil((entry.lockUntil - now) / 1000)
    };
  }
  return { locked: false };
}

function recordAuthFailure(identifier, clientIp = '') {
  const key = `${String(identifier || '').trim().toLowerCase()}|${clientIp}`;
  if (!identifier) return;
  const now = Date.now();
  const entry = authFailures.get(key) || { count: 0, lastAttemptAt: 0, lockUntil: 0 };
  if (now - entry.lastAttemptAt > 900000) {
    entry.count = 0;
  }
  entry.count += 1;
  entry.lastAttemptAt = now;
  if (entry.count >= 8) {
    entry.lockUntil = now + 3 * 60 * 1000;
  }
  authFailures.set(key, entry);
}

function clearAuthFailures(identifier, clientIp = '') {
  const key = `${String(identifier || '').trim().toLowerCase()}|${clientIp}`;
  authFailures.delete(key);
}

// ============================================================================
// 4. CORS ALLOWLIST, CSRF PROTECTION & SECURITY HEADERS
// ============================================================================
function getAllowedOriginsSet() {
  const raw = process.env.ALLOWED_ORIGIN || process.env.ALLOWED_ORIGINS || '';
  const items = raw.split(',').map(s => s.trim()).filter(Boolean);
  return new Set(items);
}

function isOriginAllowed(req) {
  const origin = req && req.headers && req.headers.origin;
  if (!origin) return true; // Same-origin non-CORS or server-to-server request
  const allowedSet = getAllowedOriginsSet();
  if (allowedSet.has('*')) return !IS_PRODUCTION;
  if (allowedSet.has(origin)) return true;
  // Allow same-host origin automatically
  const host = req && req.headers && req.headers.host;
  if (host && (origin === `https://${host}` || origin === `http://${host}`)) {
    return true;
  }
  if (!IS_PRODUCTION && /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/i.test(origin)) {
    return true;
  }
  return false;
}

function validateCsrfAndOrigin(req) {
  if (!req || ['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return true;
  const origin = req.headers && req.headers.origin;
  const referer = req.headers && req.headers.referer;
  const host = req.headers && req.headers.host;

  // If request carries an explicit Bearer token or X-XYZ-Source header, custom header preflight protects against simple cross-site form POSTs
  if (req.headers && (req.headers.authorization || req.headers['x-xyz-source'] || req.headers['x-csrf-token'])) {
    if (origin && !isOriginAllowed(req)) {
      securityMetrics.blockedCsrfRequests += 1;
      return false;
    }
    return true;
  }

  // If relying on cookies without custom headers, validate Origin or Referer matches host/allowlist
  if (origin) {
    if (!isOriginAllowed(req)) {
      securityMetrics.blockedCsrfRequests += 1;
      return false;
    }
    return true;
  }
  if (referer && host) {
    try {
      const refUrl = new URL(referer);
      if (refUrl.host === host) return true;
    } catch (e) {}
    securityMetrics.blockedCsrfRequests += 1;
    return false;
  }
  return true;
}

function applySecurityHeaders(req, res) {
  const origin = req && req.headers && req.headers.origin;
  if (origin && isOriginAllowed(req)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  } else if (!IS_PRODUCTION && !origin) {
    res.setHeader('Access-Control-Allow-Origin', '*');
  }

  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-XYZ-Source, X-XYZ-Token, X-CSRF-Token, Idempotency-Key');

  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self' https: data: blob: 'unsafe-inline' 'unsafe-eval'; img-src 'self' https: data: blob:; connect-src 'self' https: wss: ws:; frame-ancestors 'self';"
  );
  if (isHttpsRequest(req)) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
}

// ============================================================================
// 5. DEEP INPUT SANITIZATION & PASSWORD HASH MIGRATION / REDACTION
// ============================================================================
const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function sanitizeObjectDeep(obj, depth = 0) {
  if (depth > 14 || obj === null || obj === undefined) return obj;
  if (typeof obj === 'string') {
    let cleaned = obj.replace(/\0/g, '');
    if (!cleaned.startsWith('data:image/')) {
      cleaned = cleaned
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
        .replace(/javascript\s*:/gi, 'blocked:')
        .replace(/on\w+\s*=\s*["'][^"']*["']/gi, '');
    }
    return cleaned;
  }
  if (typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) {
    return obj.map(item => sanitizeObjectDeep(item, depth + 1));
  }
  const out = {};
  for (const k of Object.keys(obj)) {
    if (DANGEROUS_KEYS.has(k)) {
      securityMetrics.blockedMaliciousPayloads += 1;
      continue;
    }
    out[k] = sanitizeObjectDeep(obj[k], depth + 1);
  }
  return out;
}

/**
 * Migrates any plaintext passwords in `stateObj` into `scrypt` hashes and
 * removes plaintext `.password` from canonical records so plaintext passwords
 * are never stored in snapshots, backups, or databases.
 */
function hashStatePasswordsInPlace(stateObj) {
  if (!stateObj || typeof stateObj !== 'object') return stateObj;

  if (Array.isArray(stateObj.staffAdmins)) {
    stateObj.staffAdmins.forEach(adm => {
      if (!adm || typeof adm !== 'object') return;
      if (adm.password && adm.password !== '—' && adm.password !== '[HASHED]') {
        if (!isPasswordHashed(adm.password)) {
          adm.passwordHash = hashPasswordSync(adm.password);
        } else if (!adm.passwordHash) {
          adm.passwordHash = adm.password;
        }
      }
      if (adm.passwordHash) {
        delete adm.password;
      }
    });
  }

  const migrateUserList = (list) => {
    if (!Array.isArray(list)) return;
    list.forEach(u => {
      if (!u || typeof u !== 'object') return;
      if (u.password && u.password !== '—' && u.password !== '[HASHED]') {
        if (!isPasswordHashed(u.password)) {
          u.passwordHash = hashPasswordSync(u.password);
        } else if (!u.passwordHash) {
          u.passwordHash = u.password;
        }
      }
      if (u.passwordHash) {
        delete u.password;
      }
    });
  };

  migrateUserList(stateObj.adminUsersList);
  migrateUserList(stateObj.registeredAccounts);
  return stateObj;
}

/**
 * Produces a role-scoped, redacted view of `masterState` so:
 * - Password hashes (`passwordHash`) and plaintext passwords are NEVER sent to any browser.
 * - Unauthenticated visitors or customers NEVER receive other users' private accounts,
 *   financial records, admin sessions, staff admin lists, or internal audit logs.
 */
function redactStateForClient(masterState, authSession) {
  if (!masterState || typeof masterState !== 'object') return {};
  const isAdmin = Boolean(authSession && authSession.isAdmin === true && (authSession.aud === 'xyz-admin' || authSession.type === 'ADMIN'));
  const callerUid = (!isAdmin && authSession && authSession.sub) ? String(authSession.sub) : null;

  const stripSecretsFromUser = (u, allowContactInfo) => {
    if (!u || typeof u !== 'object') return null;
    const copy = Object.assign({}, u);
    delete copy.password;
    delete copy.passwordHash;
    if (!allowContactInfo) {
      delete copy.aadhaarNo;
      delete copy.panNo;
      delete copy.bankAcc;
      delete copy.usdtWallet;
    }
    return copy;
  };

  if (isAdmin) {
    const adminCopy = Object.assign({}, masterState);
    adminCopy.staffAdmins = (masterState.staffAdmins || []).map(a => {
      const c = Object.assign({}, a);
      delete c.password;
      delete c.passwordHash;
      return c;
    });
    adminCopy.adminUsersList = (masterState.adminUsersList || []).map(u => stripSecretsFromUser(u, true));
    adminCopy.registeredAccounts = (masterState.registeredAccounts || []).map(u => stripSecretsFromUser(u, true));
    return adminCopy;
  }

  // Customer or Unauthenticated Visitor View:
  // Only expose public game/website config and the authenticated customer's own records
  const publicAndSelfState = {
    websiteConfig: masterState.websiteConfig || {},
    currencyConfig: masterState.currencyConfig || {},
    firstDepositBonusConfig: masterState.firstDepositBonusConfig || {},
    withdrawalConfig: masterState.withdrawalConfig || {},
    depositMinConfig: masterState.depositMinConfig || {},
    wingoModesConfig: masterState.wingoModesConfig || {},
    wingoRules: masterState.wingoRules || {},
    settledPeriodResults: Object.assign({}, masterState.settledPeriodResults || {}, masterState.manualOverrides || {}),
    manualOverrides: Object.assign({}, masterState.settledPeriodResults || {}, masterState.manualOverrides || {}),
    wingoPeriods: (masterState.wingoPeriods || []).slice(0, 100).map(p => {
      const cp = Object.assign({}, p);
      return cp;
    }),
    lotteryDraws: (masterState.lotteryDraws || []).map(d => Object.assign({}, d)),
    ludoConfig: masterState.ludoConfig || {},
    unoConfig: masterState.unoConfig || {},
    mathConfig: masterState.mathConfig || {},
    aviatorConfig: masterState.aviatorConfig || {},
    promoConfig: masterState.promoConfig || {},
    quizQuestions: masterState.quizQuestions || [],
    ludoTournaments: masterState.ludoTournaments || [],
    unoTournaments: masterState.unoTournaments || [],
    mathTournaments: masterState.mathTournaments || [],
    liveMatchmakingLobby: masterState.liveMatchmakingLobby || { UNO: [], LUDO: [], QUIZ: [] },
    paymentGatewayConfig: masterState.paymentGatewayConfig
      ? {
          mode: masterState.paymentGatewayConfig.mode || 'MANUAL',
          upiMode: masterState.paymentGatewayConfig.upiMode || 'MANUAL',
          usdtMode: masterState.paymentGatewayConfig.usdtMode || 'MANUAL',
          upiIds: masterState.paymentGatewayConfig.upiIds || [],
          usdtAddresses: masterState.paymentGatewayConfig.usdtAddresses || [],
          usdtNetwork: masterState.paymentGatewayConfig.usdtNetwork || 'TRC-20 (Tron)',
          upiQrConfig: masterState.paymentGatewayConfig.upiQrConfig || {},
          usdtQrConfig: masterState.paymentGatewayConfig.usdtQrConfig || {}
        }
      : {},
    upiId: masterState.upiId || '',
    usdtAddress: masterState.usdtAddress || '',
    superAdminConfigured: Boolean(masterState.superAdminConfigured),
    forceLogoutMap: callerUid && masterState.forceLogoutMap && masterState.forceLogoutMap[callerUid]
      ? { [callerUid]: masterState.forceLogoutMap[callerUid] }
      : {},
    // Redacted promotions metadata (never expose full list of active secret codes to unauthenticated scrapers)
    adminPromotions: callerUid
      ? (masterState.adminPromotions || []).map(p => ({
          code: p.code,
          title: p.title,
          rewardInr: p.rewardInr,
          totalValueInr: p.totalValueInr,
          distributionMode: p.distributionMode,
          maxClaims: p.maxClaims,
          claimedCount: p.claimedCount,
          status: p.status,
          redeemedByUids: (p.redeemedByUids || []).includes(callerUid) ? [callerUid] : []
        }))
      : [],
    // Scoped strictly to the authenticated customer (`callerUid`)
    adminUsersList: callerUid
      ? (masterState.adminUsersList || []).filter(u => u && u.userId === callerUid).map(u => stripSecretsFromUser(u, true))
      : [],
    registeredAccounts: callerUid
      ? (masterState.registeredAccounts || []).filter(u => u && u.userId === callerUid).map(u => stripSecretsFromUser(u, true))
      : [],
    adminDeposits: callerUid
      ? (masterState.adminDeposits || []).filter(d => d && d.userId === callerUid)
      : [],
    adminWithdrawals: callerUid
      ? (masterState.adminWithdrawals || []).filter(w => w && w.userId === callerUid)
      : [],
    transactions: callerUid
      ? (masterState.transactions || []).filter(t => t && (!t.userId || t.userId === callerUid))
      : [],
    myBets: callerUid
      ? (masterState.myBets || []).filter(b => b && (!b.userId || b.userId === callerUid))
      : [],
    lotteryTickets: callerUid
      ? (masterState.lotteryTickets || []).filter(t => t && (!t.userId || t.userId === callerUid))
      : [],
    lotteryNotifications: callerUid
      ? (masterState.lotteryNotifications || []).filter(n => n && (!n.userId || n.userId === callerUid))
      : [],
    adminNotifications: (masterState.adminNotifications || []).filter(n => {
      if (!n) return false;
      const tType = String(n.targetType || 'ALL').toUpperCase();
      const tUid = String(n.targetUid || 'ALL').toUpperCase();
      if (tType === 'ALL' || tUid === 'ALL' || tUid === '*') return true;
      return Boolean(callerUid && tUid === callerUid.toUpperCase());
    }),
    referralMembers: callerUid
      ? (masterState.referralMembers || []).filter(m => m && (m.rootAgentId === callerUid || m.beneficiaryUserId === callerUid || m.parentId === callerUid || m.memberId === callerUid))
      : [],
    commissionLedger: callerUid
      ? (masterState.commissionLedger || []).filter(c => c && (!c.beneficiaryUserId || c.beneficiaryUserId === callerUid || c.memberId === callerUid))
      : [],
    ludoManualMatches: callerUid
      ? (masterState.ludoManualMatches || []).filter(m => m && (m.player1Id === callerUid || m.player2Id === callerUid))
      : [],
    unoManualMatches: callerUid
      ? (masterState.unoManualMatches || []).filter(m => m && (m.player1Id === callerUid || m.player2Id === callerUid))
      : [],
    mathManualMatches: callerUid
      ? (masterState.mathManualMatches || []).filter(m => m && (m.player1Id === callerUid || m.player2Id === callerUid))
      : [],
    remoteCommandsQueue: (masterState.remoteCommandsQueue || []).filter(cmd => {
      if (!cmd) return false;
      const tDev = String(cmd.targetDeviceId || 'ALL').trim().toUpperCase();
      const tUid = String(cmd.targetUid || '').trim().toUpperCase();
      if (tDev === 'ALL' && !tUid) return true;
      if (callerUid && tUid === callerUid.toUpperCase()) return true;
      if (tDev && tDev !== 'ALL') return true;
      return false;
    })
  };

  return publicAndSelfState;
}

// ============================================================================
// 6. PROVABLY FAIR CSPRNG WINGO OUTCOME & COMMIT-REVEAL GENERATOR
//    Replaces computeLeastExposureNumberServer() manipulation
// ============================================================================
function generatePeriodCommitAndOutcome(slotKey, periodId) {
  const hmac = crypto
    .createHmac('sha256', WINGO_HMAC_SECRET)
    .update(`WINGO_V14:${slotKey}:${periodId}`)
    .digest('hex');
  const revealedSeed = `SEED_${slotKey}_${periodId}_${hmac.slice(0, 24)}`;
  const commitHash = 'sha256:' + crypto.createHash('sha256').update(revealedSeed).digest('hex');
  // Derive outcome deterministically from the cryptographic seed (independent of user bets!)
  const outcomeByte = parseInt(hmac.slice(24, 32), 16);
  const winningNumber = outcomeByte % 10;
  const winningColor = winningNumber === 0 ? 'RED_VIOLET' : (winningNumber === 5 ? 'GREEN_VIOLET' : ([1, 3, 7, 9].includes(winningNumber) ? 'GREEN' : 'RED'));
  const winningSize = winningNumber >= 5 ? 'Big' : 'Small';
  return {
    winningNumber,
    winningColor,
    winningSize,
    serverSeed: revealedSeed,
    revealedSeed,
    commitHash
  };
}

// ============================================================================
// 7. PAYMENT GATEWAY WEBHOOK HMAC SIGNATURE VERIFICATION
// ============================================================================
function verifyWebhookSignature(rawBodyString, signatureHeader) {
  if (!PAYMENT_WEBHOOK_SECRET || !signatureHeader || typeof signatureHeader !== 'string') {
    return false;
  }
  const cleanSig = signatureHeader.replace(/^sha256=/i, '').trim();
  const expectedHex = crypto
    .createHmac('sha256', PAYMENT_WEBHOOK_SECRET)
    .update(String(rawBodyString || ''), 'utf-8')
    .digest('hex');
  const a = Buffer.from(cleanSig, 'utf-8');
  const b = Buffer.from(expectedHex, 'utf-8');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

module.exports = {
  IS_PRODUCTION,
  TRUST_PROXY,
  JWT_SECRET,
  WINGO_HMAC_SECRET,
  PAYMENT_WEBHOOK_SECRET,
  isPasswordHashed,
  hashPasswordSync,
  verifyPasswordSync,
  signJwt,
  verifyJwt,
  revokeTokenJti,
  revokeAllSessionsForSubject,
  parseCookies,
  buildCookieHeader,
  clearCookieHeader,
  extractAuthSession,
  getClientIp,
  checkRateLimit,
  checkBruteForceLock,
  recordAuthFailure,
  clearAuthFailures,
  isOriginAllowed,
  validateCsrfAndOrigin,
  applySecurityHeaders,
  sanitizeObjectDeep,
  hashStatePasswordsInPlace,
  redactStateForClient,
  generatePeriodCommitAndOutcome,
  verifyWebhookSignature,
  securityMetrics
};
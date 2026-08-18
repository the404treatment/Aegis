/**
 * Accounts, sessions and capabilities. Zero dependencies, node:crypto only.
 * Ported from Skyhawk's server.js auth block, with two deliberate changes:
 *
 *  1. Sessions are BEARER TOKENS, not cookies. Skyhawk is a server-rendered
 *     app; AEGIS is a static SPA that already talks to the server with
 *     `Authorization: Bearer` and — because EventSource cannot set headers —
 *     a `?token=` query param on the SSE stream. Cookies would break that
 *     path and drag in CORS credential handling for no gain, so a session is
 *     just a revocable, per-user token used exactly where the shared analyst
 *     token is used today.
 *  2. Two roles (analyst/lead), not Skyhawk's three. AEGIS's gate-worthy
 *     actions are narrower: removing agents and editing someone else's
 *     ticket. A third tier can be added when something actually needs it.
 *
 * This module owns no storage: the caller supplies the user list and
 * persists whatever it hands back, which keeps it directly testable.
 */
import crypto from 'node:crypto';

/* ------------------------------------------------------------- capabilities */
export const ROLES = ['analyst', 'lead'];
const ANALYST_CAPS = [
  'ticket.create', 'ticket.comment', 'ticket.editOwn', 'lake.query',
  'case.create', 'case.editOwn', 'evidence.add',
];
const CAP = {
  analyst: ANALYST_CAPS,
  lead: [...ANALYST_CAPS, 'ticket.editAny', 'case.editAny', 'report.finalize', 'agent.manage', 'user.manage'],
};
export const capsFor = role => CAP[role] || [];
export const can = (role, cap) => capsFor(role).includes(cap);
export const canonRole = raw => {
  const r = String(raw || '').trim().toLowerCase();
  return ROLES.includes(r) ? r : null;
};

/* ---------------------------------------------------------------- passwords */
export function hashPw(pw, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(pw), salt, 64).toString('hex');
  return { salt, hash };
}
export function verifyPw(pw, u) {
  if (!u || !u.salt || !u.hash) return false;
  const h = crypto.scryptSync(String(pw), u.salt, 64).toString('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(h, 'hex'), Buffer.from(u.hash, 'hex'));
  } catch { return false; }
}

/** The shape safe to hand back to a browser — never salt/hash. */
export const publicUser = u => ({ id: u.id, name: u.name, role: u.role, caps: capsFor(u.role) });

/* ----------------------------------------------------------------- sessions */
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

export class Sessions {
  constructor(ttlMs = SESSION_TTL_MS) { this.map = new Map(); this.ttl = ttlMs; }

  /** Rehydrate persisted sessions, dropping any that expired while down. */
  load(rows) {
    const now = Date.now();
    for (const r of rows || []) {
      if (!r || !r.token || !r.userId) continue;
      if (now - (r.ts || 0) > this.ttl) continue;
      this.map.set(r.token, { userId: r.userId, ts: r.ts || now });
    }
    return this;
  }
  all() { return [...this.map.entries()].map(([token, v]) => ({ token, userId: v.userId, ts: v.ts })); }

  issue(userId) {
    const token = crypto.randomBytes(24).toString('hex');
    this.map.set(token, { userId, ts: Date.now() });
    return token;
  }
  /** userId for a live session, or null when unknown/expired (expired is evicted). */
  userIdFor(token) {
    if (!token) return null;
    const s = this.map.get(token);
    if (!s) return null;
    if (Date.now() - s.ts > this.ttl) { this.map.delete(token); return null; }
    return s.userId;
  }
  revoke(token) { return this.map.delete(token); }
  /** Kill every session for one user — used when a password changes. */
  revokeUser(userId) {
    let n = 0;
    for (const [t, s] of this.map) if (s.userId === userId) { this.map.delete(t); n++; }
    return n;
  }
  sweep() {
    const now = Date.now();
    for (const [t, s] of this.map) if (now - s.ts > this.ttl) this.map.delete(t);
  }
}

/* ------------------------------------------------------- login rate limiting */
export class LoginLimiter {
  constructor({ max = 5, windowMs = 15 * 60000, lockMs = 15 * 60000 } = {}) {
    this.max = max; this.windowMs = windowMs; this.lockMs = lockMs;
    this.attempts = new Map();
  }
  static key(ip, name) {
    return String(ip || '').split(',')[0].trim() + '|' + String(name || '').toLowerCase();
  }
  /** Seconds remaining on a lockout, or 0 when not locked. */
  blockedFor(key, now = Date.now()) {
    const e = this.attempts.get(key);
    if (e && e.lockUntil && now < e.lockUntil) return Math.ceil((e.lockUntil - now) / 1000);
    return 0;
  }
  fail(key, now = Date.now()) {
    let e = this.attempts.get(key);
    if (!e || now - e.first > this.windowMs) e = { count: 0, first: now, lockUntil: 0 };
    e.count++;
    if (e.count >= this.max) e.lockUntil = now + this.lockMs;
    this.attempts.set(key, e);
    return e;
  }
  reset(key) { this.attempts.delete(key); }
}

/* -------------------------------------------------------------------- users */
export function makeUser(name, password, role) {
  const n = String(name || '').trim();
  if (!n) throw new Error('name required');
  const r = canonRole(role);
  if (!r) throw new Error('role must be one of: ' + ROLES.join(', '));
  if (!password) throw new Error('password required');
  const { salt, hash } = hashPw(password);
  return { id: 'u_' + crypto.randomBytes(6).toString('base64url'), name: n, role: r, salt, hash, createdAt: Date.now() };
}
export const findUser = (users, name) =>
  users.find(u => u.name.toLowerCase() === String(name || '').trim().toLowerCase()) || null;

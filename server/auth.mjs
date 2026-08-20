/**
 * Accounts, sessions and capabilities. Zero dependencies, node:crypto only.
 * Ported from Skyhawk's server.js auth block, with two deliberate changes:
 *
 *  1. Sessions are BEARER TOKENS, not cookies. Skyhawk is a server-rendered
 *     app; AEGIS is a static SPA that already talks to the server with
 *     `Authorization: Bearer` and - because EventSource cannot set headers -
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

/** The shape safe to hand back to a browser - never salt/hash. */
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
  /** Kill every session for one user - used when a password changes. */
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
  /** Drop entries that are neither inside their counting window nor still
      locked - a key that is only ever tried once (a scanner moving through
      random usernames) would otherwise sit here forever, since nothing
      revisits it to trigger the window-expiry reset in fail(). */
  sweep(now = Date.now()) {
    for (const [key, e] of this.attempts) {
      if (now - e.first > this.windowMs && now > e.lockUntil) this.attempts.delete(key);
    }
  }
}

/* -------------------------------------------------------------------- users */
/* Length is the only password rule worth having: composition rules ("one
   number, one symbol") push people towards Passw0rd! and buy nothing. The
   login screen promises this figure, so it is enforced here rather than in the
   UI, where a direct API call would walk straight past it. */
export const MIN_PASSWORD = 10;

export function makeUser(name, password, role, opts = {}) {
  const n = String(name || '').trim();
  if (!n) throw new Error('name required');
  const r = canonRole(role);
  if (!r) throw new Error('role must be one of: ' + ROLES.join(', '));
  if (!password) throw new Error('password required');
  // The length floor is skipped only for the seeded local defaults below,
  // whose whole point is a short, known password on a single-box install.
  if (!opts.seed && String(password).length < MIN_PASSWORD)
    throw new Error(`password must be at least ${MIN_PASSWORD} characters`);
  const { salt, hash } = hashPw(password);
  const u = { id: 'u_' + crypto.randomBytes(6).toString('base64url'), name: n, role: r, salt, hash, createdAt: Date.now() };
  if (opts.seed) u.seed = true;   // marks a default account, so the UI can say "change me"
  return u;
}

/* The two ready-made local accounts. On a single-box install the create-first-
   account dance is friction nobody asked for: this seeds an admin (lead) and a
   user (analyst) with obvious default passwords, so the login screen becomes a
   two-button "who are you" prompt. Weak on purpose - a laptop's AEGIS console
   is not internet-facing, and a real deployment changes these or adds named
   accounts. Idempotent: only fills a name that does not already exist. */
/* One standardised password across every seeded account, admins and analysts
   alike - a deliberate choice for a local range where the point is fast,
   frictionless multi-user access, not credential secrecy. Three of each so a
   handful of people can each sign in under their own name at once. Meets the
   length floor, so no seed bypass is needed. Change or remove them in Admin
   for anything networked. */
export const STANDARD_PASSWORD = 'Password123!';
export const DEFAULT_ACCOUNTS = [
  { name: 'admin1', password: STANDARD_PASSWORD, role: 'lead' },
  { name: 'admin2', password: STANDARD_PASSWORD, role: 'lead' },
  { name: 'admin3', password: STANDARD_PASSWORD, role: 'lead' },
  { name: 'user1', password: STANDARD_PASSWORD, role: 'analyst' },
  { name: 'user2', password: STANDARD_PASSWORD, role: 'analyst' },
  { name: 'user3', password: STANDARD_PASSWORD, role: 'analyst' },
];
export function seedDefaultAccounts(users) {
  let added = 0;
  for (const a of DEFAULT_ACCOUNTS) {
    if (findUser(users, a.name)) continue;
    users.push(makeUser(a.name, a.password, a.role, { seed: true }));
    added++;
  }
  return added;
}
export const findUser = (users, name) =>
  users.find(u => u.name.toLowerCase() === String(name || '').trim().toLowerCase()) || null;

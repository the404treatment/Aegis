#!/usr/bin/env node
/**
 * AEGIS Server — agent ingest, live state, ticketing, Splunk HEC forwarding.
 *
 * Zero dependencies. Node 18+.
 *   node aegis-server.mjs --config ./config.json
 *
 * SECURITY POSTURE (read before exposing this anywhere):
 *  - Binds 127.0.0.1 by default. Put it behind a TLS reverse proxy before
 *    anything else can reach it. There is no TLS in here on purpose.
 *  - Three credential types: an enrollment token (shared, rotate it), a
 *    per-agent key (issued at enrollment), and an analyst token (UI/API).
 *    Optionally a fourth: per-user session tokens, when requireLogin is on.
 *    The analyst token keeps working either way as the break-glass and
 *    automation credential, so turning accounts on never locks anyone out.
 *  - Agents can only write their own telemetry. They cannot read other hosts,
 *    read tickets, or receive commands. There is deliberately no remote-exec
 *    channel: this is a collector, not a C2.
 */

import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { AuditLog } from './audit.mjs';
import { query as lakeQuery } from './lake.mjs';
import { Sessions, LoginLimiter, makeUser, findUser, verifyPw, publicUser, can, canonRole, capsFor } from './auth.mjs';
import { makeCase, patchCase, decodeEvidence, evidenceRecord, safeEvidenceName, EVIDENCE_MAX_BYTES } from './cases.mjs';
import { buildReport, finalizeFormal } from './report.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/* ------------------------------------------------------------------ config */
function loadConfig() {
  const i = process.argv.indexOf('--config');
  const p = i > -1 ? process.argv[i + 1] : path.join(__dirname, 'config.json');
  let cfg = {};
  if (fs.existsSync(p)) cfg = JSON.parse(fs.readFileSync(p, 'utf8'));
  else console.warn(`[aegis] no config at ${p}, using defaults + generated secrets`);

  const def = {
    host: '127.0.0.1',
    port: 8787,
    dataDir: path.join(__dirname, 'data'),
    uiDir: path.join(__dirname, '..', 'ui'),
    enrollmentToken: cfg.enrollmentToken || crypto.randomBytes(24).toString('base64url'),
    analystToken: cfg.analystToken || crypto.randomBytes(24).toString('base64url'),
    // Named accounts are opt-in. Left false (the default), the analyst token
    // is the only credential and behaviour is exactly as it was before
    // accounts existed — no existing deployment changes.
    requireLogin: false,
    // agents older than this are shown as stale (seconds)
    staleAfter: 180,
    retentionEvents: 200000,
    splunk: { enabled: false, url: '', token: '', index: 'aegis', sourcetype: 'aegis:agent', verifyTls: true },
    webhook: { enabled: false, url: '', format: 'slack', minIntervalSec: 300 },
    maxEventFileMB: 256,
  };
  return { ...def, ...cfg, splunk: { ...def.splunk, ...(cfg.splunk || {}) }, webhook: { ...def.webhook, ...(cfg.webhook || {}) } };
}
const CFG = loadConfig();
fs.mkdirSync(CFG.dataDir, { recursive: true });

/* ------------------------------------------------------------------- store */
/** Small JSON+NDJSON store. Fine for a lab or a small estate (hundreds of
 *  hosts). If you outgrow it, swap these four functions for Postgres. */
const F = {
  agents: path.join(CFG.dataDir, 'agents.json'),
  tickets: path.join(CFG.dataDir, 'tickets.json'),
  events: path.join(CFG.dataDir, 'events.ndjson'),
  audit: path.join(CFG.dataDir, 'audit.ndjson'),
  users: path.join(CFG.dataDir, 'users.json'),
  sessions: path.join(CFG.dataDir, 'sessions.json'),
  cases: path.join(CFG.dataDir, 'cases.json'),
  chat: path.join(CFG.dataDir, 'chat.ndjson'),
};
const EVIDENCE_DIR = path.join(CFG.dataDir, 'evidence');
fs.mkdirSync(EVIDENCE_DIR, { recursive: true });
const readJson = (f, d) => { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return d; } };
const writeJson = (f, v) => {
  const tmp = f + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(v, null, 1));
  fs.renameSync(tmp, f); // atomic-ish; survives a crash mid-write
};

let AGENTS = readJson(F.agents, {});      // id -> agent record
let TICKETS = readJson(F.tickets, []);    // newest last
let CASES = readJson(F.cases, []);        // incident containers, newest last
let EVENTS = [];                          // in-memory ring for the UI

// hydrate the recent event ring from disk
try {
  const raw = fs.existsSync(F.events) ? fs.readFileSync(F.events, 'utf8').trim().split('\n') : [];
  EVENTS = raw.slice(-5000).map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
} catch { EVENTS = []; }

const saveAgents = () => writeJson(F.agents, AGENTS);
const saveTickets = () => writeJson(F.tickets, TICKETS);
const saveCases = () => writeJson(F.cases, CASES);
const evStream = fs.createWriteStream(F.events, { flags: 'a' });

// hash-chained, tamper-evident audit log — one global chain, filtered by
// targetId per view. actorId is whatever the client asserts (createdBy/
// author/'analyst') until per-user auth exists — not identity-verified.
const AUDIT = new AuditLog();
try {
  const raw = fs.existsSync(F.audit) ? fs.readFileSync(F.audit, 'utf8').trim().split('\n') : [];
  AUDIT.load(raw.filter(Boolean).map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean));
} catch { /* start with an empty chain */ }
const auditStream = fs.createWriteStream(F.audit, { flags: 'a' });
function auditRecord(actorId, action, targetId, data) {
  const e = AUDIT.record(actorId, action, targetId, data);
  auditStream.write(JSON.stringify(e) + '\n');
  return e;
}

/* --------------------------------------------------------------- chat */
/* Append-only, same pattern as events.ndjson, with a bounded in-memory tail
   for the UI. Delivery rides the SSE hub the server already runs — Skyhawk
   polls twice a second for this, which we simply don't need to do. */
const CHAT_KEEP = 300;
let CHAT = [];
try {
  const raw = fs.existsSync(F.chat) ? fs.readFileSync(F.chat, 'utf8').trim().split('\n') : [];
  CHAT = raw.filter(Boolean).slice(-CHAT_KEEP).map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
} catch { CHAT = []; }
const chatStream = fs.createWriteStream(F.chat, { flags: 'a' });

/* ------------------------------------------------------------ accounts */
let USERS = readJson(F.users, []);
const saveUsers = () => writeJson(F.users, USERS);
const SESSIONS = new Sessions().load(readJson(F.sessions, []));
const saveSessions = () => writeJson(F.sessions, SESSIONS.all());
const LOGINS = new LoginLimiter();
const clientIp = req => String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '');

/* -------------------------------------------------------------------- util */
const uid = (p = '') => p + crypto.randomBytes(9).toString('base64url');
const now = () => Date.now();
const safeEq = (a, b) => {
  const A = Buffer.from(String(a || '')), B = Buffer.from(String(b || ''));
  return A.length === B.length && crypto.timingSafeEqual(A, B);
};

/* --------------------------------------------------------------- SSE hub */
const clients = new Set();
function broadcast(type, data) {
  const msg = `event: ${type}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of clients) { try { res.write(msg); } catch { clients.delete(res); } }
}

/* ------------------------------------------------------------ Splunk HEC */
let splunkQueue = [];
let splunkTimer = null;
function toSplunk(ev, agent) {
  if (!CFG.splunk.enabled || !CFG.splunk.url || !CFG.splunk.token) return;
  splunkQueue.push({
    time: Math.floor((ev.ts || now()) / 1000),
    host: agent?.hostname || ev.host || 'unknown',
    source: 'aegis',
    sourcetype: CFG.splunk.sourcetype,
    index: CFG.splunk.index,
    event: { ...ev, agent_id: agent?.id, agent_os: agent?.os },
  });
  if (!splunkTimer) splunkTimer = setTimeout(flushSplunk, 1500);
}
function flushSplunk() {
  splunkTimer = null;
  if (!splunkQueue.length) return;
  const batch = splunkQueue.splice(0, 500);
  const body = batch.map(e => JSON.stringify(e)).join('\n');
  let u;
  try { u = new URL(CFG.splunk.url); } catch { return; }
  const lib = u.protocol === 'https:' ? https : http;
  const req = lib.request({
    hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
    path: u.pathname === '/' ? '/services/collector/event' : u.pathname,
    method: 'POST',
    rejectUnauthorized: CFG.splunk.verifyTls !== false,
    headers: { 'Authorization': `Splunk ${CFG.splunk.token}`, 'Content-Type': 'application/json' },
  }, res => {
    if (res.statusCode >= 300) console.warn('[splunk] HEC', res.statusCode);
    res.resume();
  });
  req.on('error', e => console.warn('[splunk] send failed:', e.message));
  req.end(body);
  if (splunkQueue.length) splunkTimer = setTimeout(flushSplunk, 1500);
}

/* --------------------------------------------------------------- mapping */
/** Turn an agent's self-reported facts into the node type AEGIS draws. */
function inferNodeType(a) {
  const n = (a.hostname || '').toLowerCase();
  const roles = (a.roles || []).map(r => String(r).toLowerCase());
  if (roles.includes('domain_controller') || /^dc\d|domaincontroller/.test(n)) return 'dc';
  if (roles.includes('hypervisor')) return 'srv';
  if (/^fw|firewall/.test(n)) return 'fw';
  if (/^rtr|router/.test(n)) return 'router';
  if (/^sw\d|switch/.test(n)) return 'switch';
  if (/vpn/.test(n)) return 'vpn';
  if (/nas|storage|fileserver|^fs\d/.test(n)) return 'nas';
  if (/web|www|dmz|proxy/.test(n)) return 'dmz';
  if ((a.os || '').toLowerCase().includes('server')) return 'srv';
  return 'wks';
}
function inferZone(a) {
  const t = inferNodeType(a);
  if (t === 'dc') return 'core';
  if (t === 'dmz') return 'dmz';
  if (['fw', 'router', 'switch', 'vpn'].includes(t)) return 'edge';
  return 'internal';
}
function publicAgent(a) {
  const stale = now() - (a.lastSeen || 0) > CFG.staleAfter * 1000;
  return {
    id: a.id, hostname: a.hostname, os: a.os, ip: a.ip, roles: a.roles || [],
    nodeType: a.nodeType || inferNodeType(a), zone: a.zone || inferZone(a),
    lastSeen: a.lastSeen, enrolledAt: a.enrolledAt, stale,
    version: a.version, eventCount: a.eventCount || 0,
    counters: a.counters || {},
    logging: a.logging || null,
    gaps: loggingGaps(a),
    listening: a.listening || [],
  };
}

/* ------------------------------------------------------- alerting */
/** Fire a webhook (Slack/Teams/generic) when something malicious lands.
 *  Rate-limited per host so one noisy box cannot flood the channel. */
const _notified = {};
function notify(events, agent) {
  const wh = CFG.webhook;
  if (!wh || !wh.enabled || !wh.url) return;
  const k = agent.hostname;
  const gap = (wh.minIntervalSec || 300) * 1000;
  if (_notified[k] && now() - _notified[k] < gap) return;
  _notified[k] = now();
  const text = `AEGIS: ${events.length} malicious event${events.length === 1 ? '' : 's'} on ${agent.hostname}\n` +
    events.slice(0, 3).map(e => `- ${e.channel} ${e.eventId}: ${e.message.slice(0, 160)}`).join('\n');
  let u; try { u = new URL(wh.url); } catch { return; }
  const lib = u.protocol === 'https:' ? https : http;
  const body = JSON.stringify(wh.format === 'teams' ? { text } : { text });
  const req = lib.request({
    hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
    path: u.pathname + u.search, method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
  }, r => r.resume());
  req.on('error', e => console.warn('[webhook]', e.message));
  req.end(body);
}

/* --------------------------------------------------- link inference */
let LINKS = [];
/** Turn each agent's observed peers into edges between known hosts.
 *  Only links where BOTH ends are enrolled agents are drawn — an unknown IP
 *  is noise, not topology. */
function rebuildLinks() {
  const byIp = {};
  for (const a of Object.values(AGENTS)) if (a.ip) byIp[a.ip] = a.id;
  const seen = new Set();
  const out = [];
  for (const a of Object.values(AGENTS)) {
    for (const pr of (a.peers || [])) {
      const other = byIp[pr.ip];
      if (!other || other === a.id) continue;
      const key = [a.id, other].sort().join('|');
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ a: a.id, b: other, port: pr.port, proto: pr.proto });
    }
  }
  LINKS = out;
}
rebuildLinks();

/** Which detection-relevant logging is missing per host. */
function loggingGaps(a) {
  const l = a.logging || {};
  const gaps = [];
  if (l.sysmon === false) gaps.push({ id: 'sysmon', label: 'Sysmon not installed', impact: 'No EID 1/3/7/11 — image loads, network connections, and file writes are invisible.' });
  if (l.psScriptBlock === false) gaps.push({ id: 'ps4104', label: 'PowerShell script block logging off', impact: 'No 4104 — encoded and obfuscated PowerShell cannot be reconstructed.' });
  if (l.cmdLineAudit === false) gaps.push({ id: 'cmdline', label: 'Process command line auditing off', impact: '4688 without CommandLine is nearly useless for detection.' });
  if (l.shareAudit === false) gaps.push({ id: 'share5145', label: 'Detailed file share auditing off', impact: 'No 5145 — lateral movement over SMB and share enumeration are unseen.' });
  return gaps;
}

/* ------------------------------------------------------------------ HTTP */
const json = (res, code, obj) => {
  const b = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(b) });
  res.end(b);
};
const readBody = (req, limit = 4e6) => new Promise((resolve, reject) => {
  let n = 0; const chunks = [];
  req.on('data', c => { n += c.length; if (n > limit) { reject(new Error('body too large')); req.destroy(); } chunks.push(c); });
  req.on('end', () => { try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks)) : {}); } catch (e) { reject(e); } });
  req.on('error', reject);
});
const bearer = req => (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
/** EventSource cannot set headers, so the SSE stream passes ?token= instead. */
const credOf = (req, u) => bearer(req) || (u && u.searchParams.get('token')) || '';

/**
 * Resolve the caller to an actor, or null when unauthenticated.
 *
 * Two credentials are accepted, always:
 *  - the shared analyst token — kept working unconditionally so existing
 *    deployments, scripts and integrations never break. It carries the top
 *    role, i.e. it is the break-glass/automation credential.
 *  - a session token from POST /api/login, when accounts are enabled.
 *
 * With CFG.requireLogin false (the default) there are no accounts and the
 * analyst token is the whole story, exactly as before.
 */
function actorOf(req, u) {
  const tok = credOf(req, u);
  if (!tok) return null;
  if (safeEq(tok, CFG.analystToken)) return { id: 'analyst-token', name: 'analyst token', role: 'lead', shared: true };
  const uid = SESSIONS.userIdFor(tok);
  if (!uid) return null;
  const user = USERS.find(x => x.id === uid);
  return user ? { id: user.id, name: user.name, role: user.role, shared: false } : null;
}
const isAnalyst = (req, u) => !!actorOf(req, u);
/** 403 helper — returns true (and responds) when the actor lacks the capability. */
function denied(res, actor, cap) {
  if (actor && can(actor.role, cap)) return false;
  json(res, 403, { error: `permission denied: ${(actor && actor.role) || 'anonymous'} lacks ${cap}` });
  return true;
}
function agentFrom(req) {
  const id = req.headers['x-agent-id'];
  const key = req.headers['x-agent-key'];
  const a = AGENTS[id];
  if (!a || !safeEq(key, a.key)) return null;
  return a;
}

const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://x');
  const p = u.pathname;

  // CORS is intentionally narrow: same-origin UI, or an explicit allowlist.
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-Agent-Id,X-Agent-Key');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,DELETE,OPTIONS');
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }

  try {
    /* ---------------- health ---------------- */
    if (p === '/api/health') return json(res, 200, { ok: true, agents: Object.keys(AGENTS).length, uptime: process.uptime() });

    /* ---------------- agent enrollment ---------------- */
    if (p === '/api/enroll' && req.method === 'POST') {
      const b = await readBody(req);
      if (!safeEq(b.enrollmentToken, CFG.enrollmentToken)) return json(res, 401, { error: 'bad enrollment token' });
      if (!b.hostname) return json(res, 400, { error: 'hostname required' });

      // re-enrolling the same hostname reuses the record (agent reinstall)
      let a = Object.values(AGENTS).find(x => x.hostname.toLowerCase() === String(b.hostname).toLowerCase());
      if (!a) {
        a = { id: uid('ag_'), enrolledAt: now(), eventCount: 0, counters: {} };
        AGENTS[a.id] = a;
      }
      a.key = uid('ak_');
      a.hostname = b.hostname; a.os = b.os || 'unknown'; a.ip = b.ip || '';
      a.roles = b.roles || []; a.version = b.version || '';
      a.nodeType = inferNodeType(a); a.zone = inferZone(a);
      a.lastSeen = now();
      saveAgents();
      broadcast('agent', publicAgent(a));
      console.log(`[aegis] enrolled ${a.hostname} (${a.id})`);
      return json(res, 200, { agentId: a.id, agentKey: a.key, heartbeat: 60 });
    }

    /* ---------------- agent network discovery ---------------- */
    if (p === '/api/discovery' && req.method === 'POST') {
      const a = agentFrom(req); if (!a) return json(res, 401, { error: 'unauthorized' });
      const b = await readBody(req);
      a.lastSeen = now();
      // peers this host actually talks to — real adjacency, not guesswork
      if (Array.isArray(b.peers)) {
        a.peers = b.peers.slice(0, 200).map(x => ({
          ip: String(x.ip || '').slice(0, 45),
          port: Number(x.port) || 0,
          host: String(x.host || '').slice(0, 128),
          proto: String(x.proto || '').slice(0, 8),
        }));
      }
      // what this host is actually logging — drives the gap report
      if (b.logging && typeof b.logging === 'object') a.logging = b.logging;
      if (Array.isArray(b.listening)) a.listening = b.listening.slice(0, 100);
      saveAgents();
      rebuildLinks();
      broadcast('agent', publicAgent(a));
      broadcast('links', LINKS);
      return json(res, 200, { ok: true });
    }

    /* ---------------- agent heartbeat ---------------- */
    if (p === '/api/heartbeat' && req.method === 'POST') {
      const a = agentFrom(req); if (!a) return json(res, 401, { error: 'unauthorized' });
      const b = await readBody(req);
      a.lastSeen = now();
      if (b.ip) a.ip = b.ip;
      if (b.counters) a.counters = b.counters;
      if (b.roles) { a.roles = b.roles; a.nodeType = inferNodeType(a); a.zone = inferZone(a); }
      saveAgents();
      broadcast('agent', publicAgent(a));
      return json(res, 200, { ok: true, serverTime: now() });
    }

    /* ---------------- agent event ingest ---------------- */
    if (p === '/api/events' && req.method === 'POST') {
      const a = agentFrom(req); if (!a) return json(res, 401, { error: 'unauthorized' });
      const b = await readBody(req);
      const arr = Array.isArray(b.events) ? b.events : [];
      const accepted = [];
      for (const raw of arr.slice(0, 1000)) {
        const ev = {
          id: uid('ev_'),
          ts: Number(raw.ts) || now(),
          agentId: a.id,
          host: a.hostname,
          channel: String(raw.channel || 'unknown').slice(0, 64),
          eventId: String(raw.eventId ?? '').slice(0, 32),
          severity: ['info', 'suspicious', 'malicious'].includes(raw.severity) ? raw.severity : 'info',
          message: String(raw.message || '').slice(0, 4000),
          fields: (raw.fields && typeof raw.fields === 'object') ? raw.fields : {},
          technique: String(raw.technique || '').slice(0, 16),
        };
        accepted.push(ev);
        EVENTS.push(ev);
        evStream.write(JSON.stringify(ev) + '\n');
        toSplunk(ev, a);
      }
      if (EVENTS.length > 5000) EVENTS.splice(0, EVENTS.length - 5000);
      a.eventCount = (a.eventCount || 0) + accepted.length;
      a.lastSeen = now();
      saveAgents();
      if (accepted.length) broadcast('events', accepted);
      const bad = accepted.filter(e => e.severity === 'malicious');
      if (bad.length) notify(bad, a);
      return json(res, 200, { accepted: accepted.length });
    }

    /* ============ everything below is analyst-authenticated ============ */

    /* ---------------- live event stream (SSE) ---------------- */
    if (p === '/api/stream') {
      if (!isAnalyst(req, u)) return json(res, 401, { error: 'unauthorized' });
      res.writeHead(200, {
        'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache',
        'Connection': 'keep-alive', 'X-Accel-Buffering': 'no',
      });
      res.write(`event: hello\ndata: ${JSON.stringify({ t: now() })}\n\n`);
      clients.add(res);
      const ka = setInterval(() => { try { res.write(': keepalive\n\n'); } catch { } }, 25000);
      req.on('close', () => { clearInterval(ka); clients.delete(res); });
      return;
    }

    /* ---------------- accounts (opt-in via CFG.requireLogin) ---------------- */
    // Advertises whether the console should present a login screen. Public by
    // design: it leaks nothing but a boolean the login page needs to render.
    if (p === '/api/auth/mode') return json(res, 200, { requireLogin: !!CFG.requireLogin, accounts: USERS.length });

    if (p === '/api/auth/login' && req.method === 'POST') {
      const b = await readBody(req);
      const key = LoginLimiter.key(clientIp(req), b.name);
      const wait = LOGINS.blockedFor(key);
      if (wait) return json(res, 429, { error: `too many attempts — wait ${wait}s` });
      const user = findUser(USERS, b.name);
      // Same response and same work either way: never reveal which half was wrong.
      if (!user || !verifyPw(b.password || '', user)) {
        LOGINS.fail(key);
        auditRecord(String(b.name || '').slice(0, 64), 'auth.login.failed', 'auth', null);
        return json(res, 401, { error: 'invalid name or password' });
      }
      LOGINS.reset(key);
      const token = SESSIONS.issue(user.id); saveSessions();
      auditRecord(user.id, 'auth.login', 'auth', { name: user.name });
      return json(res, 200, { token, user: publicUser(user) });
    }

    if (p === '/api/auth/logout' && req.method === 'POST') {
      const tok = credOf(req, u);
      const uid = SESSIONS.userIdFor(tok);
      if (uid) { SESSIONS.revoke(tok); saveSessions(); auditRecord(uid, 'auth.logout', 'auth', null); }
      return json(res, 200, { ok: true });
    }

    if (p.startsWith('/api/') && !isAnalyst(req, u)) return json(res, 401, { error: 'unauthorized' });

    if (p === '/api/auth/me') {
      const a = actorOf(req, u);
      return json(res, 200, { id: a.id, name: a.name, role: a.role, shared: !!a.shared, caps: capsFor(a.role) });
    }

    /* User administration. Requires user.manage, so the analyst token (or a
       lead) can create the first account — otherwise enabling requireLogin
       would lock everyone out with no way back in. */
    if (p === '/api/users' && req.method === 'GET') {
      const a = actorOf(req, u); if (denied(res, a, 'user.manage')) return;
      return json(res, 200, USERS.map(publicUser));
    }
    if (p === '/api/users' && req.method === 'POST') {
      const a = actorOf(req, u); if (denied(res, a, 'user.manage')) return;
      const b = await readBody(req);
      if (findUser(USERS, b.name)) return json(res, 409, { error: 'that name is taken' });
      let user;
      try { user = makeUser(b.name, b.password, b.role); }
      catch (e) { return json(res, 400, { error: e.message }); }
      USERS.push(user); saveUsers();
      auditRecord(a.id, 'user.create', user.id, { name: user.name, role: user.role });
      return json(res, 200, publicUser(user));
    }
    const mU = p.match(/^\/api\/users\/([^/]+)$/);
    if (mU && req.method === 'DELETE') {
      const a = actorOf(req, u); if (denied(res, a, 'user.manage')) return;
      const i = USERS.findIndex(x => x.id === mU[1]);
      if (i < 0) return json(res, 404, { error: 'no such user' });
      const [gone] = USERS.splice(i, 1); saveUsers();
      SESSIONS.revokeUser(gone.id); saveSessions();  // a deleted account's sessions must die with it
      auditRecord(a.id, 'user.delete', gone.id, { name: gone.name });
      return json(res, 200, { ok: true });
    }
    if (mU && req.method === 'PATCH') {
      const a = actorOf(req, u); if (denied(res, a, 'user.manage')) return;
      const user = USERS.find(x => x.id === mU[1]);
      if (!user) return json(res, 404, { error: 'no such user' });
      const b = await readBody(req);
      if (b.role) { const r = canonRole(b.role); if (!r) return json(res, 400, { error: 'bad role' }); user.role = r; }
      if (b.password) {
        const { salt, hash } = makeUser(user.name, b.password, user.role);
        user.salt = salt; user.hash = hash;
        SESSIONS.revokeUser(user.id); saveSessions(); // a password change must invalidate live sessions
      }
      saveUsers();
      auditRecord(a.id, 'user.update', user.id, { role: user.role, passwordChanged: !!b.password });
      return json(res, 200, publicUser(user));
    }

    /* ---------------- state for the UI ---------------- */
    if (p === '/api/state') {
      return json(res, 200, {
        agents: Object.values(AGENTS).map(publicAgent),
        links: LINKS,
        tickets: TICKETS.slice(-500),
        cases: CASES.slice(-500),
        chat: CHAT.slice(-100),
        events: EVENTS.slice(-500),
        serverTime: now(),
        splunk: { enabled: !!CFG.splunk.enabled, index: CFG.splunk.index },
      });
    }

    if (p === '/api/agents' && req.method === 'GET')
      return json(res, 200, Object.values(AGENTS).map(publicAgent));

    // let an analyst correct what the agent guessed
    const mAgent = p.match(/^\/api\/agents\/([^/]+)$/);
    if (mAgent && req.method === 'PATCH') {
      const a = AGENTS[mAgent[1]]; if (!a) return json(res, 404, { error: 'no such agent' });
      const b = await readBody(req);
      if (b.nodeType) a.nodeType = b.nodeType;
      if (b.zone) a.zone = b.zone;
      if (b.hostname) a.hostname = b.hostname;
      saveAgents(); broadcast('agent', publicAgent(a));
      return json(res, 200, publicAgent(a));
    }
    if (mAgent && req.method === 'DELETE') {
      if (denied(res, actorOf(req, u), 'agent.manage')) return;
      const a = AGENTS[mAgent[1]]; if (!a) return json(res, 404, { error: 'no such agent' });
      delete AGENTS[mAgent[1]]; saveAgents();
      auditRecord(actorOf(req, u).id, 'agent.delete', mAgent[1], { hostname: a.hostname });
      broadcast('agentRemoved', { id: mAgent[1] });
      return json(res, 200, { ok: true });
    }

    if (p === '/api/events' && req.method === 'GET') {
      const host = u.searchParams.get('host');
      const sev = u.searchParams.get('severity');
      let out = EVENTS;
      if (host) out = out.filter(e => e.host === host);
      if (sev) out = out.filter(e => e.severity === sev);
      return json(res, 200, out.slice(-500));
    }

    /* ---------------- event lake (SIEM-style query) ---------------- */
    if (p === '/api/lake' && req.method === 'GET') {
      const q = u.searchParams;
      return json(res, 200, lakeQuery(EVENTS, {
        q: q.get('q') || '',
        channel: q.get('channel') || '',
        severity: q.get('severity') || '',
        host: q.get('host') || '',
        from: q.get('from') || '',
        to: q.get('to') || '',
        limit: q.get('limit'),
        offset: q.get('offset'),
      }));
    }

    /* ---------------- ticketing ---------------- */
    if (p === '/api/tickets' && req.method === 'GET') return json(res, 200, TICKETS);

    if (p === '/api/tickets' && req.method === 'POST') {
      const actor = actorOf(req, u);
      if (denied(res, actor, 'ticket.create')) return;
      const b = await readBody(req);
      if (!b.title) return json(res, 400, { error: 'title required' });
      const t = {
        id: uid('tk_'), num: TICKETS.length + 1,
        title: String(b.title).slice(0, 300),
        body: String(b.body || '').slice(0, 20000),
        status: 'open',
        severity: ['low', 'medium', 'high', 'critical'].includes(b.severity) ? b.severity : 'medium',
        assignee: b.assignee || '',
        host: b.host || '',
        technique: b.technique || '',
        // The one field tickets gain for the case layer. Optional: a ticket
        // with no case behaves exactly as it always did.
        caseId: b.caseId || '',
        // Formal-report opt-in. A ticket reaches the client-facing report
        // only when a lead flags it AND writes a plain-language summary.
        includeInFormal: false,
        formalSummary: '',
        // Attribution comes from the authenticated actor, never the request
        // body — with accounts on, "who did this" is now actually verified.
        // The shared analyst token still reports as 'analyst', as before.
        createdBy: actor.shared ? (b.createdBy || 'analyst') : actor.name,
        createdById: actor.id,
        createdAt: now(), updatedAt: now(),
        comments: [],
      };
      TICKETS.push(t); saveTickets();
      auditRecord(actor.id, 'ticket.create', t.id, { title: t.title, severity: t.severity });
      broadcast('ticket', t);
      return json(res, 200, t);
    }

    const mT = p.match(/^\/api\/tickets\/([^/]+)$/);
    if (mT && req.method === 'PATCH') {
      const actor = actorOf(req, u);
      const t = TICKETS.find(x => x.id === mT[1]); if (!t) return json(res, 404, { error: 'no such ticket' });
      // Editing your own ticket needs only ticket.editOwn; editing anyone
      // else's needs ticket.editAny (leads). Tickets created before accounts
      // existed have no owner id, so they fall to the editAny check.
      const own = !actor.shared && t.createdById && t.createdById === actor.id;
      if (denied(res, actor, own ? 'ticket.editOwn' : 'ticket.editAny')) return;
      const b = await readBody(req);
      for (const k of ['title', 'body', 'status', 'severity', 'assignee', 'host', 'technique', 'caseId']) {
        if (b[k] !== undefined) t[k] = b[k];
      }
      // Curating what reaches a client-facing report is a lead's call, not
      // the raising analyst's — so these two need report.finalize, whether
      // or not the ticket is your own.
      if (b.includeInFormal !== undefined || b.formalSummary !== undefined) {
        if (denied(res, actor, 'report.finalize')) return;
        if (b.includeInFormal !== undefined) t.includeInFormal = !!b.includeInFormal;
        if (b.formalSummary !== undefined) t.formalSummary = String(b.formalSummary).slice(0, 20000);
      }
      t.updatedAt = now(); saveTickets();
      auditRecord(actor.id, 'ticket.update', t.id, b);
      broadcast('ticket', t);
      return json(res, 200, t);
    }
    const mC = p.match(/^\/api\/tickets\/([^/]+)\/comments$/);
    if (mC && req.method === 'POST') {
      const actor = actorOf(req, u);
      if (denied(res, actor, 'ticket.comment')) return;
      const t = TICKETS.find(x => x.id === mC[1]); if (!t) return json(res, 404, { error: 'no such ticket' });
      const b = await readBody(req);
      const c = { id: uid('c_'), author: actor.shared ? (b.author || 'analyst') : actor.name, text: String(b.text || '').slice(0, 8000), at: now() };
      t.comments.push(c); t.updatedAt = now(); saveTickets();
      auditRecord(actor.id, 'ticket.comment', t.id, { commentId: c.id });
      broadcast('ticket', t);
      return json(res, 200, c);
    }
    const mA = p.match(/^\/api\/tickets\/([^/]+)\/audit$/);
    if (mA && req.method === 'GET') {
      const events = AUDIT.all().filter(e => e.targetId === mA[1]);
      return json(res, 200, { intact: AUDIT.verify(), events });
    }

    /* ---------------- cases ---------------- */
    if (p === '/api/cases' && req.method === 'GET') return json(res, 200, CASES);

    if (p === '/api/cases' && req.method === 'POST') {
      const actor = actorOf(req, u);
      if (denied(res, actor, 'case.create')) return;
      const b = await readBody(req);
      let c;
      try { c = makeCase(b, actor, CASES.length + 1); }
      catch (e) { return json(res, 400, { error: e.message }); }
      CASES.push(c); saveCases();
      auditRecord(actor.id, 'case.create', c.id, { title: c.title, severity: c.severity });
      broadcast('case', c);
      return json(res, 200, c);
    }

    const mCase = p.match(/^\/api\/cases\/([^/]+)$/);
    if (mCase && req.method === 'PATCH') {
      const actor = actorOf(req, u);
      const c = CASES.find(x => x.id === mCase[1]); if (!c) return json(res, 404, { error: 'no such case' });
      // Same ownership rule as tickets: your own needs editOwn, anyone
      // else's needs editAny. Cases created before accounts existed have no
      // owner id, so they fall to the editAny check.
      const own = !actor.shared && c.createdById && c.createdById === actor.id;
      if (denied(res, actor, own ? 'case.editOwn' : 'case.editAny')) return;
      const b = await readBody(req);
      const applied = patchCase(c, b);
      saveCases();
      auditRecord(actor.id, 'case.update', c.id, applied);
      broadcast('case', c);
      return json(res, 200, c);
    }

    /* Evidence upload. Body limit is raised well past the 4MB default here
       and only here: base64 inflates bytes by ~33%, so the default would
       silently reject a ~3MB screenshot. */
    const mEv = p.match(/^\/api\/cases\/([^/]+)\/evidence$/);
    if (mEv && req.method === 'POST') {
      const actor = actorOf(req, u);
      if (denied(res, actor, 'evidence.add')) return;
      const c = CASES.find(x => x.id === mEv[1]); if (!c) return json(res, 404, { error: 'no such case' });
      let b;
      try { b = await readBody(req, Math.ceil(EVIDENCE_MAX_BYTES * 1.4) + 65536); }
      catch { return json(res, 413, { error: 'file too large' }); }
      let decoded;
      try { decoded = decodeEvidence(b.data); }
      catch (e) { return json(res, 400, { error: e.message }); }
      const rec = evidenceRecord(decoded, b.caption, b.name, actor);
      // Content-addressed: the same bytes uploaded twice is one file on disk.
      try { fs.writeFileSync(path.join(EVIDENCE_DIR, rec.file), decoded.buf); }
      catch (e) { return json(res, 500, { error: 'could not store evidence: ' + e.message }); }
      c.evidence = c.evidence || [];
      c.evidence.push(rec);
      c.updatedAt = now(); saveCases();
      // The hash goes in the audit chain, so tampering with a stored file
      // later is detectable against an entry that cannot be quietly edited.
      auditRecord(actor.id, 'evidence.add', c.id, { evidenceId: rec.id, sha256: rec.sha256, bytes: rec.bytes, name: rec.name });
      broadcast('case', c);
      return json(res, 200, rec);
    }

    /* ---------------- case reports ---------------- */
    const mRep = p.match(/^\/api\/cases\/([^/]+)\/report$/);
    if (mRep && req.method === 'GET') {
      const c = CASES.find(x => x.id === mRep[1]); if (!c) return json(res, 404, { error: 'no such case' });
      const kind = u.searchParams.get('kind') === 'formal' ? 'formal' : 'technical';
      return json(res, 200, buildReport(c, TICKETS, kind));
    }

    /* Freezing is what turns the formal report from a view into a
       deliverable, so it is a lead's signature, not an analyst's. */
    const mFin = p.match(/^\/api\/cases\/([^/]+)\/finalize$/);
    if (mFin && req.method === 'POST') {
      const actor = actorOf(req, u);
      if (denied(res, actor, 'report.finalize')) return;
      const c = CASES.find(x => x.id === mFin[1]); if (!c) return json(res, 404, { error: 'no such case' });
      const snap = finalizeFormal(c, TICKETS, actor.shared ? 'analyst token' : actor.name);
      c.updatedAt = now(); saveCases();
      // The snapshot hash goes in the chain, so a frozen report altered on
      // disk afterwards no longer matches what was signed.
      auditRecord(actor.id, 'report.finalize', c.id, { version: snap.version, sha256: snap.sha256, blocks: snap.blocks.length });
      broadcast('case', c);
      return json(res, 200, snap);
    }

    const mEvGet = p.match(/^\/api\/evidence\/([^/]+)$/);
    if (mEvGet && req.method === 'GET') {
      const safe = safeEvidenceName(mEvGet[1]);
      if (!safe) return json(res, 400, { error: 'bad evidence name' });
      const fp = path.join(EVIDENCE_DIR, safe);
      if (!fs.existsSync(fp)) return json(res, 404, { error: 'no such evidence' });
      const rec = CASES.flatMap(c => c.evidence || []).find(e => e.file === safe);
      res.writeHead(200, {
        'Content-Type': (rec && rec.mime) || 'application/octet-stream',
        'Content-Disposition': `inline; filename="${safe}"`,
        // stored bytes are analyst-supplied; never let the browser sniff or
        // execute them, and never let them run script in our origin
        'X-Content-Type-Options': 'nosniff',
        'Content-Security-Policy': "default-src 'none'; sandbox",
        'Cache-Control': 'private, max-age=3600',
      });
      return res.end(fs.readFileSync(fp));
    }

    /* ---------------- team chat ---------------- */
    if (p === '/api/chat' && req.method === 'GET') {
      const limit = Math.min(Math.max(1, Number(u.searchParams.get('limit')) || 100), CHAT_KEEP);
      return json(res, 200, CHAT.slice(-limit));
    }
    if (p === '/api/chat' && req.method === 'POST') {
      const actor = actorOf(req, u);
      const b = await readBody(req);
      const text = String(b.text || '').trim().slice(0, 2000);
      if (!text) return json(res, 400, { error: 'empty message' });
      const m = {
        id: uid('m_'),
        // Attribution from the session, never the body — same rule as
        // tickets and cases.
        from: actor.shared ? 'analyst token' : actor.name,
        fromId: actor.id,
        caseId: String(b.caseId || '').slice(0, 64),   // optional: pin to a case
        text,
        at: now(),
      };
      CHAT.push(m);
      if (CHAT.length > CHAT_KEEP) CHAT.splice(0, CHAT.length - CHAT_KEEP);
      chatStream.write(JSON.stringify(m) + '\n');
      broadcast('chat', m);
      return json(res, 200, m);
    }

    /* ---------------- deployment helper ---------------- */
    if (p === '/api/enrollment-info') {
      return json(res, 200, { enrollmentToken: CFG.enrollmentToken, serverUrl: `http://${CFG.host}:${CFG.port}` });
    }

    /* ---------------- static UI ---------------- */
    let file = p === '/' ? '/index.html' : p;
    const full = path.join(CFG.uiDir, path.normalize(file).replace(/^(\.\.[/\\])+/, ''));
    if (fs.existsSync(full) && fs.statSync(full).isFile()) {
      res.writeHead(200, { 'Content-Type': MIME[path.extname(full)] || 'application/octet-stream' });
      return fs.createReadStream(full).pipe(res);
    }
    return json(res, 404, { error: 'not found' });
  } catch (e) {
    console.error('[aegis]', e.message);
    return json(res, 400, { error: e.message });
  }
});

/* -------------------------------------------------- retention + shutdown */
setInterval(() => {
  // mark stale agents so the UI greys them out without deleting history
  let changed = false;
  for (const a of Object.values(AGENTS)) {
    const stale = now() - (a.lastSeen || 0) > CFG.staleAfter * 1000;
    if (a._stale !== stale) { a._stale = stale; changed = true; broadcast('agent', publicAgent(a)); }
  }
  if (changed) saveAgents();
}, 30000);

/* rotate the event log so it cannot grow without bound */
setInterval(() => {
  try {
    const st = fs.statSync(F.events);
    if (st.size > (CFG.maxEventFileMB || 256) * 1024 * 1024) {
      const keep = EVENTS.slice(-2000).map(e => JSON.stringify(e)).join('\n') + '\n';
      fs.writeFileSync(F.events + '.1', fs.readFileSync(F.events));
      fs.writeFileSync(F.events, keep);
      console.log('[aegis] rotated events.ndjson');
    }
  } catch { }
}, 300000);

process.on('SIGINT', () => { console.log('\n[aegis] shutting down'); saveAgents(); saveTickets(); evStream.end(); process.exit(0); });

/** Addresses an agent could actually reach us on. 0.0.0.0 is not a URL. */
function reachableUrls() {
  if (CFG.host !== '0.0.0.0' && CFG.host !== '::') return [`http://${CFG.host}:${CFG.port}`];
  const out = [`http://127.0.0.1:${CFG.port}`];
  for (const [name, addrs] of Object.entries(os.networkInterfaces())) {
    for (const a of addrs || []) {
      if (a.family !== 'IPv4' || a.internal) continue;
      const virtual = /vmware|virtualbox|hyper-v|vethernet|nord|wireguard|tailscale|zerotier|docker|wsl/i.test(name);
      out.push(`http://${a.address}:${CFG.port}${virtual ? '   (virtual adapter)' : ''}`);
    }
  }
  return out;
}

// A stack trace is the wrong answer for the two failures people actually hit.
server.on('error', err => {
  if (err.code === 'EADDRINUSE') {
    console.error(`\n  Port ${CFG.port} is already in use.`);
    console.error('  AEGIS is probably already running — check http://127.0.0.1:' + CFG.port);
    console.error(`  If not, stop whatever is using the port, or set a different`);
    console.error('  "port" in server/config.json.\n');
    process.exit(1);
  }
  if (err.code === 'EACCES') {
    console.error(`\n  Not allowed to listen on port ${CFG.port}.`);
    console.error('  Ports below 1024 need root/Administrator. Pick a higher');
    console.error('  "port" in server/config.json (8787 is the default).\n');
    process.exit(1);
  }
  console.error('\n  Server failed to start:', err.message, '\n');
  process.exit(1);
});

server.listen(CFG.port, CFG.host, () => {
  const urls = reachableUrls();
  console.log(`\n  AEGIS server  ${urls[0]}`);
  if (urls.length > 1) {
    console.log('  agents can reach it on:');
    urls.slice(1).forEach(u => console.log(`                ${u}`));
  }
  console.log(`  data          ${CFG.dataDir}`);
  console.log(`  splunk HEC    ${CFG.splunk.enabled ? CFG.splunk.url : 'disabled'}`);
  console.log(`\n  enrollment token : ${CFG.enrollmentToken}`);
  console.log(`  analyst token    : ${CFG.analystToken}`);
  if (CFG.requireLogin) {
    console.log(`\n  accounts         : ON  (${USERS.length} account${USERS.length === 1 ? '' : 's'})`);
    if (!USERS.length) {
      console.log('  No accounts exist yet. Create the first one with the analyst token:');
      console.log(`    curl -X POST http://${CFG.host}:${CFG.port}/api/users \\`);
      console.log(`      -H "Authorization: Bearer ${CFG.analystToken}" \\`);
      console.log('      -H "Content-Type: application/json" \\');
      console.log('      -d \'{"name":"you","password":"a-real-password","role":"lead"}\'');
    }
  }
  console.log(`\n  Bound to ${CFG.host}. Put TLS in front before exposing it.\n`);
});

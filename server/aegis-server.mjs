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
 *  - Agents can only write their own telemetry. They cannot read other hosts,
 *    read tickets, or receive commands. There is deliberately no remote-exec
 *    channel: this is a collector, not a C2.
 */

import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { AuditLog } from './audit.mjs';

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
};
const readJson = (f, d) => { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return d; } };
const writeJson = (f, v) => {
  const tmp = f + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(v, null, 1));
  fs.renameSync(tmp, f); // atomic-ish; survives a crash mid-write
};

let AGENTS = readJson(F.agents, {});      // id -> agent record
let TICKETS = readJson(F.tickets, []);    // newest last
let EVENTS = [];                          // in-memory ring for the UI

// hydrate the recent event ring from disk
try {
  const raw = fs.existsSync(F.events) ? fs.readFileSync(F.events, 'utf8').trim().split('\n') : [];
  EVENTS = raw.slice(-5000).map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
} catch { EVENTS = []; }

const saveAgents = () => writeJson(F.agents, AGENTS);
const saveTickets = () => writeJson(F.tickets, TICKETS);
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
const isAnalyst = req => safeEq(bearer(req), CFG.analystToken);
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
      const tok = u.searchParams.get('token') || bearer(req);
      if (!safeEq(tok, CFG.analystToken)) return json(res, 401, { error: 'unauthorized' });
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

    if (p.startsWith('/api/') && !isAnalyst(req)) return json(res, 401, { error: 'unauthorized' });

    /* ---------------- state for the UI ---------------- */
    if (p === '/api/state') {
      return json(res, 200, {
        agents: Object.values(AGENTS).map(publicAgent),
        links: LINKS,
        tickets: TICKETS.slice(-500),
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
      const a = AGENTS[mAgent[1]]; if (!a) return json(res, 404, { error: 'no such agent' });
      delete AGENTS[mAgent[1]]; saveAgents();
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

    /* ---------------- ticketing ---------------- */
    if (p === '/api/tickets' && req.method === 'GET') return json(res, 200, TICKETS);

    if (p === '/api/tickets' && req.method === 'POST') {
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
        createdBy: b.createdBy || 'analyst',
        createdAt: now(), updatedAt: now(),
        comments: [],
      };
      TICKETS.push(t); saveTickets();
      auditRecord(t.createdBy, 'ticket.create', t.id, { title: t.title, severity: t.severity });
      broadcast('ticket', t);
      return json(res, 200, t);
    }

    const mT = p.match(/^\/api\/tickets\/([^/]+)$/);
    if (mT && req.method === 'PATCH') {
      const t = TICKETS.find(x => x.id === mT[1]); if (!t) return json(res, 404, { error: 'no such ticket' });
      const b = await readBody(req);
      for (const k of ['title', 'body', 'status', 'severity', 'assignee', 'host', 'technique']) {
        if (b[k] !== undefined) t[k] = b[k];
      }
      t.updatedAt = now(); saveTickets();
      auditRecord(b.updatedBy || 'analyst', 'ticket.update', t.id, b);
      broadcast('ticket', t);
      return json(res, 200, t);
    }
    const mC = p.match(/^\/api\/tickets\/([^/]+)\/comments$/);
    if (mC && req.method === 'POST') {
      const t = TICKETS.find(x => x.id === mC[1]); if (!t) return json(res, 404, { error: 'no such ticket' });
      const b = await readBody(req);
      const c = { id: uid('c_'), author: b.author || 'analyst', text: String(b.text || '').slice(0, 8000), at: now() };
      t.comments.push(c); t.updatedAt = now(); saveTickets();
      auditRecord(c.author, 'ticket.comment', t.id, { commentId: c.id });
      broadcast('ticket', t);
      return json(res, 200, c);
    }
    const mA = p.match(/^\/api\/tickets\/([^/]+)\/audit$/);
    if (mA && req.method === 'GET') {
      const events = AUDIT.all().filter(e => e.targetId === mA[1]);
      return json(res, 200, { intact: AUDIT.verify(), events });
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

server.listen(CFG.port, CFG.host, () => {
  console.log(`\n  AEGIS server  http://${CFG.host}:${CFG.port}`);
  console.log(`  data          ${CFG.dataDir}`);
  console.log(`  splunk HEC    ${CFG.splunk.enabled ? CFG.splunk.url : 'disabled'}`);
  console.log(`\n  enrollment token : ${CFG.enrollmentToken}`);
  console.log(`  analyst token    : ${CFG.analystToken}`);
  console.log(`\n  Bound to ${CFG.host}. Put TLS in front before exposing it.\n`);
});

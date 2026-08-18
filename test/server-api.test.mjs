#!/usr/bin/env node
/**
 * End-to-end HTTP tests against a real server process. Zero dependencies.
 *
 * DESIGN RULE: stubs mimic hostile reality — and the most hostile reality for
 * this change is an EXISTING deployment. The whole point of Phase 4 is that
 * turning accounts on is opt-in and turning them off changes nothing, so the
 * first suite here boots the server in its default configuration and asserts
 * the old shared-token behaviour is byte-for-byte intact. Unit tests on
 * auth.mjs cannot catch a wiring mistake that locks out every existing user;
 * only driving the real HTTP surface can.
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

let pass = 0, fail = 0;
const ok = (name, cond, extra = '') => {
  if (cond) { pass++; console.log(`  ok   ${name}`); }
  else { fail++; console.log(`  FAIL ${name}${extra ? '  -> ' + extra : ''}`); }
};
const eq = (name, a, b) => ok(name, a === b, `${JSON.stringify(a)} !== ${JSON.stringify(b)}`);
const section = s => console.log(`\n${s}`);

/** Boot a server on a scratch dir with the given config; resolve when ready. */
async function boot(extraCfg = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-test-'));
  const port = 18000 + Math.floor(Math.random() * 2000);
  const cfg = {
    host: '127.0.0.1', port, dataDir: path.join(dir, 'data'), uiDir: path.join(ROOT, 'ui'),
    enrollmentToken: 'test-enroll-token', analystToken: 'test-analyst-token', ...extraCfg,
  };
  const cfgPath = path.join(dir, 'config.json');
  fs.writeFileSync(cfgPath, JSON.stringify(cfg));
  const proc = spawn(process.execPath, [path.join(ROOT, 'server', 'aegis-server.mjs'), '--config', cfgPath], { stdio: 'ignore' });
  const base = `http://127.0.0.1:${port}`;
  for (let i = 0; i < 100; i++) {                       // poll until it answers
    try { const r = await fetch(base + '/api/health'); if (r.ok) break; } catch { }
    await new Promise(r => setTimeout(r, 50));
  }
  return { base, proc, dir, stop() { try { proc.kill(); } catch { } try { fs.rmSync(dir, { recursive: true, force: true }); } catch { } } };
}
const api = (base, p, opts = {}) => fetch(base + p, {
  ...opts, headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
});
const withTok = (tok, opts = {}) => ({ ...opts, headers: { ...(opts.headers || {}), Authorization: 'Bearer ' + tok } });

/* ============ 1. default config: nothing about the old behaviour changes ============ */
section('backwards compatibility (requireLogin off — the default)');
{
  const S = await boot();
  try {
    let r = await api(S.base, '/api/state');
    eq('no credential is still 401', r.status, 401);

    r = await api(S.base, '/api/state', withTok('wrong-token'));
    eq('a wrong token is still 401', r.status, 401);

    r = await api(S.base, '/api/state', withTok('test-analyst-token'));
    eq('the analyst token still works', r.status, 200);

    r = await api(S.base, '/api/auth/mode');
    const mode = await r.json();
    eq('the console is told no login is required', mode.requireLogin, false);

    // the analyst token keeps full reach, exactly as before accounts existed
    r = await api(S.base, '/api/tickets', withTok('test-analyst-token', {
      method: 'POST', body: JSON.stringify({ title: 'compat check', severity: 'low' }),
    }));
    eq('the analyst token can still create tickets', r.status, 200);
    const t = await r.json();
    eq('attribution falls back to the old literal', t.createdBy, 'analyst');

    r = await api(S.base, `/api/tickets/${t.id}`, withTok('test-analyst-token', {
      method: 'PATCH', body: JSON.stringify({ status: 'contained' }),
    }));
    eq('the analyst token can still edit any ticket', r.status, 200);

    r = await api(S.base, '/api/agents/nope', withTok('test-analyst-token', { method: 'DELETE' }));
    eq('the analyst token still reaches agent management (404, not 403)', r.status, 404);

    r = await api(S.base, '/api/lake?q=severity:malicious', withTok('test-analyst-token'));
    eq('the analyst token can query the lake', r.status, 200);
  } finally { S.stop(); }
}

/* ============ 2. accounts enabled ============ */
section('accounts enabled (requireLogin on)');
{
  const S = await boot({ requireLogin: true });
  try {
    let r = await api(S.base, '/api/auth/mode');
    eq('the console is told to show a login', (await r.json()).requireLogin, true);

    // The analyst token must still work, or enabling accounts on a running
    // server would lock out the very person doing it.
    r = await api(S.base, '/api/state', withTok('test-analyst-token'));
    eq('the analyst token still works as break-glass', r.status, 200);

    r = await api(S.base, '/api/auth/me', withTok('test-analyst-token'));
    const me = await r.json();
    eq('the shared token reports itself as shared', me.shared, true);
    eq('the shared token carries the top role', me.role, 'lead');

    // bootstrap the first accounts using the break-glass credential
    r = await api(S.base, '/api/users', withTok('test-analyst-token', {
      method: 'POST', body: JSON.stringify({ name: 'lead1', password: 'pw-lead-12345', role: 'lead' }),
    }));
    eq('a lead account can be created', r.status, 200);
    r = await api(S.base, '/api/users', withTok('test-analyst-token', {
      method: 'POST', body: JSON.stringify({ name: 'ana1', password: 'pw-ana-12345', role: 'analyst' }),
    }));
    eq('an analyst account can be created', r.status, 200);
    r = await api(S.base, '/api/users', withTok('test-analyst-token', {
      method: 'POST', body: JSON.stringify({ name: 'ana1', password: 'x', role: 'analyst' }),
    }));
    eq('a duplicate name is rejected', r.status, 409);

    /* --- login --- */
    r = await api(S.base, '/api/auth/login', { method: 'POST', body: JSON.stringify({ name: 'ana1', password: 'wrong' }) });
    eq('a wrong password is 401', r.status, 401);
    r = await api(S.base, '/api/auth/login', { method: 'POST', body: JSON.stringify({ name: 'nobody', password: 'x' }) });
    eq('an unknown user is 401 (same as a wrong password)', r.status, 401);

    r = await api(S.base, '/api/auth/login', { method: 'POST', body: JSON.stringify({ name: 'ana1', password: 'pw-ana-12345' }) });
    eq('a correct password logs in', r.status, 200);
    const ana = await r.json();
    ok('a session token is issued', typeof ana.token === 'string' && ana.token.length > 20);
    ok('the login response never carries the hash', !JSON.stringify(ana).includes('hash'));

    r = await api(S.base, '/api/auth/login', { method: 'POST', body: JSON.stringify({ name: 'lead1', password: 'pw-lead-12345' }) });
    const lead = await (r).json();

    /* --- the session token works like a credential --- */
    r = await api(S.base, '/api/state', withTok(ana.token));
    eq('a session token authenticates', r.status, 200);
    r = await api(S.base, '/api/auth/me', withTok(ana.token));
    const anaMe = await r.json();
    eq('me reports the real account name', anaMe.name, 'ana1');
    eq('me reports the real role', anaMe.role, 'analyst');
    eq('a named account is not marked shared', anaMe.shared, false);

    /* --- capability enforcement, the actual point of roles --- */
    r = await api(S.base, '/api/users', withTok(ana.token));
    eq('an analyst CANNOT list users', r.status, 403);
    r = await api(S.base, '/api/agents/whatever', withTok(ana.token, { method: 'DELETE' }));
    eq('an analyst CANNOT remove an agent', r.status, 403);
    r = await api(S.base, '/api/users', withTok(lead.token));
    eq('a lead CAN list users', r.status, 200);

    /* --- ownership: own vs anyone else's ticket --- */
    r = await api(S.base, '/api/tickets', withTok(ana.token, {
      method: 'POST', body: JSON.stringify({ title: 'analyst ticket' }),
    }));
    const anaTicket = await r.json();
    eq('attribution comes from the session, not the body', anaTicket.createdBy, 'ana1');

    r = await api(S.base, '/api/tickets', withTok(ana.token, {
      method: 'POST', body: JSON.stringify({ title: 'spoof attempt', createdBy: 'somebody-else' }),
    }));
    const spoof = await r.json();
    eq('a client-supplied createdBy is ignored', spoof.createdBy, 'ana1');

    r = await api(S.base, `/api/tickets/${anaTicket.id}`, withTok(ana.token, {
      method: 'PATCH', body: JSON.stringify({ status: 'contained' }),
    }));
    eq('an analyst can edit their OWN ticket', r.status, 200);

    r = await api(S.base, '/api/tickets', withTok(lead.token, {
      method: 'POST', body: JSON.stringify({ title: 'lead ticket' }),
    }));
    const leadTicket = await r.json();
    r = await api(S.base, `/api/tickets/${leadTicket.id}`, withTok(ana.token, {
      method: 'PATCH', body: JSON.stringify({ status: 'closed' }),
    }));
    eq('an analyst CANNOT edit someone else\'s ticket', r.status, 403);
    r = await api(S.base, `/api/tickets/${anaTicket.id}`, withTok(lead.token, {
      method: 'PATCH', body: JSON.stringify({ status: 'closed' }),
    }));
    eq('a lead CAN edit anyone\'s ticket', r.status, 200);

    /* --- logout revokes immediately --- */
    r = await api(S.base, '/api/auth/logout', withTok(ana.token, { method: 'POST' }));
    eq('logout succeeds', r.status, 200);
    r = await api(S.base, '/api/state', withTok(ana.token));
    eq('the revoked session is rejected immediately', r.status, 401);

    /* --- a password change must kill live sessions --- */
    r = await api(S.base, '/api/auth/login', { method: 'POST', body: JSON.stringify({ name: 'lead1', password: 'pw-lead-12345' }) });
    const lead2 = await r.json();
    const users = await (await api(S.base, '/api/users', withTok('test-analyst-token'))).json();
    const leadId = users.find(x => x.name === 'lead1').id;
    r = await api(S.base, `/api/users/${leadId}`, withTok('test-analyst-token', {
      method: 'PATCH', body: JSON.stringify({ password: 'brand-new-password' }),
    }));
    eq('a password can be changed', r.status, 200);
    r = await api(S.base, '/api/state', withTok(lead2.token));
    eq('changing a password invalidates that user\'s live sessions', r.status, 401);

    /* --- deleting an account kills its sessions too --- */
    r = await api(S.base, '/api/auth/login', { method: 'POST', body: JSON.stringify({ name: 'lead1', password: 'brand-new-password' }) });
    const lead3 = await r.json();
    eq('the new password works', typeof lead3.token, 'string');
    r = await api(S.base, `/api/users/${leadId}`, withTok('test-analyst-token', { method: 'DELETE' }));
    eq('an account can be deleted', r.status, 200);
    r = await api(S.base, '/api/state', withTok(lead3.token));
    eq('a deleted account\'s session dies with it', r.status, 401);
  } finally { S.stop(); }
}

/* ============ 3. lockout over real HTTP ============ */
section('login lockout (over HTTP)');
{
  const S = await boot({ requireLogin: true });
  try {
    await api(S.base, '/api/users', withTok('test-analyst-token', {
      method: 'POST', body: JSON.stringify({ name: 'target', password: 'right-password', role: 'analyst' }),
    }));
    let last;
    for (let i = 0; i < 5; i++) {
      last = await api(S.base, '/api/auth/login', { method: 'POST', body: JSON.stringify({ name: 'target', password: 'nope' }) });
    }
    eq('the fifth wrong password is still 401', last.status, 401);
    const after = await api(S.base, '/api/auth/login', { method: 'POST', body: JSON.stringify({ name: 'target', password: 'nope' }) });
    eq('further attempts are rate-limited with 429', after.status, 429);
    // and the lock holds even against the CORRECT password — otherwise it is
    // no defence at all against an attacker who eventually guesses right
    const right = await api(S.base, '/api/auth/login', { method: 'POST', body: JSON.stringify({ name: 'target', password: 'right-password' }) });
    eq('the lock holds even for the correct password', right.status, 429);
  } finally { S.stop(); }
}

/* ============ 4. session survives a server restart ============ */
section('sessions survive a restart');
{
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-restart-'));
  const port = 18500 + Math.floor(Math.random() * 400);
  const cfgPath = path.join(dir, 'config.json');
  fs.writeFileSync(cfgPath, JSON.stringify({
    host: '127.0.0.1', port, dataDir: path.join(dir, 'data'), uiDir: path.join(ROOT, 'ui'),
    enrollmentToken: 'e', analystToken: 'test-analyst-token', requireLogin: true,
  }));
  const start = async () => {
    const proc = spawn(process.execPath, [path.join(ROOT, 'server', 'aegis-server.mjs'), '--config', cfgPath], { stdio: 'ignore' });
    const base = `http://127.0.0.1:${port}`;
    for (let i = 0; i < 100; i++) {
      try { const r = await fetch(base + '/api/health'); if (r.ok) break; } catch { }
      await new Promise(r => setTimeout(r, 50));
    }
    return { base, proc };
  };
  let s = await start();
  try {
    await api(s.base, '/api/users', withTok('test-analyst-token', {
      method: 'POST', body: JSON.stringify({ name: 'persist', password: 'pw-persist-123', role: 'analyst' }),
    }));
    const login = await (await api(s.base, '/api/auth/login', {
      method: 'POST', body: JSON.stringify({ name: 'persist', password: 'pw-persist-123' }),
    })).json();
    s.proc.kill();
    await new Promise(r => setTimeout(r, 300));
    s = await start();
    const r = await api(s.base, '/api/state', withTok(login.token));
    eq('a session issued before a restart still works after it', r.status, 200);
    const r2 = await api(s.base, '/api/auth/login', {
      method: 'POST', body: JSON.stringify({ name: 'persist', password: 'pw-persist-123' }),
    });
    eq('the account itself survived the restart', r2.status, 200);
  } finally {
    try { s.proc.kill(); } catch { }
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { }
  }
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

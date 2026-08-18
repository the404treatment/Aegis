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
import crypto from 'node:crypto';
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

/* ============ 1. token-only deploys keep working ============ */
/* Accounts are now the default, so this section pins the OTHER promise: a
   deployment that opts out with requireLogin:false must behave exactly as it
   did before accounts existed. */
section('backwards compatibility (requireLogin explicitly off)');
{
  const S = await boot({ requireLogin: false });
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
    eq('...and is not offered a first-run setup it does not need', mode.needsSetup, false);

    // With accounts off there is no such thing as a first account, so the
    // bootstrap door must not be ajar.
    r = await api(S.base, '/api/auth/bootstrap', {
      method: 'POST', body: JSON.stringify({ name: 'sneak', password: 'pw-sneak-12345' }),
    });
    ok('bootstrap creates nothing when accounts are off', r.status !== 200, 'HTTP ' + r.status);

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

/* ============ 1b. first-run bootstrap ============ */
/* Accounts are on by default, so a brand-new server demands a login it has no
   account for. The bootstrap door exists to break that deadlock — and must
   slam shut the instant it has been used, or it is a permanent way in. */
section('first-run bootstrap (the default state of a new server)');
{
  const S = await boot();   // no config overrides: this IS the default now
  try {
    let r = await api(S.base, '/api/auth/mode');
    let mode = await r.json();
    eq('accounts are on by default', mode.requireLogin, true);
    eq('a fresh server advertises that it needs setting up', mode.needsSetup, true);
    eq('...and reports having no accounts', mode.accounts, 0);

    // A password the auth layer would reject must not create a half-made
    // server that can never be bootstrapped again.
    r = await api(S.base, '/api/auth/bootstrap', {
      method: 'POST', body: JSON.stringify({ name: 'lead', password: 'short' }),
    });
    eq('a weak password is refused', r.status, 400);
    mode = await (await api(S.base, '/api/auth/mode')).json();
    eq('...and leaves the server still bootstrappable', mode.needsSetup, true);

    r = await api(S.base, '/api/auth/bootstrap', {
      method: 'POST', body: JSON.stringify({ name: 'first', password: 'pw-first-12345' }),
    });
    eq('the first account is created without a credential', r.status, 200);
    const first = await r.json();
    eq('it is a lead, so it can create everyone else', first.user.role, 'lead');
    ok('and it is signed straight in', !!first.token);

    r = await api(S.base, '/api/state', withTok(first.token));
    eq('the returned session works immediately', r.status, 200);

    // THE point of the test: the door is now shut.
    r = await api(S.base, '/api/auth/bootstrap', {
      method: 'POST', body: JSON.stringify({ name: 'intruder', password: 'pw-intruder-12345' }),
    });
    eq('a second bootstrap is refused', r.status, 409);

    mode = await (await api(S.base, '/api/auth/mode')).json();
    eq('the console stops offering setup', mode.needsSetup, false);
    eq('...but still asks for a login', mode.requireLogin, true);

    // And the ordinary route still requires the capability.
    r = await api(S.base, '/api/users', {
      method: 'POST', body: JSON.stringify({ name: 'x', password: 'pw-x-123456789', role: 'lead' }),
    });
    eq('unauthenticated account creation is still refused', r.status, 401);

    r = await api(S.base, '/api/users', withTok(first.token, {
      method: 'POST', body: JSON.stringify({ name: 'second', password: 'pw-second-12345', role: 'analyst' }),
    }));
    eq('the bootstrapped lead can create the next account', r.status, 200);
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

/* ============ 2b. cases and evidence ============ */
section('cases and evidence (over HTTP)');
{
  const S = await boot({ requireLogin: true });
  try {
    const T = withTok('test-analyst-token');
    await api(S.base, '/api/users', withTok('test-analyst-token', {
      method: 'POST', body: JSON.stringify({ name: 'ana', password: 'pw-ana-12345', role: 'analyst' }),
    }));
    await api(S.base, '/api/users', withTok('test-analyst-token', {
      method: 'POST', body: JSON.stringify({ name: 'lead', password: 'pw-lead-12345', role: 'lead' }),
    }));
    const ana = await (await api(S.base, '/api/auth/login', { method: 'POST', body: JSON.stringify({ name: 'ana', password: 'pw-ana-12345' }) })).json();
    const lead = await (await api(S.base, '/api/auth/login', { method: 'POST', body: JSON.stringify({ name: 'lead', password: 'pw-lead-12345' }) })).json();

    let r = await api(S.base, '/api/cases', withTok(ana.token, { method: 'POST', body: JSON.stringify({ title: 'Ransomware on FS01' }) }));
    eq('an analyst can open a case', r.status, 200);
    const c = await r.json();
    eq('case attribution comes from the session', c.createdBy, 'ana');
    eq('a new case starts open', c.status, 'open');

    r = await api(S.base, '/api/cases', withTok(ana.token, { method: 'POST', body: JSON.stringify({}) }));
    eq('a case with no title is rejected', r.status, 400);

    /* --- ownership, same rule as tickets --- */
    r = await api(S.base, `/api/cases/${c.id}`, withTok(ana.token, { method: 'PATCH', body: JSON.stringify({ status: 'contained', execSummary: 'wrote it up' }) }));
    eq('the owner can edit their own case', r.status, 200);
    eq('the narrative saved', (await r.json()).execSummary, 'wrote it up');

    const leadCase = await (await api(S.base, '/api/cases', withTok(lead.token, { method: 'POST', body: JSON.stringify({ title: 'lead case' }) }))).json();
    r = await api(S.base, `/api/cases/${leadCase.id}`, withTok(ana.token, { method: 'PATCH', body: JSON.stringify({ status: 'closed' }) }));
    eq('an analyst CANNOT edit someone else\'s case', r.status, 403);
    r = await api(S.base, `/api/cases/${c.id}`, withTok(lead.token, { method: 'PATCH', body: JSON.stringify({ status: 'recovered' }) }));
    eq('a lead CAN edit anyone\'s case', r.status, 200);

    /* --- tickets link to cases with one optional field --- */
    r = await api(S.base, '/api/tickets', withTok(ana.token, { method: 'POST', body: JSON.stringify({ title: 'in the case', caseId: c.id }) }));
    const linked = await r.json();
    eq('a ticket can be created attached to a case', linked.caseId, c.id);
    const loose = await (await api(S.base, '/api/tickets', withTok(ana.token, { method: 'POST', body: JSON.stringify({ title: 'no case' }) }))).json();
    eq('a ticket with no case still works exactly as before', loose.caseId, '');
    r = await api(S.base, `/api/tickets/${loose.id}`, withTok(ana.token, { method: 'PATCH', body: JSON.stringify({ caseId: c.id }) }));
    eq('an existing ticket can be attached later', (await r.json()).caseId, c.id);

    /* --- evidence round-trip, hash verified against the bytes --- */
    const bytes = 'evidence file contents';
    const expected = crypto.createHash('sha256').update(Buffer.from(bytes)).digest('hex');
    r = await api(S.base, `/api/cases/${c.id}/evidence`, withTok(ana.token, {
      method: 'POST',
      body: JSON.stringify({ data: 'data:text/plain;base64,' + Buffer.from(bytes).toString('base64'), name: 'notes.txt', caption: 'collected from the host' }),
    }));
    eq('evidence uploads', r.status, 200);
    const ev = await r.json();
    eq('the stored hash matches the bytes we sent', ev.sha256, expected);
    eq('the stored filename is the hash', ev.file, expected + '.txt');

    r = await api(S.base, `/api/evidence/${ev.file}`, withTok(ana.token));
    eq('evidence can be fetched back', r.status, 200);
    eq('the bytes round-trip unchanged', await r.text(), bytes);
    eq('the response refuses content sniffing', r.headers.get('x-content-type-options'), 'nosniff');

    r = await api(S.base, `/api/evidence/${ev.file}`);
    eq('evidence is NOT readable without a credential', r.status, 401);

    r = await api(S.base, '/api/evidence/..%2F..%2Fconfig.json', withTok(ana.token));
    ok('a traversal attempt is refused', r.status === 400 || r.status === 404);

    r = await api(S.base, `/api/cases/${c.id}/evidence`, withTok(ana.token, {
      method: 'POST', body: JSON.stringify({ data: 'data:image/svg+xml;base64,' + Buffer.from('<svg onload=alert(1)/>').toString('base64'), name: 'x.svg' }),
    }));
    eq('an SVG is refused (it could run script in our origin)', r.status, 400);

    r = await api(S.base, `/api/cases/nope/evidence`, withTok(ana.token, {
      method: 'POST', body: JSON.stringify({ data: 'data:text/plain;base64,eA==' }),
    }));
    eq('evidence for a missing case is 404', r.status, 404);

    /* --- the hash is written into the tamper-evident chain --- */
    const cases = await (await api(S.base, '/api/cases', T)).json();
    const stored = cases.find(x => x.id === c.id);
    eq('the case carries its evidence', stored.evidence.length, 1);
    eq('and it is the one we uploaded', stored.evidence[0].sha256, expected);
  } finally { S.stop(); }
}

/* ============ 2c. formal report curation and freeze ============ */
section('formal report freeze (over HTTP)');
{
  const S = await boot({ requireLogin: true });
  try {
    await api(S.base, '/api/users', withTok('test-analyst-token', {
      method: 'POST', body: JSON.stringify({ name: 'ana', password: 'pw-ana-12345', role: 'analyst' }),
    }));
    await api(S.base, '/api/users', withTok('test-analyst-token', {
      method: 'POST', body: JSON.stringify({ name: 'lead', password: 'pw-lead-12345', role: 'lead' }),
    }));
    const ana = await (await api(S.base, '/api/auth/login', { method: 'POST', body: JSON.stringify({ name: 'ana', password: 'pw-ana-12345' }) })).json();
    const lead = await (await api(S.base, '/api/auth/login', { method: 'POST', body: JSON.stringify({ name: 'lead', password: 'pw-lead-12345' }) })).json();

    const c = await (await api(S.base, '/api/cases', withTok(lead.token, {
      method: 'POST', body: JSON.stringify({ title: 'Incident', execSummary: 'the summary' }),
    }))).json();
    const t = await (await api(S.base, '/api/tickets', withTok(ana.token, {
      method: 'POST', body: JSON.stringify({ title: 'Finding one', body: 'RAW-TECHNICAL-DETAIL', caseId: c.id, severity: 'high' }),
    }))).json();

    /* --- curation is a lead's call, not the raising analyst's --- */
    let r = await api(S.base, `/api/tickets/${t.id}`, withTok(ana.token, {
      method: 'PATCH', body: JSON.stringify({ includeInFormal: true }),
    }));
    eq('an analyst CANNOT flag their own ticket into the formal report', r.status, 403);
    r = await api(S.base, `/api/tickets/${t.id}`, withTok(ana.token, {
      method: 'PATCH', body: JSON.stringify({ formalSummary: 'sneaking a summary in' }),
    }));
    eq('an analyst CANNOT write the formal summary either', r.status, 403);
    r = await api(S.base, `/api/tickets/${t.id}`, withTok(ana.token, {
      method: 'PATCH', body: JSON.stringify({ status: 'contained' }),
    }));
    eq('but an analyst can still edit their own ticket normally', r.status, 200);

    /* --- freezing needs the lead role --- */
    r = await api(S.base, `/api/cases/${c.id}/finalize`, withTok(ana.token, { method: 'POST' }));
    eq('an analyst CANNOT freeze the formal report', r.status, 403);

    /* --- the two-part gate, over the wire --- */
    r = await api(S.base, `/api/cases/${c.id}/report?kind=formal`, withTok(lead.token));
    eq('nothing qualifies before curation', (await r.json()).blocks.length, 0);

    await api(S.base, `/api/tickets/${t.id}`, withTok(lead.token, { method: 'PATCH', body: JSON.stringify({ includeInFormal: true }) }));
    r = await api(S.base, `/api/cases/${c.id}/report?kind=formal`, withTok(lead.token));
    eq('flagged but unwritten still does not qualify', (await r.json()).blocks.length, 0);

    await api(S.base, `/api/tickets/${t.id}`, withTok(lead.token, { method: 'PATCH', body: JSON.stringify({ formalSummary: 'A system was affected and restored.' }) }));
    r = await api(S.base, `/api/cases/${c.id}/report?kind=formal`, withTok(lead.token));
    const formalLive = await r.json();
    eq('flagged AND written qualifies', formalLive.blocks.length, 1);
    ok('the raw technical detail never reaches the formal report', !JSON.stringify(formalLive).includes('RAW-TECHNICAL-DETAIL'));
    ok('the analyst name never reaches the formal report', !JSON.stringify(formalLive).includes('"ana"'));

    r = await api(S.base, `/api/cases/${c.id}/report?kind=technical`, withTok(ana.token));
    const tech = await r.json();
    ok('the technical report DOES carry the raw detail', JSON.stringify(tech).includes('RAW-TECHNICAL-DETAIL'));
    eq('and credits the analyst', tech.blocks[0].raisedBy, 'ana');

    /* --- freeze, then prove it stopped tracking --- */
    r = await api(S.base, `/api/cases/${c.id}/finalize`, withTok(lead.token, { method: 'POST' }));
    eq('a lead CAN freeze', r.status, 200);
    const snap = await r.json();
    eq('first freeze is version 1', snap.version, 1);
    eq('signed by the lead', snap.frozenBy, 'lead');
    ok('carries a snapshot hash', /^[a-f0-9]{64}$/.test(snap.sha256));

    await api(S.base, `/api/tickets/${t.id}`, withTok(lead.token, { method: 'PATCH', body: JSON.stringify({ formalSummary: 'CHANGED AFTER FREEZING' }) }));
    r = await api(S.base, `/api/cases/${c.id}/report?kind=formal`, withTok(lead.token));
    const afterEdit = await r.json();
    eq('the frozen report ignores later edits', afterEdit.blocks[0].body, 'A system was affected and restored.');
    eq('and still reports as frozen', afterEdit.frozen, true);

    // The technical report tracks the ticket body (the working detail), not
    // the lead's formal summary — so edit the body to prove it stays live.
    await api(S.base, `/api/tickets/${t.id}`, withTok(lead.token, { method: 'PATCH', body: JSON.stringify({ body: 'DETAIL-UPDATED-AFTER-FREEZING' }) }));
    r = await api(S.base, `/api/cases/${c.id}/report?kind=technical`, withTok(lead.token));
    ok('while the technical view moved on', JSON.stringify(await r.json()).includes('DETAIL-UPDATED-AFTER-FREEZING'));
    r = await api(S.base, `/api/cases/${c.id}/report?kind=formal`, withTok(lead.token));
    ok('and the frozen formal report did not', !JSON.stringify(await r.json()).includes('DETAIL-UPDATED-AFTER-FREEZING'));

    r = await api(S.base, `/api/cases/${c.id}/finalize`, withTok(lead.token, { method: 'POST' }));
    const snap2 = await r.json();
    eq('re-freezing bumps to version 2', snap2.version, 2);
    eq('and publishes the newer text', snap2.blocks[0].body, 'CHANGED AFTER FREEZING');

    r = await api(S.base, '/api/cases/nope/finalize', withTok(lead.token, { method: 'POST' }));
    eq('freezing a missing case is 404', r.status, 404);
  } finally { S.stop(); }
}

/* ============ 2d. team chat ============ */
section('team chat (over HTTP)');
{
  const S = await boot({ requireLogin: true });
  try {
    await api(S.base, '/api/users', withTok('test-analyst-token', {
      method: 'POST', body: JSON.stringify({ name: 'ana', password: 'pw-ana-12345', role: 'analyst' }),
    }));
    const ana = await (await api(S.base, '/api/auth/login', { method: 'POST', body: JSON.stringify({ name: 'ana', password: 'pw-ana-12345' }) })).json();

    let r = await api(S.base, '/api/chat');
    eq('chat is not readable unauthenticated', r.status, 401);

    r = await api(S.base, '/api/chat', withTok(ana.token, { method: 'POST', body: JSON.stringify({ text: 'FS01 is isolated' }) }));
    eq('an analyst can post', r.status, 200);
    const m = await r.json();
    eq('attribution comes from the session', m.from, 'ana');

    r = await api(S.base, '/api/chat', withTok(ana.token, {
      method: 'POST', body: JSON.stringify({ text: 'spoofed', from: 'somebody-else', fromId: 'u_evil' }),
    }));
    const spoof = await r.json();
    eq('a client-supplied from is ignored', spoof.from, 'ana');
    ok('a client-supplied fromId is ignored', spoof.fromId !== 'u_evil');

    r = await api(S.base, '/api/chat', withTok(ana.token, { method: 'POST', body: JSON.stringify({ text: '   ' }) }));
    eq('an empty message is rejected', r.status, 400);

    const long = await (await api(S.base, '/api/chat', withTok(ana.token, { method: 'POST', body: JSON.stringify({ text: 'x'.repeat(5000) }) }))).json();
    ok('an overlong message is clamped', long.text.length <= 2000);

    r = await api(S.base, '/api/chat', withTok(ana.token));
    const history = await r.json();
    ok('history returns what was posted', history.some(x => x.text === 'FS01 is isolated'));
    eq('history is oldest-first', history[0].text, 'FS01 is isolated');

    const one = await (await api(S.base, '/api/chat?limit=1', withTok(ana.token))).json();
    eq('limit is honoured', one.length, 1);
    eq('and returns the newest', one[0].id, long.id);

    // chat rides the state payload so a fresh console has context immediately
    const st = await (await api(S.base, '/api/state', withTok(ana.token))).json();
    ok('state carries recent chat', Array.isArray(st.chat) && st.chat.length > 0);
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

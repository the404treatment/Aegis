#!/usr/bin/env node
/**
 * Agent enrollment identity tests. Zero dependencies.
 *
 * WHY THIS FILE EXISTS
 *
 * Enrollment used to match purely on hostname: any machine holding the
 * enrollment token that claimed an existing hostname was treated as that
 * agent reinstalling, silently inheriting its record and issuing it a fresh
 * key. Default and cloned hostnames (DESKTOP-XXXXX, unsysprepped VM
 * templates) collide across unrelated machines constantly, so this was a
 * real telemetry-attribution bug, not a theoretical one. The fix adds an
 * optional, agent-persisted `machineId`: when a record already has one on
 * file and a re-enrollment disagrees, it is treated as a different machine,
 * not a reinstall.
 *
 * DESIGN RULE: stubs mimic hostile reality. The interesting case here is not
 * "the agent reinstalls itself" - it is "something else claims a hostname
 * that already belongs to someone" - and it must be a NEW record, not a
 * silent merge, for AEGIS's own attribution to remain trustworthy.
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
let pass = 0, fail = 0;
const ok = (name, cond, extra = '') => {
  if (cond) { pass++; console.log(`  ok   ${name}`); }
  else { fail++; console.log(`  FAIL ${name}${extra ? '  -> ' + extra : ''}`); }
};
const section = s => console.log(`\n${s}`);

async function boot() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-agents-'));
  const port = 19300 + Math.floor(Math.random() * 400);
  const cfgPath = path.join(dir, 'config.json');
  fs.writeFileSync(cfgPath, JSON.stringify({
    host: '127.0.0.1', port, dataDir: path.join(dir, 'data'), uiDir: path.join(ROOT, 'ui'),
    enrollmentToken: 'e-tok', analystToken: 'a-tok', requireLogin: false,
    llm: { enabled: false },
  }));
  const proc = spawn(process.execPath, [path.join(ROOT, 'server', 'aegis-server.mjs'), '--config', cfgPath], { stdio: 'ignore' });
  const base = `http://127.0.0.1:${port}`;
  for (let i = 0; i < 100; i++) {
    try { const r = await fetch(base + '/api/health'); if (r.ok) break; } catch { }
    await new Promise(r => setTimeout(r, 50));
  }
  return { base, stop() { try { proc.kill(); } catch { } try { fs.rmSync(dir, { recursive: true, force: true }); } catch { } } };
}

const enroll = (base, body) => fetch(base + '/api/enroll', {
  method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ enrollmentToken: 'e-tok', ...body }),
}).then(r => r.json());

const agents = base => fetch(base + '/api/agents', { headers: { Authorization: 'Bearer a-tok' } }).then(r => r.json());

const S = await boot();
try {
  section('a fresh hostname enrolls a new agent');
  const first = await enroll(S.base, { hostname: 'WKS-001', os: 'windows', machineId: 'mid-a' });
  ok('an agentId comes back', !!first.agentId);
  let list = await agents(S.base);
  ok('exactly one agent exists', list.length === 1);

  section('re-enrolling with the same machineId reuses the record (real reinstall)');
  const reinstall = await enroll(S.base, { hostname: 'WKS-001', os: 'windows', machineId: 'mid-a' });
  ok('same agentId comes back', reinstall.agentId === first.agentId);
  ok('the key rotated', reinstall.agentKey !== first.agentKey);
  list = await agents(S.base);
  ok('still exactly one agent', list.length === 1);

  section('a pre-machineId agent adopts one on its first upgraded check-in');
  const noMidYet = await enroll(S.base, { hostname: 'WKS-002', os: 'linux' }); // no machineId - simulates an old agent
  list = await agents(S.base);
  ok('a second, independent agent exists', list.length === 2);
  const firstUpgrade = await enroll(S.base, { hostname: 'WKS-002', os: 'linux', machineId: 'mid-b' });
  ok('same agentId - adopting a machineId for the first time is not a collision', firstUpgrade.agentId === noMidYet.agentId);
  list = await agents(S.base);
  ok('still exactly two agents', list.length === 2);

  section('an old agent with no machineId re-enrolling against a record that has one is not flagged');
  const stillNoMid = await enroll(S.base, { hostname: 'WKS-002', os: 'linux' }); // reverted / unmodified deploy tooling
  ok('same agentId - missing data is never treated as a collision', stillNoMid.agentId === firstUpgrade.agentId);
  list = await agents(S.base);
  ok('still exactly two agents', list.length === 2);

  section('a different machine claiming an existing, machineId-bound hostname gets its own record');
  const impostor = await enroll(S.base, { hostname: 'WKS-001', os: 'windows', machineId: 'mid-c' });
  ok('a different agentId comes back, not the original', impostor.agentId !== first.agentId && !!impostor.agentId);
  list = await agents(S.base);
  ok('a third agent now exists - nothing was silently merged', list.length === 3);
  const dupes = list.filter(a => a.hostname.toLowerCase() === 'wks-001');
  ok('both WKS-001 records are visible for a lead to review', dupes.length === 2);

  section('the original record is untouched by the collision');
  const original = list.find(a => a.id === first.agentId);
  ok('the original agent is still there under its own id', !!original);
} finally { S.stop(); }

console.log(`\n${fail ? 'FAILED' : 'PASSED'}  ${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);

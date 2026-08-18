#!/usr/bin/env node
/**
 * Audit-chain tests. Zero dependencies, node --test compatible runner
 * (matches test/ui.test.mjs's own zero-dep convention).
 *
 * DESIGN RULE: this is the server-side equivalent of ui.test.mjs's
 * reload-survival philosophy — a chain that "verifies" only in memory and
 * breaks on a real restart is exactly the kind of bug that testing rule
 * exists to catch, so `load()` rehydration is tested explicitly, not just
 * a fresh in-memory chain.
 */
import { AuditLog } from '../server/audit.mjs';

let pass = 0, fail = 0;
const ok = (name, cond, extra = '') => {
  if (cond) { pass++; console.log(`  ok   ${name}`); }
  else { fail++; console.log(`  FAIL ${name}${extra ? '  -> ' + extra : ''}`); }
};
const eq = (name, a, b) => ok(name, a === b, `${JSON.stringify(a)} !== ${JSON.stringify(b)}`);
const section = s => console.log(`\n${s}`);

section('audit chain');
{
  const log = new AuditLog();
  const e0 = log.record('analyst', 'ticket.create', 'tk_1', { title: 'first' });
  const e1 = log.record('analyst', 'ticket.update', 'tk_1', { status: 'contained' });
  eq('sequence numbers increment', e1.seq, e0.seq + 1);
  eq('second event chains to the first', e1.prevHash, e0.hash);
  eq('first event chains to genesis', e0.prevHash, '0'.repeat(64));
  ok('a fresh chain verifies as intact', log.verify());
}

section('tamper detection');
{
  const log = new AuditLog();
  log.record('analyst', 'ticket.create', 'tk_1', { title: 'first' });
  log.record('analyst', 'ticket.comment', 'tk_1', { commentId: 'c_1' });
  ok('untampered chain verifies', log.verify());
  log.events[0].data = { title: 'tampered' }; // mutate a stored field in place
  // AuditLog doesn't store `data` directly (only dataHash), so mutate dataHash instead
  log.events[0].dataHash = 'deadbeef'.repeat(8);
  ok('mutating a chained field breaks verification', !log.verify());
}

section('reload survival');
{
  const original = new AuditLog();
  original.record('analyst', 'ticket.create', 'tk_1', { title: 'first' });
  original.record('analyst', 'ticket.update', 'tk_1', { status: 'contained' });
  const serialized = JSON.stringify(original.all());

  // simulate a server restart: a brand-new AuditLog rehydrated from disk
  const rehydrated = new AuditLog().load(JSON.parse(serialized));
  ok('rehydrated chain still verifies', rehydrated.verify());

  const next = rehydrated.record('analyst', 'ticket.comment', 'tk_1', { commentId: 'c_1' });
  eq('seq continues correctly after reload', next.seq, 2);
  eq('prevHash continues correctly after reload', next.prevHash, original.all()[1].hash);
  ok('chain still verifies after continuing post-reload', rehydrated.verify());
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

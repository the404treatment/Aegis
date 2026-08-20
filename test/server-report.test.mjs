#!/usr/bin/env node
/**
 * Report audiences and the formal freeze. Zero dependencies.
 *
 * DESIGN RULE: stubs mimic hostile reality. The failure modes that matter
 * here are the ones a happy-path test sails straight past:
 *  - a formal report that LEAKS the analyst's name or the raw technical
 *    body is a policy breach, not a cosmetic bug,
 *  - a "frozen" report that keeps tracking the case was never frozen, so
 *    the fixtures are mutated after freezing and re-read,
 *  - and a ticket that is flagged but unwritten, or written but unflagged,
 *    must NOT appear - half-curated content reaching a client is the exact
 *    thing the two-part gate exists to prevent.
 */
import { buildReport, finalizeFormal, isFormalEligible, TechnicalPolicy, FormalPolicy, policyFor, snapshotHash } from '../server/report.mjs';

let pass = 0, fail = 0;
const ok = (name, cond, extra = '') => {
  if (cond) { pass++; console.log(`  ok   ${name}`); }
  else { fail++; console.log(`  FAIL ${name}${extra ? '  -> ' + extra : ''}`); }
};
const eq = (name, a, b) => ok(name, a === b, `${JSON.stringify(a)} !== ${JSON.stringify(b)}`);
const section = s => console.log(`\n${s}`);

const mkCase = over => ({
  id: 'cs_1', num: 1, title: 'Ransomware on FS01', status: 'contained', severity: 'high',
  execSummary: 'Attacker encrypted the finance share.', scope: 'FS01 and two workstations.',
  remediation: 'Isolated, rebuilt, credentials rotated.', formalFrozen: null, ...over,
});
const mkTicket = over => ({
  id: 't1', num: 1, caseId: 'cs_1', title: 'Encrypted shares', body: 'RAW TECHNICAL DETAIL: vssadmin delete shadows',
  severity: 'critical', status: 'open', host: 'FS01', technique: 'T1486',
  createdBy: 'ANALYST-NAME', createdAt: 1000, includeInFormal: false, formalSummary: '', ...over,
});

section('eligibility - the two-part gate');
{
  ok('flagged AND summarised is eligible', isFormalEligible(mkTicket({ includeInFormal: true, formalSummary: 'wrote it up' })));
  ok('flagged but NOT summarised is not eligible', !isFormalEligible(mkTicket({ includeInFormal: true, formalSummary: '' })));
  ok('a whitespace-only summary does not count', !isFormalEligible(mkTicket({ includeInFormal: true, formalSummary: '   \n  ' })));
  ok('summarised but NOT flagged is not eligible', !isFormalEligible(mkTicket({ includeInFormal: false, formalSummary: 'wrote it up' })));
  ok('neither is not eligible', !isFormalEligible(mkTicket()));
  ok('null is handled', !isFormalEligible(null));
}

section('technical audience');
{
  const r = buildReport(mkCase(), [mkTicket()], 'technical');
  eq('technical includes every ticket regardless of curation', r.blocks.length, 1);
  eq('it carries the raw technical body', r.blocks[0].body, 'RAW TECHNICAL DETAIL: vssadmin delete shadows');
  eq('and credits the analyst', r.blocks[0].raisedBy, 'ANALYST-NAME');
  eq('it is never frozen', r.frozen, false);
  eq('policyFor defaults to technical', policyFor('anything').kind, 'technical');
}

section('formal audience - what must NOT leak');
{
  const t = mkTicket({ includeInFormal: true, formalSummary: 'A server was encrypted and has been restored.' });
  const r = buildReport(mkCase(), [t], 'formal');
  eq('the eligible ticket appears', r.blocks.length, 1);
  eq('the lead summary replaces the body', r.blocks[0].body, 'A server was encrypted and has been restored.');

  const json = JSON.stringify(r);
  ok('the raw technical body is NOT present anywhere', !json.includes('RAW TECHNICAL DETAIL'));
  ok('the analyst name is NOT present anywhere', !json.includes('ANALYST-NAME'));
  eq('no raisedBy field at all', r.blocks[0].raisedBy, undefined);

  eq('an uncurated ticket is excluded', buildReport(mkCase(), [mkTicket()], 'formal').blocks.length, 0);
  eq('a flagged-but-unwritten ticket is excluded',
    buildReport(mkCase(), [mkTicket({ includeInFormal: true })], 'formal').blocks.length, 0);
}

section('case scoping');
{
  const mine = mkTicket({ id: 't1', includeInFormal: true, formalSummary: 's' });
  const other = mkTicket({ id: 't2', caseId: 'cs_OTHER', includeInFormal: true, formalSummary: 's' });
  eq('technical only sees its own case', buildReport(mkCase(), [mine, other], 'technical').blocks.length, 1);
  eq('formal only sees its own case', buildReport(mkCase(), [mine, other], 'formal').blocks.length, 1);
  eq('an orphan ticket is ignored',
    buildReport(mkCase(), [mkTicket({ caseId: '' })], 'technical').blocks.length, 0);
}

section('freezing');
{
  const c = mkCase();
  const tickets = [mkTicket({ includeInFormal: true, formalSummary: 'first write-up' })];

  const snap = finalizeFormal(c, tickets, 'mike');
  eq('first freeze is version 1', snap.version, 1);
  eq('signer recorded', snap.frozenBy, 'mike');
  eq('one block captured', snap.blocks.length, 1);
  ok('a snapshot hash is recorded', /^[a-f0-9]{64}$/.test(snap.sha256));
  ok('the case now carries the snapshot', c.formalFrozen === snap);

  // THE point of freezing: the case moves on, the signed report does not.
  tickets[0].formalSummary = 'REWRITTEN AFTER FREEZING';
  tickets.push(mkTicket({ id: 't2', num: 2, includeInFormal: true, formalSummary: 'added after freezing' }));
  c.execSummary = 'REWRITTEN SUMMARY';

  const after = buildReport(c, tickets, 'formal');
  eq('the frozen report still has one block', after.blocks.length, 1);
  eq('the frozen text is unchanged', after.blocks[0].body, 'first write-up');
  eq('the frozen narrative is unchanged', after.execSummary, 'Attacker encrypted the finance share.');
  eq('it reports itself as frozen', after.frozen, true);

  // ...while the technical view keeps tracking reality
  const tech = buildReport(c, tickets, 'technical');
  eq('technical still tracks the case', tech.blocks.length, 2);
  eq('technical sees the rewritten narrative', tech.execSummary, 'REWRITTEN SUMMARY');

  // re-freezing publishes a new version that picks up the changes
  const snap2 = finalizeFormal(c, tickets, 'someone-else');
  eq('re-freeze bumps the version', snap2.version, 2);
  eq('re-freeze picks up the new content', snap2.blocks.length, 2);
  eq('re-freeze records the new signer', snap2.frozenBy, 'someone-else');
  ok('and a different hash', snap2.sha256 !== snap.sha256);
}

section('snapshot hashing');
{
  const base = { version: 1, blocks: [{ num: 1, title: 'a', body: 'b' }], execSummary: 'x', scope: 'y', remediation: 'z' };
  eq('hashing is deterministic', snapshotHash(base), snapshotHash({ ...base }));
  ok('changing a block changes the hash',
    snapshotHash({ ...base, blocks: [{ num: 1, title: 'a', body: 'TAMPERED' }] }) !== snapshotHash(base));
  ok('changing the narrative changes the hash',
    snapshotHash({ ...base, execSummary: 'TAMPERED' }) !== snapshotHash(base));
  ok('changing the version changes the hash',
    snapshotHash({ ...base, version: 2 }) !== snapshotHash(base));
}

section('policy shapes');
{
  eq('technical policy is named', TechnicalPolicy.kind, 'technical');
  eq('formal policy is named', FormalPolicy.kind, 'formal');
  const long = 'x'.repeat(30000);
  const r = buildReport(mkCase(), [mkTicket({ body: long })], 'technical');
  ok('an overlong body is clamped', r.blocks[0].body.length <= 20000);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

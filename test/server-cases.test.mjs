#!/usr/bin/env node
/**
 * Case model and evidence handling. Zero dependencies.
 *
 * DESIGN RULE: stubs mimic hostile reality. Evidence is the one place where
 * an analyst hands the server arbitrary bytes AND an arbitrary filename, and
 * the server writes both to disk and serves them back. So the cases that
 * matter here are the abusive ones — a traversal in the filename, an SVG or
 * HTML that would run script in our own origin if served, a data URL that
 * isn't one, and a file large enough to matter. A "happy path uploads fine"
 * test proves nothing about any of that.
 */
import { makeCase, patchCase, decodeEvidence, evidenceRecord, safeEvidenceName, sha256,
         CASE_STATUSES, CASE_SEVERITIES, EVIDENCE_MAX_BYTES } from '../server/cases.mjs';
import crypto from 'node:crypto';

let pass = 0, fail = 0;
const ok = (name, cond, extra = '') => {
  if (cond) { pass++; console.log(`  ok   ${name}`); }
  else { fail++; console.log(`  FAIL ${name}${extra ? '  -> ' + extra : ''}`); }
};
const eq = (name, a, b) => ok(name, a === b, `${JSON.stringify(a)} !== ${JSON.stringify(b)}`);
const section = s => console.log(`\n${s}`);
const threw = fn => { try { fn(); return false; } catch { return true; } };

const ACTOR = { id: 'u_1', name: 'mike', role: 'lead', shared: false };
const SHARED = { id: 'analyst-token', name: 'analyst token', role: 'lead', shared: true };
const dataUrl = (mime, bytes) => `data:${mime};base64,` + Buffer.from(bytes).toString('base64');

section('case creation');
{
  const c = makeCase({ title: 'Ransomware on FS01' }, ACTOR, 1);
  eq('title kept', c.title, 'Ransomware on FS01');
  eq('defaults to open', c.status, 'open');
  eq('defaults to medium', c.severity, 'medium');
  eq('numbered', c.num, 1);
  ok('has an id', /^cs_/.test(c.id));
  eq('attribution comes from the actor', c.createdBy, 'mike');
  eq('owner id recorded for the ownership check', c.createdById, 'u_1');
  ok('starts with no evidence', Array.isArray(c.evidence) && c.evidence.length === 0);
  eq('starts unfrozen (phase 6 fills this)', c.formalFrozen, null);

  eq('the shared token reports as the old literal', makeCase({ title: 'x' }, SHARED, 2).createdBy, 'analyst');
  ok('a blank title is rejected', threw(() => makeCase({ title: '   ' }, ACTOR, 3)));
  ok('a missing title is rejected', threw(() => makeCase({}, ACTOR, 3)));

  const bogus = makeCase({ title: 'x', status: 'banana', severity: 'apocalyptic' }, ACTOR, 4);
  eq('an unknown status falls back to open', bogus.status, 'open');
  eq('an unknown severity falls back to medium', bogus.severity, 'medium');

  const long = makeCase({ title: 'x'.repeat(5000) }, ACTOR, 5);
  ok('an overlong title is clamped', long.title.length <= 300);
}

section('case patching');
{
  const c = makeCase({ title: 'original' }, ACTOR, 1);
  const before = c.createdAt;

  patchCase(c, { status: 'contained', severity: 'high', execSummary: 'summary text' });
  eq('status applied', c.status, 'contained');
  eq('severity applied', c.severity, 'high');
  eq('narrative applied', c.execSummary, 'summary text');
  ok('updatedAt moves', c.updatedAt >= before);

  patchCase(c, { status: 'nonsense' });
  eq('an invalid status is ignored, not applied', c.status, 'contained');
  patchCase(c, { severity: 'nonsense' });
  eq('an invalid severity is ignored', c.severity, 'high');

  // the important one: a patch must not be able to rewrite provenance
  patchCase(c, { createdBy: 'someone else', createdById: 'u_evil', id: 'cs_evil', num: 999, evidence: [{ fake: 1 }], formalFrozen: { forged: true } });
  eq('createdBy is not patchable', c.createdBy, 'mike');
  eq('createdById is not patchable', c.createdById, 'u_1');
  eq('id is not patchable', c.id.startsWith('cs_') && c.id !== 'cs_evil', true);
  eq('num is not patchable', c.num, 1);
  eq('evidence is not patchable', c.evidence.length, 0);
  eq('formalFrozen is not patchable', c.formalFrozen, null);

  const applied = patchCase(c, { title: 'renamed', bogusField: 'x' });
  eq('the applied map reports what changed', applied.title, 'renamed');
  eq('unknown fields are not reported as applied', applied.bogusField, undefined);
  eq('unknown fields are not written', c.bogusField, undefined);
}

section('evidence decoding — accepted types');
{
  for (const [mime, ext] of Object.entries({ 'image/png': 'png', 'image/jpeg': 'jpg', 'image/gif': 'gif', 'image/webp': 'webp', 'application/pdf': 'pdf', 'text/plain': 'txt' })) {
    const d = decodeEvidence(dataUrl(mime, 'hello'));
    eq(`${mime} accepted as .${ext}`, d.ext, ext);
  }
  const d = decodeEvidence(dataUrl('IMAGE/PNG', 'hello'));
  eq('mime matching is case-insensitive', d.ext, 'png');
  eq('bytes round-trip intact', decodeEvidence(dataUrl('text/plain', 'hello world')).buf.toString(), 'hello world');
}

section('evidence decoding — rejected input');
{
  ok('a non-data-URL is rejected', threw(() => decodeEvidence('https://example.com/x.png')));
  ok('empty input is rejected', threw(() => decodeEvidence('')));
  ok('null is rejected', threw(() => decodeEvidence(null)));
  ok('a data URL with no base64 marker is rejected', threw(() => decodeEvidence('data:image/png,notbase64')));
  ok('an empty payload is rejected', threw(() => decodeEvidence('data:image/png;base64,')));

  // These are the ones that matter: bytes we would store and serve back.
  // SVG and HTML can execute script in the serving origin.
  ok('SVG is rejected (it can carry script)', threw(() => decodeEvidence(dataUrl('image/svg+xml', '<svg/>'))));
  ok('HTML is rejected', threw(() => decodeEvidence(dataUrl('text/html', '<h1>x</h1>'))));
  ok('JavaScript is rejected', threw(() => decodeEvidence(dataUrl('text/javascript', 'alert(1)'))));
  ok('an executable is rejected', threw(() => decodeEvidence(dataUrl('application/x-msdownload', 'MZ'))));

  const tooBig = 'data:image/png;base64,' + Buffer.alloc(EVIDENCE_MAX_BYTES + 1024).toString('base64');
  ok('an oversized file is rejected', threw(() => decodeEvidence(tooBig)));
  const atLimit = 'data:image/png;base64,' + Buffer.alloc(EVIDENCE_MAX_BYTES).toString('base64');
  ok('a file exactly at the limit is accepted', !threw(() => decodeEvidence(atLimit)));
}

section('evidence records and hashing');
{
  const bytes = 'the quick brown fox';
  const d = decodeEvidence(dataUrl('text/plain', bytes));
  const rec = evidenceRecord(d, 'a caption', 'notes.txt', ACTOR);

  eq('hash is the real SHA-256 of the bytes', rec.sha256, crypto.createHash('sha256').update(Buffer.from(bytes)).digest('hex'));
  eq('sha256() helper agrees', sha256(Buffer.from(bytes)), rec.sha256);
  eq('stored filename is derived from the hash, not the input', rec.file, rec.sha256 + '.txt');
  eq('byte count recorded', rec.bytes, bytes.length);
  eq('caption kept', rec.caption, 'a caption');
  eq('attribution from the actor', rec.addedBy, 'mike');

  // identical bytes must be content-addressed to the same file
  const rec2 = evidenceRecord(decodeEvidence(dataUrl('text/plain', bytes)), '', 'other-name.txt', ACTOR);
  eq('identical bytes produce the same filename', rec2.file, rec.file);
  ok('but a distinct record id', rec2.id !== rec.id);

  // a filename must never be able to steer the write
  const eviln = evidenceRecord(d, '', '../../../etc/passwd', ACTOR);
  eq('a traversal filename cannot reach the stored name', eviln.file, rec.file);
  ok('the display name is stripped of path separators', !eviln.name.includes('/') && !eviln.name.includes('\\'));
  const winEvil = evidenceRecord(d, '', '..\\..\\windows\\system32\\config', ACTOR);
  ok('backslash paths are stripped too', !winEvil.name.includes('\\'));
}

section('serving evidence back');
{
  const good = 'a'.repeat(64) + '.png';
  eq('a well-formed hash name is allowed', safeEvidenceName(good), good);
  eq('traversal is refused', safeEvidenceName('../../etc/passwd'), null);
  eq('an absolute path is refused', safeEvidenceName('/etc/passwd'), null);
  eq('a windows path is refused', safeEvidenceName('..\\config.json'), null);
  eq('a non-hash name is refused', safeEvidenceName('screenshot.png'), null);
  eq('a disallowed extension is refused', safeEvidenceName('a'.repeat(64) + '.svg'), null);
  eq('a short hash is refused', safeEvidenceName('abc.png'), null);
  eq('an uppercase hash is refused (we only ever write lowercase)', safeEvidenceName('A'.repeat(64) + '.png'), null);
  eq('empty is refused', safeEvidenceName(''), null);
  eq('null is refused', safeEvidenceName(null), null);
  eq('trailing junk after the extension is refused', safeEvidenceName('a'.repeat(64) + '.png .txt'), null);
  eq('a NUL byte (classic path truncation) is refused', safeEvidenceName('a'.repeat(64) + '.png\0.txt'), null);
}

section('shape constants');
{
  eq('five IR statuses in lifecycle order', CASE_STATUSES.join(','), 'open,contained,eradicated,recovered,closed');
  eq('four severities', CASE_SEVERITIES.length, 4);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

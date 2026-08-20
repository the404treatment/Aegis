#!/usr/bin/env node
/**
 * Verify the audit chain, and if it is broken, say exactly where.
 *
 *   npm run verify:audit
 *   node verify-audit.mjs --file /backups/audit-2026-08-19.ndjson
 *
 * The console tells you *that* the chain is broken. During an incident that is
 * not enough: you need to know which row was touched, because everything
 * recorded before it is still provably intact and can be relied on. This walks
 * the chain row by row and reports the first failure and why.
 *
 * Exit codes are meant for cron: 0 intact, 1 broken, 2 could not read.
 *
 * Zero dependencies.
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { AuditLog } from './server/audit.mjs';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const val = (f, d) => { const i = argv.indexOf(f); return i > -1 && argv[i + 1] ? argv[i + 1] : d; };
const quiet = argv.includes('--quiet');

const C = process.stdout.isTTY && !process.env.NO_COLOR;
const w = k => s => (C ? `\x1b[${k}m${s}\x1b[0m` : String(s));
const c = { b: w(1), d: w(2), g: w(32), y: w(33), r: w(31), cy: w(36) };
const say = (...a) => { if (!quiet) console.log(...a); };

const FILE = val('--file', path.join(ROOT, 'server', 'data', 'audit.ndjson'));

if (!fs.existsSync(FILE)) {
  console.error(`\n  ${c.y('No audit log at')} ${FILE}`);
  console.error(`  ${c.d('A server that has never recorded anything has no chain yet - that is not a fault.')}\n`);
  process.exit(2);
}

/* Parse line by line rather than in one go: a truncated final line is a very
   ordinary way for this file to end (killed mid-write) and should be reported
   as itself, not as "the whole file is corrupt". */
const raw = fs.readFileSync(FILE, 'utf8').split('\n');
const rows = [];
let badLine = null;
for (let i = 0; i < raw.length; i++) {
  const line = raw[i].trim();
  if (!line) continue;
  try { rows.push(JSON.parse(line)); }
  catch { badLine = { n: i + 1, text: line.slice(0, 120) }; break; }
}

say('');
say(`  ${c.b('AEGIS audit chain')}`);
say(`  ${c.d('-'.repeat(64))}`);
say(`  file    ${FILE}`);
say(`  rows    ${rows.length}`);

if (badLine) {
  say(`  ${c.y('unparseable line ' + badLine.n)} ${c.d('- truncated write, most likely an unclean shutdown')}`);
  say(`  ${c.d(badLine.text)}`);
}

if (!rows.length) {
  say(`\n  ${c.y('Nothing to verify.')}\n`);
  process.exit(badLine ? 1 : 0);
}

/* Walk forward one row at a time. The first prefix that fails to verify ends
   at the tampered row - everything before it is intact. */
let firstBad = -1;
for (let i = 1; i <= rows.length; i++) {
  if (!new AuditLog().load(rows.slice(0, i)).verify()) { firstBad = i - 1; break; }
}

const when = r => (r && r.timestamp) || 'unknown time';

if (firstBad === -1 && !badLine) {
  say(`  span    ${c.d(when(rows[0]))}  →  ${c.d(when(rows[rows.length - 1]))}`);
  say('');
  say(`  ${c.g('INTACT')} - every row hashes to its recorded value and the chain is unbroken.`);
  say('');
  process.exit(0);
}

/* -------------------------------------------------------- explain the break */
const bad = rows[firstBad];
const prev = rows[firstBad - 1];
say('');
say(`  ${c.r('BROKEN')} at row ${c.b(String(firstBad))} ${c.d('(seq ' + (bad && bad.seq) + ', ' + when(bad) + ')')}`);
say('');

/* Say which specific property no longer matches, because "the chain is broken"
   and "someone changed this person's role" are very different sentences to put
   in an incident report. */
const sha256 = s => crypto.createHash('sha256').update(s).digest('hex');
const reasons = [];
if (bad && prev && bad.prevHash !== prev.hash) reasons.push('its prevHash does not match the row before it - a row was inserted, deleted or reordered');
if (bad && bad.data !== undefined && sha256(JSON.stringify(bad.data ?? null)) !== bad.dataHash) reasons.push('its stored body no longer hashes to the recorded dataHash - the body was edited');
{
  const { hash, ...base } = bad || {};
  if (bad && AuditLog.digest(base) !== hash) reasons.push('its own fields no longer hash to the recorded hash - actor, action, target or timestamp was changed');
}
for (const r of reasons) say(`    ${c.y('·')} ${r}`);
if (!reasons.length) say(`    ${c.y('·')} the row verifies alone but breaks the chain - check the rows around it`);

say('');
say(`  ${c.b('The row as it now stands:')}`);
for (const k of ['seq', 'timestamp', 'actorId', 'action', 'targetId']) {
  if (bad && bad[k] !== undefined) say(`    ${k.padEnd(10)} ${c.cy(String(bad[k]))}`);
}
if (bad && bad.data) say(`    ${'data'.padEnd(10)} ${c.cy(JSON.stringify(bad.data).slice(0, 200))}`);

say('');
say(`  ${c.g('Rows 0–' + (firstBad - 1) + ' are still provably intact')} ${c.d('(' + firstBad + ' of ' + rows.length + ').')}`);
say(`  ${c.d('Anything recorded from row ' + firstBad + ' onward is unverified until this is explained.')}`);
say('');
say(`  ${c.b('Do this first:')}`);
say(`    1. ${c.cy('cp ' + FILE + ' /somewhere/safe/')}  ${c.d('- preserve it before anything else')}`);
say(`    2. Check the host for an unclean shutdown or a full disk around ${c.d(when(bad))}`);
say(`    3. If neither explains it, treat it as tampering: docs/DEFENDING-AEGIS.md §4`);
say('');
process.exit(1);

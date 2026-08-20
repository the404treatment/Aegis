#!/usr/bin/env node
/**
 * Event-lake query tests. Zero dependencies, matching test/ui.test.mjs's
 * own runner conventions.
 *
 * DESIGN RULE: stubs mimic hostile reality. The fixture deliberately includes
 * an event with an unmapped field name and one with no technique/fields at
 * all, because the failure mode that matters is a query silently matching
 * everything (or nothing) rather than throwing.
 */
import { query, parseQuery, matchQuery } from '../server/lake.mjs';

let pass = 0, fail = 0;
const ok = (name, cond, extra = '') => {
  if (cond) { pass++; console.log(`  ok   ${name}`); }
  else { fail++; console.log(`  FAIL ${name}${extra ? '  -> ' + extra : ''}`); }
};
const eq = (name, a, b) => ok(name, a === b, `${JSON.stringify(a)} !== ${JSON.stringify(b)}`);
const section = s => console.log(`\n${s}`);

const T0 = Date.parse('2026-01-01T00:00:00Z');
const EVENTS = [
  { id: 'e1', ts: T0 + 1000, agentId: 'ag1', host: 'DC01', channel: 'Security', eventId: '4624',
    severity: 'info', message: 'Successful logon for jdoe', fields: { LogonType: '3' }, technique: 'T1078' },
  { id: 'e2', ts: T0 + 2000, agentId: 'ag1', host: 'DC01', channel: 'Security', eventId: '4625',
    severity: 'suspicious', message: 'Failed logon burst', fields: { TargetUserName: 'admin' }, technique: 'T1110' },
  { id: 'e3', ts: T0 + 3000, agentId: 'ag2', host: 'WKS-101', channel: 'Microsoft-Windows-Sysmon/Operational',
    eventId: '10', severity: 'malicious', message: 'lsass.exe access from procdump',
    fields: { TargetImage: 'C:\\Windows\\System32\\lsass.exe' }, technique: 'T1003.001' },
  { id: 'e4', ts: T0 + 4000, agentId: 'ag2', host: 'WKS-101', channel: 'System', eventId: '7045',
    severity: 'suspicious', message: 'New service installed', fields: {}, technique: '' },
];

section('field queries');
{
  eq('host: matches one host', query(EVENTS, { q: 'host:DC01' }).total, 2);
  eq('severity: matches', query(EVENTS, { q: 'severity:malicious' }).total, 1);
  eq('eventid: alias resolves to eventId', query(EVENTS, { q: 'eventid:4625' }).total, 1);
  eq('technique: alias matches', query(EVENTS, { q: 'technique:T1110' }).total, 1);
  eq('attack: is an alias for technique', query(EVENTS, { q: 'attack:T1078' }).total, 1);
  eq('channel: matches a substring', query(EVENTS, { q: 'channel:Sysmon' }).total, 1);
  eq('sub-technique prefix matches its parent string', query(EVENTS, { q: 'technique:T1003' }).total, 1);
}

section('the collector self-activity flag');
{
  // A separate fixture so the counts above stay stable. The point is that an
  // analyst can hide the agent's own scheduled runs, and equally isolate them
  // to confirm the agent is alive.
  const SELF = [
    { id: 's1', ts: T0, host: 'WKS-1', channel: 'Security', eventId: '4688', severity: 'info',
      message: 'Collector self-activity (task svc-telemetry).', fields: {}, technique: '', self: true },
    { id: 's2', ts: T0 + 1, host: 'WKS-1', channel: 'Security', eventId: '4688', severity: 'suspicious',
      message: 'powershell -enc ...', fields: {}, technique: 'T1059.001', self: false },
  ];
  eq('-self:true hides the collector runs', query(SELF, { q: '-self:true' }).total, 1);
  eq('...leaving real activity', query(SELF, { q: '-self:true' }).events[0].id, 's2');
  eq('self:true isolates them', query(SELF, { q: 'self:true' }).total, 1);
  eq('...and it is the self event', query(SELF, { q: 'self:true' }).events[0].id, 's1');
  // A real detection that happens to name the agent path must not be hidden by
  // the self filter - only the actual boolean flag counts.
  const spoof = [{ id: 'x', ts: T0, host: 'h', channel: 'Security', eventId: '4688', severity: 'malicious',
    message: 'attacker ran C:\\ProgramData\\svc-telemetry\\evil.exe', fields: {}, technique: 'T1059', self: false }];
  eq('a malicious event mentioning the path is not hidden', query(spoof, { q: '-self:true' }).total, 1);
}

section('free text, negation, quoting, OR');
{
  eq('bare term matches anywhere in the event', query(EVENTS, { q: 'procdump' }).total, 1);
  eq('terms are ANDed', query(EVENTS, { q: 'host:DC01 severity:suspicious' }).total, 1);
  eq('negation excludes', query(EVENTS, { q: 'host:DC01 -eventid:4624' }).total, 1);
  eq('quoted phrase matches with a space', query(EVENTS, { q: 'message:"Failed logon"' }).total, 1);
  eq('unquoted multi-word ANDs instead', query(EVENTS, { q: 'lsass procdump' }).total, 1);
  eq('or splits into alternatives', query(EVENTS, { q: 'host:DC01 or host:WKS-101' }).total, 4);
  eq('|| behaves like or', query(EVENTS, { q: 'severity:malicious || severity:info' }).total, 2);
}

section('agent fields bag and unknown fields');
{
  eq('an agent-supplied field is searchable', query(EVENTS, { q: 'LogonType:3' }).total, 1);
  eq('an unknown field matches nothing rather than everything',
    query(EVENTS, { q: 'nosuchfield:whatever' }).total, 0);
  eq('empty query returns everything', query(EVENTS, { q: '' }).total, 4);
  eq('whitespace-only query returns everything', query(EVENTS, { q: '   ' }).total, 4);
}

section('filters, ordering, pagination');
{
  eq('channel filter', query(EVENTS, { channel: 'Security' }).total, 2);
  eq('severity filter', query(EVENTS, { severity: 'suspicious' }).total, 2);
  eq('host filter', query(EVENTS, { host: 'WKS-101' }).total, 2);
  eq('from filter is inclusive', query(EVENTS, { from: T0 + 3000 }).total, 2);
  eq('to filter is inclusive', query(EVENTS, { to: T0 + 2000 }).total, 2);

  const r = query(EVENTS, {});
  eq('newest first', r.events[0].id, 'e4');
  eq('count reports the whole set', r.count, 4);

  const page = query(EVENTS, { limit: 2, offset: 1 });
  eq('limit caps the page', page.events.length, 2);
  eq('offset skips', page.events[0].id, 'e3');
  eq('total ignores pagination', page.total, 4);
  eq('limit is clamped to 500', query(EVENTS, { limit: 99999 }).events.length, 4);
  eq('a zero/absent limit falls back to the default', query(EVENTS, { limit: 0 }).events.length, 4);
}

section('summary facets');
{
  const r = query(EVENTS, {});
  eq('channels are counted', r.channels.Security, 2);
  eq('severities are counted', r.severities.suspicious, 2);
  eq('top hosts ranked', r.top.hosts[0].v, 2);
  ok('techniques exclude the empty one', r.top.techniques.every(t => t.k !== ''));
}

section('query parser internals');
{
  eq('parseQuery splits OR groups', parseQuery('a or b').length, 2);
  eq('parseQuery ANDs within a group', parseQuery('a b').length, 1);
  ok('matchQuery with no groups matches everything', matchQuery(EVENTS[0], []));
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

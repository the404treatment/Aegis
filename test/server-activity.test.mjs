#!/usr/bin/env node
/**
 * The team activity feed. Zero dependencies.
 *
 * DESIGN RULE: stubs mimic hostile reality. The failure modes that matter here
 * are the ones a happy-path test walks straight past:
 *  - the feed is rendered from the AUDIT log, so an unrecognised action must
 *    be DROPPED rather than rendered as "someone did ticket.frobnicate" -
 *    a feed that invents verbs for rows it does not understand is worse than
 *    one that stays quiet,
 *  - order is load-bearing: newest first, and the `limit` must cost the tail
 *    of the log rather than a full walk, so the fixtures are deliberately
 *    longer than the limit,
 *  - and a real audit row often has a null/absent actor, a missing target, or
 *    a patch body that touched nothing worth naming - all of which have to
 *    render as a sentence rather than "undefined undefined".
 */
import { describe as describeEvent, feed, actors } from '../server/activity.mjs';

let pass = 0, fail = 0;
const ok = (name, cond, extra = '') => {
  if (cond) { pass++; console.log(`  ok   ${name}`); }
  else { fail++; console.log(`  FAIL ${name}${extra ? '  -> ' + extra : ''}`); }
};
const eq = (name, a, b) => ok(name, a === b, `${JSON.stringify(a)} !== ${JSON.stringify(b)}`);
const section = s => console.log(`\n${s}`);

let _seq = 0;
const ev = (action, over = {}) => ({
  seq: ++_seq, timestamp: new Date().toISOString(), actorId: 'u_sarah', action, targetId: 'tk_1', data: null, ...over,
});
const NAMES = { u_sarah: 'Sarah Okafor', u_mike: 'Mike Pache' };

/* ------------------------------------------------------------- one row */
section('rendering a single row');
{
  const r = describeEvent(ev('ticket.create', { targetId: 'tk_9' }), { tk_9: 'Suspicious logon on DC01' }, NAMES);
  eq('the actor id resolves to a name', r.actor, 'Sarah Okafor');
  eq('...and the exact id is kept alongside it', r.actorId, 'u_sarah');

  // The chain stores ISO-8601 so the log stays readable on disk; the client
  // does date arithmetic, so this has to arrive as epoch ms or every row in
  // the feed renders "NaNd ago".
  ok('the timestamp is epoch ms, not an ISO string', typeof r.at === 'number' && r.at > 0, String(r.at));
  ok('...and is a plausible time', Math.abs(Date.now() - r.at) < 60000);

  // A person who has since been deleted still has rows in the chain. Falling
  // back to the raw id is ugly but honest; inventing a name would not be.
  eq('an unresolvable actor falls back to the id',
    describeEvent(ev('ticket.create', { actorId: 'u_ghost' }), {}, NAMES).actor, 'u_ghost');
  eq('verb is human', r.verb, 'raised');
  eq('noun names the thing', r.noun, 'ticket');
  eq('target resolves to a title', r.target, 'Suspicious logon on DC01');
  eq('kind drives the colour stripe', r.kind, 'ticket');

  // A title we don't have must not render as a raw id in the sentence.
  const noTitle = describeEvent(ev('ticket.create', { targetId: 'tk_unknown' }), {});
  eq('an unknown target renders empty, not as an id', noTitle.target, '');

  eq('a missing actor still reads as a sentence',
    describeEvent(ev('case.create', { actorId: null })).actor, 'someone');
}

section('unknown and malformed rows are dropped, not guessed at');
{
  ok('an unmapped action is dropped', describeEvent(ev('ticket.frobnicate')) === null);
  ok('a null event is dropped', describeEvent(null) === null);
  ok('an event with no action is dropped', describeEvent({ seq: 1 }) === null);
  // auth.login.failed is recorded by the server but has no VERBS entry: it
  // must not leak into a feed everyone can see.
  ok('failed sign-ins are not rendered', describeEvent(ev('auth.login.failed')) === null);
}

section('detail lines summarise, they do not dump the patch');
{
  const upd = describeEvent(ev('ticket.update', { data: { status: 'closed', severity: 'high', body: 'x'.repeat(5000) } }));
  eq('named fields are summarised', upd.detail, 'status → closed, severity → high');
  ok('the patch body is not dumped into the feed', !upd.detail.includes('xxxx'), upd.detail);

  eq('a patch with nothing notable renders no detail',
    describeEvent(ev('ticket.update', { data: { body: 'reworded' } })).detail, '');
  eq('evidence names the file',
    describeEvent(ev('case.evidence', { data: { filename: 'memdump.raw' } })).detail, 'memdump.raw');
  eq('a null data body is safe',
    describeEvent(ev('ticket.update', { data: null })).detail, '');
  eq('a non-object data body is safe',
    describeEvent(ev('ticket.update', { data: 'oops' })).detail, '');
}

/* ---------------------------------------------------------------- feed */
section('feed ordering and limits');
{
  const many = [];
  for (let i = 0; i < 200; i++) many.push(ev('ticket.create', { targetId: 'tk_' + i }));
  const f = feed(many, { limit: 10 });
  eq('limit is honoured', f.length, 10);
  eq('newest first', f[0].targetId, 'tk_199');
  eq('...and descending', f[9].targetId, 'tk_190');

  eq('an empty log yields an empty feed', feed([], {}).length, 0);
}

section('sign-in noise is filtered by default');
{
  const mixed = [ev('auth.login'), ev('ticket.create'), ev('auth.logout'), ev('case.create')];
  const quiet = feed(mixed, {});
  eq('only work is shown', quiet.length, 2);
  ok('no auth rows leak in', quiet.every(i => i.kind !== 'auth'));

  const loud = feed(mixed, { includeQuiet: true });
  eq('opting in brings them back', loud.length, 4);

  // The limit must apply to what SURVIVES filtering, not to rows scanned -
  // otherwise a burst of sign-ins silently empties the visible feed.
  const noisy = [];
  for (let i = 0; i < 50; i++) noisy.push(ev('auth.login'));
  noisy.push(ev('ticket.create', { targetId: 'tk_real' }));
  const survived = feed(noisy, { limit: 5 });
  eq('real work is not crowded out by filtered rows', survived.length, 1);
  eq('...and it is the right row', survived[0].targetId, 'tk_real');
}

/* -------------------------------------------------------------- actors */
section('recently active people');
{
  const now = Date.now();
  const iso = ms => new Date(ms).toISOString();
  const rows = [
    ev('ticket.create', { actorId: 'u_mike',  timestamp: iso(now - 40 * 3600e3) }), // yesterday+
    ev('ticket.create', { actorId: 'u_sarah', timestamp: iso(now - 3600e3) }),
    ev('case.create',   { actorId: 'u_ravi',  timestamp: iso(now - 600e3) }),
    ev('ticket.update', { actorId: 'u_sarah', timestamp: iso(now - 60e3) }),
  ];
  const a = actors(rows, 24 * 3600e3, NAMES);
  eq('only people inside the window', a.length, 2);
  eq('most recent first', a[0].id, 'u_sarah');
  eq('...resolved to a name', a[0].name, 'Sarah Okafor');
  ok('the stale actor is excluded', !a.some(x => x.id === 'u_mike'));
  eq('repeat activity is counted once per person', a.filter(x => x.id === 'u_sarah').length, 1);
  eq('...but the count reflects both actions', a.find(x => x.id === 'u_sarah').count, 2);
}

console.log(`\n${fail ? 'FAILED' : 'PASSED'}  ${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);

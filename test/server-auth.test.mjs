#!/usr/bin/env node
/**
 * Accounts / sessions / capabilities tests. Zero dependencies, matching
 * test/ui.test.mjs's runner conventions.
 *
 * DESIGN RULE: stubs mimic hostile reality. The cases that matter here are
 * the ones where a naive implementation looks fine:
 *  - a wrong password that happens to hash to a different LENGTH must not
 *    throw out of timingSafeEqual and read as "true" to a try/catch caller,
 *  - lockout must survive the attacker simply waiting a little, but must
 *    also EXPIRE (a permanent lock is a self-inflicted outage),
 *  - sessions must actually expire, and revocation must be immediate,
 *  - and a password change must kill live sessions, or "reset the password"
 *    is security theatre.
 */
import { Sessions, LoginLimiter, makeUser, findUser, hashPw, verifyPw, publicUser, can, capsFor, canonRole, ROLES } from '../server/auth.mjs';

let pass = 0, fail = 0;
const ok = (name, cond, extra = '') => {
  if (cond) { pass++; console.log(`  ok   ${name}`); }
  else { fail++; console.log(`  FAIL ${name}${extra ? '  -> ' + extra : ''}`); }
};
const eq = (name, a, b) => ok(name, a === b, `${JSON.stringify(a)} !== ${JSON.stringify(b)}`);
const section = s => console.log(`\n${s}`);

section('passwords');
{
  const u = makeUser('alice', 'correct horse battery staple', 'lead');
  ok('correct password verifies', verifyPw('correct horse battery staple', u));
  ok('wrong password rejected', !verifyPw('wrong', u));
  ok('empty password rejected', !verifyPw('', u));
  ok('a much longer wrong password is rejected, not thrown',
    !verifyPw('x'.repeat(5000), u));
  ok('salt is stored', !!u.salt);
  ok('plaintext is never stored', JSON.stringify(u).indexOf('correct horse') === -1);

  const a = hashPw('same', 'fixedsalt'), b = hashPw('same', 'fixedsalt');
  eq('same password + salt is deterministic', a.hash, b.hash);
  const c = hashPw('same'), d = hashPw('same');
  ok('random salts make identical passwords hash differently', c.hash !== d.hash);

  ok('verify against a user with no hash is false, not a throw', !verifyPw('x', { name: 'x' }));
  ok('verify against null is false', !verifyPw('x', null));
}

section('user creation');
{
  ok('rejects a blank name', (() => { try { makeUser('', 'pw', 'lead'); return false; } catch { return true; } })());
  ok('rejects a missing password', (() => { try { makeUser('bob', '', 'lead'); return false; } catch { return true; } })());
  ok('rejects an unknown role', (() => { try { makeUser('bob', 'pw', 'wizard'); return false; } catch { return true; } })());
  eq('role is canonicalised from mixed case', makeUser('bob', 'pw', 'LEAD').role, 'lead');
  eq('canonRole rejects junk', canonRole('nope'), null);

  const users = [makeUser('Alice', 'pw', 'lead'), makeUser('bob', 'pw', 'analyst')];
  ok('lookup is case-insensitive', !!findUser(users, 'ALICE'));
  ok('lookup trims whitespace', !!findUser(users, '  alice  '));
  eq('unknown user is null', findUser(users, 'nobody'), null);

  const p = publicUser(users[0]);
  ok('public shape omits the hash', p.hash === undefined && p.salt === undefined);
  ok('public shape carries caps', Array.isArray(p.caps) && p.caps.length > 0);
}

section('capabilities');
{
  eq('two roles', ROLES.length, 2);
  ok('analyst can create a ticket', can('analyst', 'ticket.create'));
  ok('analyst can edit their own ticket', can('analyst', 'ticket.editOwn'));
  ok('analyst CANNOT edit anyone else\'s ticket', !can('analyst', 'ticket.editAny'));
  ok('analyst CANNOT remove agents', !can('analyst', 'agent.manage'));
  ok('analyst CANNOT manage users', !can('analyst', 'user.manage'));
  ok('lead can edit any ticket', can('lead', 'ticket.editAny'));
  ok('lead can remove agents', can('lead', 'agent.manage'));
  ok('lead can manage users', can('lead', 'user.manage'));
  ok('an unknown role has no capabilities', capsFor('wizard').length === 0);
  ok('an unknown role is denied everything', !can('wizard', 'ticket.create'));
  ok('lead is a superset of analyst', capsFor('analyst').every(c => can('lead', c)));
}

section('sessions');
{
  const s = new Sessions();
  const t = s.issue('u1');
  eq('a fresh session resolves to its user', s.userIdFor('u1' === t ? '' : t), 'u1');
  eq('an unknown token resolves to null', s.userIdFor('nope'), null);
  eq('an empty token resolves to null', s.userIdFor(''), null);
  ok('two sessions get different tokens', s.issue('u1') !== t);

  ok('revoke kills the session', s.revoke(t) && s.userIdFor(t) === null);

  const s2 = new Sessions();
  const a = s2.issue('u1'), b = s2.issue('u1'), c = s2.issue('u2');
  eq('revokeUser kills every session for that user', s2.revokeUser('u1'), 2);
  ok('the other user is untouched', s2.userIdFor(c) === 'u2');
  ok('the revoked user has nothing left', s2.userIdFor(a) === null && s2.userIdFor(b) === null);
}

section('session expiry and persistence');
{
  const shortLived = new Sessions(50); // 50ms TTL
  const t = shortLived.issue('u1');
  eq('valid immediately', shortLived.userIdFor(t), 'u1');
  // simulate the clock moving past the TTL by rewriting the issue time
  shortLived.map.get(t).ts = Date.now() - 1000;
  eq('expired session no longer resolves', shortLived.userIdFor(t), null);
  ok('expired session is evicted, not just hidden', !shortLived.map.has(t));

  // a restart: persist, then rehydrate into a brand-new instance
  const before = new Sessions();
  const live = before.issue('u1');
  const rows = before.all();
  const after = new Sessions().load(rows);
  eq('a live session survives a restart', after.userIdFor(live), 'u1');

  const stale = new Sessions().load([{ token: 'old', userId: 'u1', ts: Date.now() - (8 * 24 * 60 * 60 * 1000) }]);
  eq('a session that expired while the server was down is dropped', stale.userIdFor('old'), null);
  const junk = new Sessions().load([null, {}, { token: 'x' }, { userId: 'y' }]);
  eq('malformed persisted rows are ignored', junk.all().length, 0);
}

section('login rate limiting');
{
  const L = new LoginLimiter();
  const k = LoginLimiter.key('10.0.0.1', 'Alice');
  eq('key is ip|lowercased-name', k, '10.0.0.1|alice');
  eq('x-forwarded-for takes the first hop', LoginLimiter.key('1.2.3.4, 5.6.7.8', 'a'), '1.2.3.4|a');

  eq('not blocked initially', L.blockedFor(k), 0);
  for (let i = 0; i < 4; i++) L.fail(k);
  eq('four failures do not lock', L.blockedFor(k), 0);
  L.fail(k);
  ok('the fifth failure locks', L.blockedFor(k) > 0);
  ok('lockout is reported in seconds, near 15 minutes', L.blockedFor(k) > 890 && L.blockedFor(k) <= 900);

  // a lock must expire — a permanent lock is a self-inflicted outage
  const e = L.attempts.get(k);
  e.lockUntil = Date.now() - 1;
  eq('lock expires', L.blockedFor(k), 0);

  L.reset(k);
  eq('reset clears the record', L.blockedFor(k), 0);

  // the counting window slides: slow guessing must not accumulate forever
  const L2 = new LoginLimiter({ max: 3, windowMs: 100, lockMs: 1000 });
  const k2 = 'ip|u';
  L2.fail(k2, 1000); L2.fail(k2, 1050);
  L2.fail(k2, 5000); // well outside the window — the counter restarts
  eq('failures outside the window do not accumulate into a lock', L2.blockedFor(k2, 5000), 0);

  // different users on one IP are tracked separately
  const L3 = new LoginLimiter();
  const ka = LoginLimiter.key('10.0.0.1', 'alice'), kb = LoginLimiter.key('10.0.0.1', 'bob');
  for (let i = 0; i < 5; i++) L3.fail(ka);
  ok('locking one account does not lock another on the same IP', L3.blockedFor(ka) > 0 && L3.blockedFor(kb) === 0);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

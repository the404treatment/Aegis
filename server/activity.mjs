/**
 * The team pulse.
 *
 * Everything anyone does already lands in the hash-chained audit log — that log
 * exists to prove what happened, so it is machine-shaped: `ticket.update` with
 * a patch body. Nobody watches a hash chain to find out what their colleague is
 * doing.
 *
 * This module is the other half of that: the same rows, rendered as sentences,
 * newest first. One source of truth, two readings — the audit view for "prove
 * it", the activity feed for "what's everyone on right now".
 *
 * It deliberately holds no state. Presence (who is connected) is a live
 * property of the SSE hub and lives in the server; this is history.
 *
 * Zero dependencies.
 */

/** Actions worth putting in front of a person, and how to say them. */
const VERBS = {
  'ticket.create':   { verb: 'raised',        noun: 'ticket',   kind: 'ticket' },
  'ticket.update':   { verb: 'updated',       noun: 'ticket',   kind: 'ticket' },
  'ticket.comment':  { verb: 'commented on',  noun: 'ticket',   kind: 'ticket' },
  'case.create':     { verb: 'opened',        noun: 'case',     kind: 'case' },
  'case.update':     { verb: 'updated',       noun: 'case',     kind: 'case' },
  'case.evidence':   { verb: 'added evidence to', noun: 'case', kind: 'evidence' },
  'case.formal':     { verb: 'froze the formal report for', noun: 'case', kind: 'report' },
  'user.create':     { verb: 'created the account', noun: '',   kind: 'user' },
  'user.update':     { verb: 'changed the account', noun: '',   kind: 'user' },
  'user.delete':     { verb: 'removed the account', noun: '',   kind: 'user' },
  'auth.login':      { verb: 'signed in',     noun: '',         kind: 'auth' },
  'auth.logout':     { verb: 'signed out',    noun: '',         kind: 'auth' },
};

/* Sign-in noise drowns the feed on a busy team; the audit log still has every
   one of them for when you actually need to ask who was on at 3am. */
const QUIET = new Set(['auth.login', 'auth.logout']);

/** A short, human label for what changed — not a diff dump. */
function detailOf(e) {
  const d = e.data;
  if (!d || typeof d !== 'object') return '';
  if (e.action === 'ticket.update') {
    const bits = [];
    if (d.status) bits.push(`status → ${d.status}`);
    if (d.severity) bits.push(`severity → ${d.severity}`);
    if (d.assignee) bits.push(`assigned to ${d.assignee}`);
    // A patch that touched nothing worth naming is still worth showing as an
    // edit — just without inventing detail for it.
    return bits.join(', ');
  }
  if (e.action === 'case.update') {
    const bits = [];
    if (d.status) bits.push(`status → ${d.status}`);
    if (d.severity) bits.push(`severity → ${d.severity}`);
    return bits.join(', ');
  }
  if (e.action === 'case.evidence') return d.filename ? String(d.filename) : '';
  if (e.action === 'user.create' || e.action === 'user.delete') return d.name ? String(d.name) : '';
  if (e.action === 'user.update') return d.role ? `role → ${d.role}` : (d.passwordChanged ? 'password changed' : '');
  return '';
}

/**
 * One audit row → one feed item, or null if it is not worth showing.
 * `titles` maps a targetId to something a person recognises ("#4 Ransomware on
 * FS01") so the feed reads as work rather than as identifiers.
 */
export function describe(e, titles = {}, names = {}) {
  if (!e || !e.action) return null;
  const spec = VERBS[e.action];
  if (!spec) return null;
  const target = titles[e.targetId] || '';
  // The chain records actor IDs, because a name can be edited and an identity
  // cannot. Nobody recognises `u_Kw80BJ9a`, so resolve to the display name for
  // reading and keep the ID for anything that needs to be exact.
  const actorId = e.actorId || '';
  return {
    id: e.seq,
    // Timestamps are stored ISO-8601 so the log stays readable on disk; the
    // client does date arithmetic, which needs epoch ms.
    at: e.timestamp ? Date.parse(e.timestamp) : 0,
    actorId,
    actor: names[actorId] || actorId || 'someone',
    verb: spec.verb,
    noun: spec.noun,
    kind: spec.kind,
    targetId: e.targetId || '',
    target,
    detail: detailOf(e),
  };
}

/**
 * Newest-first feed.
 *
 * `includeQuiet` pulls sign-in/out back in — off by default so the feed shows
 * work, not attendance.
 */
export function feed(events, { limit = 60, titles = {}, names = {}, includeQuiet = false } = {}) {
  const out = [];
  // Walk backwards so `limit` costs the tail of the log, not a full map+sort of
  // every event ever recorded.
  for (let i = events.length - 1; i >= 0 && out.length < limit; i--) {
    const e = events[i];
    if (!includeQuiet && QUIET.has(e.action)) continue;
    const item = describe(e, titles, names);
    if (item) out.push(item);
  }
  return out;
}

/**
 * Who has been active recently, and on what. Drives the "3 people on this
 * incident today" line — distinct from live presence, which is who has a
 * stream open right now.
 */
export function actors(events, sinceMs, names = {}) {
  const cut = Date.now() - (sinceMs || 24 * 3600e3);
  const seen = new Map();
  for (let i = events.length - 1; i >= 0; i--) {
    const e = events[i];
    const at = e.timestamp ? Date.parse(e.timestamp) : 0;
    if (!at || at < cut) break;   // the log is append-ordered
    if (!e.actorId) continue;
    const cur = seen.get(e.actorId);
    if (!cur) seen.set(e.actorId, { id: e.actorId, name: names[e.actorId] || e.actorId, last: at, count: 1 });
    else cur.count++;
  }
  return [...seen.values()].sort((a, b) => b.last - a.last);
}

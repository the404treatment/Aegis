/**
 * Event lake query engine - a small field-aware query language (KQL/SPL-lite)
 * over the telemetry the server already keeps. Ported from Skyhawk's
 * domain/lake.js.
 *
 * Deliberately NOT a second store: Skyhawk keeps one NDJSON file per case, but
 * AEGIS has no case entity yet and already maintains `events.ndjson` plus an
 * in-memory ring, so this is a pure query function over an array the caller
 * supplies. When a case layer lands, scope it by adding a filter here rather
 * than a parallel event store.
 *
 * Query syntax: tokens are ANDed; `field:value`, `field:"a b"`, bare free-text
 * matches anywhere, `-` negates, and a bare `or` starts a new OR-group.
 */

/* Field aliases -> AEGIS's own event shape
   ({id,ts,agentId,host,channel,eventId,severity,message,fields,technique}).
   Re-keyed from Skyhawk's network-flow shape, which AEGIS doesn't share. */
const FIELDMAP = {
  host: 'host', hostname: 'host', computer: 'host',
  channel: 'channel', source: 'channel', log: 'channel',
  eventid: 'eventId', eid: 'eventId', id: 'eventId',
  severity: 'severity', sev: 'severity',
  message: 'message', msg: 'message',
  technique: 'technique', attack: 'technique', tech: 'technique',
  agent: 'agentId', agentid: 'agentId',
  // The agent's own scheduled runs. `self:true` isolates them; `-self:true`
  // hides them, which is what an analyst wants most of the time.
  self: 'self',
};

function tokenize(qs) {
  const out = [];
  const re = /(-?)(?:([A-Za-z_][\w.]*):)?(?:"([^"]*)"|(\S+))/g;
  let m;
  while ((m = re.exec(qs))) {
    const val = (m[3] != null ? m[3] : m[4]) || '';
    if (!val) continue;
    out.push({ neg: m[1] === '-', field: m[2] ? m[2].toLowerCase() : null, val: val.toLowerCase() });
  }
  return out;
}

function matchToken(e, t) {
  let hit;
  if (t.field) {
    const key = FIELDMAP[t.field];
    if (key) {
      hit = String(e[key] == null ? '' : e[key]).toLowerCase().includes(t.val);
    } else {
      // Not a known alias - try the agent-supplied fields bag. Field names are
      // lowercased during tokenizing but the bag's keys are the raw Windows
      // ones (CamelCase, e.g. LogonType), so match the key case-insensitively;
      // a case-sensitive lookup silently returns nothing for every real field
      // name an analyst would actually type.
      const bag = e.fields || {};
      const key = Object.keys(bag).find(k => k.toLowerCase() === t.field);
      hit = key != null
        ? String(bag[key]).toLowerCase().includes(t.val)
        : JSON.stringify(e).toLowerCase().includes(t.field + ':' + t.val);
    }
  } else {
    hit = JSON.stringify(e).toLowerCase().includes(t.val);
  }
  return t.neg ? !hit : hit;
}

/** Split tokens into OR-groups (a bare `or`/`||` separates them); each group is ANDed. */
export function parseQuery(qs) {
  const groups = [[]];
  for (const t of tokenize(qs)) {
    if (!t.field && !t.neg && (t.val === 'or' || t.val === '||')) groups.push([]);
    else groups[groups.length - 1].push(t);
  }
  return groups.filter(g => g.length);
}

export function matchQuery(e, groups) {
  if (!groups.length) return true;
  return groups.some(g => g.every(t => matchToken(e, t)));
}

const topN = (o, n) => Object.keys(o).map(k => ({ k, v: o[k] })).sort((a, b) => b.v - a.v).slice(0, n);

/** AEGIS stores ts as epoch ms; accept either that or an ISO string. */
const tsMs = v => (typeof v === 'number' ? v : Date.parse(v || '')) || 0;

/**
 * @param {Array} all   the event array to query (the server's EVENTS ring)
 * @param {Object} opts {q, channel, severity, host, from, to, limit, offset}
 */
export function query(all, opts = {}) {
  const channels = {}, hosts = {}, severities = {}, techniques = {};
  for (const e of all) {
    channels[e.channel || '?'] = (channels[e.channel || '?'] || 0) + 1;
    if (e.host) hosts[e.host] = (hosts[e.host] || 0) + 1;
    if (e.severity) severities[e.severity] = (severities[e.severity] || 0) + 1;
    if (e.technique) techniques[e.technique] = (techniques[e.technique] || 0) + 1;
  }
  const top = { hosts: topN(hosts, 6), techniques: topN(techniques, 8) };

  let rows = all;
  if (opts.channel) rows = rows.filter(e => e.channel === opts.channel);
  if (opts.severity) rows = rows.filter(e => e.severity === opts.severity);
  if (opts.host) rows = rows.filter(e => e.host === opts.host);
  const from = opts.from ? tsMs(opts.from) : 0;
  const to = opts.to ? tsMs(opts.to) : 0;
  if (from) rows = rows.filter(e => tsMs(e.ts) >= from);
  if (to) rows = rows.filter(e => tsMs(e.ts) <= to);

  const qs = String(opts.q || '').trim();
  if (qs) { const groups = parseQuery(qs); rows = rows.filter(e => matchQuery(e, groups)); }

  rows = rows.slice().sort((a, b) => tsMs(b.ts) - tsMs(a.ts)); // newest first
  const total = rows.length;
  const limit = Math.min(Math.max(1, Number(opts.limit) || 100), 500);
  const offset = Math.max(0, Number(opts.offset) || 0);
  return { total, count: all.length, channels, severities, top, events: rows.slice(offset, offset + limit) };
}

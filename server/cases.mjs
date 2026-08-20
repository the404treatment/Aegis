/**
 * Cases and evidence. Zero dependencies, node:crypto only.
 *
 * A case is a container: a named incident that groups tickets, carries the
 * narrative an analyst writes up, and holds hashed evidence. It is
 * deliberately NOT a retrofit of the ticket model - a ticket is a single
 * artifact with one host and one technique, which is a different thing from
 * the incident it belongs to. Tickets gain exactly one optional `caseId`
 * field for the link; nothing else about them changes.
 *
 * Skyhawk's six-state finding approval workflow (Draft -> Submitted ->
 * UnderReview -> Approved/Parked/Rejected) is intentionally NOT ported. It
 * exists to serve multi-analyst peer review, which is a much larger feature
 * than the formal report actually needs; the two fields the report filter
 * really uses (includeInFormal, formalSummary) live on the case instead.
 *
 * This module owns no storage - the caller persists what it hands back.
 */
import crypto from 'node:crypto';

/** The IR lifecycle, in order. Matches the language responders already use. */
export const CASE_STATUSES = ['open', 'contained', 'eradicated', 'recovered', 'closed'];
export const CASE_SEVERITIES = ['low', 'medium', 'high', 'critical'];

/** Narrative fields an analyst writes up; free text, all optional. */
export const CASE_NARRATIVE = ['execSummary', 'scope', 'remediation'];
/** Everything a PATCH is allowed to touch. */
export const CASE_PATCHABLE = ['title', 'status', 'severity', 'assignee', ...CASE_NARRATIVE];

const clamp = (v, n) => String(v == null ? '' : v).slice(0, n);

export function makeCase(body, actor, num) {
  const title = clamp(body.title, 300).trim();
  if (!title) throw new Error('title required');
  return {
    id: 'cs_' + crypto.randomBytes(9).toString('base64url'),
    num,
    title,
    status: CASE_STATUSES.includes(body.status) ? body.status : 'open',
    severity: CASE_SEVERITIES.includes(body.severity) ? body.severity : 'medium',
    assignee: clamp(body.assignee, 120),
    execSummary: clamp(body.execSummary, 20000),
    scope: clamp(body.scope, 20000),
    remediation: clamp(body.remediation, 20000),
    // Attribution comes from the authenticated actor, never the body.
    createdBy: actor.shared ? 'analyst' : actor.name,
    createdById: actor.id,
    createdAt: Date.now(),
    updatedAt: Date.now(),
    evidence: [],
    // Phase 6 will freeze a formal report onto this.
    formalFrozen: null,
  };
}

/** Apply a patch in place, ignoring anything not explicitly patchable. */
export function patchCase(c, body) {
  const applied = {};
  for (const k of CASE_PATCHABLE) {
    if (body[k] === undefined) continue;
    if (k === 'status' && !CASE_STATUSES.includes(body[k])) continue;
    if (k === 'severity' && !CASE_SEVERITIES.includes(body[k])) continue;
    c[k] = CASE_NARRATIVE.includes(k) ? clamp(body[k], 20000) : clamp(body[k], 300);
    applied[k] = c[k];
  }
  c.updatedAt = Date.now();
  return applied;
}

/* ------------------------------------------------------------------ evidence */

/**
 * What an analyst is allowed to attach. An allowlist, not a denylist: the
 * server writes these bytes to disk and serves them back, so anything that a
 * browser might execute in our own origin (svg, html) stays off the list on
 * purpose, even though they are "images" in casual use.
 */
export const EVIDENCE_TYPES = {
  'image/png': 'png',
  'image/jpeg': 'jpg',
  'image/gif': 'gif',
  'image/webp': 'webp',
  'application/pdf': 'pdf',
  'text/plain': 'txt',
};
export const EVIDENCE_MAX_BYTES = 12 * 1024 * 1024; // 12MB of actual bytes

/**
 * Decode a `data:<mime>;base64,<payload>` URL into bytes.
 * Returns {buf, mime, ext} or throws with a reason the UI can show.
 */
export function decodeEvidence(dataUrl) {
  const m = /^data:([a-z0-9.+/-]+);base64,(.*)$/is.exec(String(dataUrl || '').trim());
  if (!m) throw new Error('not a base64 data URL');
  const mime = m[1].toLowerCase();
  const ext = EVIDENCE_TYPES[mime];
  if (!ext) throw new Error(`unsupported type ${mime} - allowed: ${Object.keys(EVIDENCE_TYPES).join(', ')}`);
  let buf;
  try { buf = Buffer.from(m[2], 'base64'); } catch { throw new Error('could not decode base64'); }
  if (!buf.length) throw new Error('empty file');
  if (buf.length > EVIDENCE_MAX_BYTES) {
    throw new Error(`file is ${(buf.length / 1048576).toFixed(1)}MB, limit is ${EVIDENCE_MAX_BYTES / 1048576}MB`);
  }
  return { buf, mime, ext };
}

export const sha256 = buf => crypto.createHash('sha256').update(buf).digest('hex');

/**
 * Build the stored evidence record. The on-disk filename is derived from the
 * hash, never from user input - an analyst-supplied name must never be able
 * to steer a write out of the evidence directory.
 */
export function evidenceRecord({ buf, mime, ext }, caption, originalName, actor) {
  const hash = sha256(buf);
  return {
    id: 'ev_' + crypto.randomBytes(6).toString('base64url'),
    file: `${hash}.${ext}`,
    sha256: hash,
    mime,
    bytes: buf.length,
    // kept for display only, and stripped of anything path-like
    name: clamp(String(originalName || '').replace(/[\\/]/g, '_'), 200),
    caption: clamp(caption, 500),
    addedBy: actor.shared ? 'analyst' : actor.name,
    addedById: actor.id,
    addedAt: Date.now(),
  };
}

/** Guard for serving evidence back: only ever a bare hash.ext, never a path. */
export function safeEvidenceName(name) {
  return /^[a-f0-9]{64}\.(png|jpg|gif|webp|pdf|txt)$/.test(String(name || '')) ? String(name) : null;
}

/**
 * Case reports: the same data through two audiences.
 * Ported from Skyhawk's domain/report.js + audience-policy.js.
 *
 *  - TECHNICAL is always live. It recomputes from current tickets on every
 *    read, carries full detail, and names the analyst who raised each item.
 *    It is the working document.
 *
 *  - FORMAL is the deliverable. It selects only the tickets a lead has
 *    flagged AND written a plain-language summary for, drops the raw
 *    technical body, and carries no analyst attribution at all — the
 *    organisation speaks, not the individual. Once frozen it stops tracking
 *    the case entirely and returns the stored snapshot verbatim.
 *
 * Freezing is what makes it a deliverable rather than a view: the bytes you
 * signed are the bytes that come back, even if the case keeps moving. The
 * snapshot's hash is recorded in the audit chain by the caller, so a frozen
 * report that was edited afterwards is detectable.
 *
 * Storage-free and side-effect-free so it can be tested directly.
 */
import crypto from 'node:crypto';

/** A ticket is in the formal report only if a lead opted it in AND wrote it up. */
export const isFormalEligible = t => !!(t && t.includeInFormal && String(t.formalSummary || '').trim());

const clamp = (v, n) => String(v == null ? '' : v).slice(0, n);

export const TechnicalPolicy = {
  kind: 'technical',
  select: tickets => tickets.slice(),
  toBlock: t => ({
    num: t.num,
    title: clamp(t.title, 300),
    body: clamp(t.body, 20000),          // full technical detail
    severity: t.severity,
    status: t.status,
    host: t.host || '',
    technique: t.technique || '',
    // the working document credits the analyst
    raisedBy: t.createdBy || 'analyst',
    at: t.createdAt,
  }),
};

export const FormalPolicy = {
  kind: 'formal',
  select: tickets => tickets.filter(isFormalEligible),
  toBlock: t => ({
    num: t.num,
    title: clamp(t.title, 300),
    // the lead's plain-language write-up REPLACES the raw body; the technical
    // detail is deliberately not carried into a client-facing document
    body: clamp(t.formalSummary, 20000),
    severity: t.severity,
    host: t.host || '',
    technique: t.technique || '',
    // no raisedBy: formal reports are not attributed to an individual
    at: t.createdAt,
  }),
};

export const policyFor = kind => (kind === 'formal' ? FormalPolicy : TechnicalPolicy);

/** Stable hash of a snapshot, so tampering with a frozen report is detectable. */
export const snapshotHash = snap =>
  crypto.createHash('sha256').update(JSON.stringify({
    version: snap.version, blocks: snap.blocks,
    execSummary: snap.execSummary, scope: snap.scope, remediation: snap.remediation,
  })).digest('hex');

/**
 * Build a report view for a case.
 * A frozen formal report ignores `tickets` entirely and returns the snapshot.
 */
export function buildReport(kase, tickets, kind) {
  const policy = policyFor(kind);
  if (policy.kind === 'formal' && kase.formalFrozen) {
    return { ...kase.formalFrozen, kind: 'formal', frozen: true, caseNum: kase.num, title: kase.title };
  }
  const mine = tickets.filter(t => t.caseId === kase.id);
  return {
    kind: policy.kind,
    frozen: false,
    caseNum: kase.num,
    title: kase.title,
    status: kase.status,
    severity: kase.severity,
    execSummary: kase.execSummary || '',
    scope: kase.scope || '',
    remediation: kase.remediation || '',
    blocks: policy.select(mine).map(policy.toBlock),
    generatedAt: Date.now(),
  };
}

/**
 * Freeze the formal report onto the case. Re-finalizing bumps the version;
 * previous versions are not retained here (the audit chain records each
 * freeze, including the hash of what was signed).
 */
export function finalizeFormal(kase, tickets, signer) {
  const mine = tickets.filter(t => t.caseId === kase.id);
  const blocks = FormalPolicy.select(mine).map(FormalPolicy.toBlock);
  const snap = {
    version: ((kase.formalFrozen && kase.formalFrozen.version) || 0) + 1,
    frozenAt: Date.now(),
    frozenBy: signer,
    blocks,
    execSummary: kase.execSummary || '',
    scope: kase.scope || '',
    remediation: kase.remediation || '',
  };
  snap.sha256 = snapshotHash(snap);
  kase.formalFrozen = snap;
  return snap;
}

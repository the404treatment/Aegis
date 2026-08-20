/**
 * Tamper-evident, hash-chained audit log. Any retroactive edit breaks the
 * chain. Fully local, zero dependencies; no external timestamp authority.
 * Ported from Skyhawk's domain/audit.js to ESM.
 *
 * One global chain for the whole server (no per-case scoping exists yet -
 * callers filter AuditLog.all() by targetId for a per-ticket/per-case view).
 */
import { createHash } from 'node:crypto';

const GENESIS = '0'.repeat(64);
const sha256 = s => createHash('sha256').update(s).digest('hex');

export class AuditLog {
  events = [];

  static digest(e) {
    return sha256(`${e.seq}|${e.timestamp}|${e.actorId}|${e.action}|${e.targetId}|${e.dataHash}|${e.prevHash}`);
  }

  record(actorId, action, targetId, data) {
    const seq = this.events.length;
    const prevHash = seq === 0 ? GENESIS : this.events[seq - 1].hash;
    const base = {
      seq, timestamp: new Date().toISOString(), actorId, action, targetId,
      dataHash: sha256(JSON.stringify(data ?? null)), prevHash,
    };
    // `data` is kept alongside its hash, not just hashed away. Storing only
    // the hash made the log able to prove that SOMETHING changed while being
    // unable to say what - so every human-readable view of it had to go to
    // another source, and a chain that verifies but explains nothing is a
    // poor record. verify() re-derives dataHash from it, so keeping the body
    // tightens tamper detection rather than loosening it.
    const event = { ...base, data: data ?? null, hash: AuditLog.digest(base) };
    this.events.push(event);
    return event;
  }

  all() { return this.events; }

  /** Rehydrate a persisted chain so it continues verifiably across restarts. */
  load(events) { this.events = events.slice(); return this; }

  /** True only if the whole chain is intact and untampered. */
  verify() {
    let prev = GENESIS;
    for (const e of this.events) {
      const { hash, ...base } = e;
      if (e.prevHash !== prev || AuditLog.digest(base) !== hash) return false;
      // Editing the stored body must break verification too, or `data` would
      // be a freely-rewritable field hanging off a tamper-evident record.
      // Chains written before bodies were stored have no `data` and are
      // checked on the hash alone.
      if (e.data !== undefined && sha256(JSON.stringify(e.data ?? null)) !== e.dataHash) return false;
      prev = hash;
    }
    return true;
  }
}

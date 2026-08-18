/**
 * Tamper-evident, hash-chained audit log. Any retroactive edit breaks the
 * chain. Fully local, zero dependencies; no external timestamp authority.
 * Ported from Skyhawk's domain/audit.js to ESM.
 *
 * One global chain for the whole server (no per-case scoping exists yet —
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
    const event = { ...base, hash: AuditLog.digest(base) };
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
      prev = hash;
    }
    return true;
  }
}

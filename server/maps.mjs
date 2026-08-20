/**
 * Shared network maps. Zero dependencies, node:crypto only.
 *
 * The hunt map used to live only in each analyst's browser (localStorage), so
 * nobody could see anyone else's estate or attack-path planning. These are the
 * server-backed, shareable version: a named snapshot of nodes/edges/zones that
 * everyone on the server can open, owned by whoever saved it.
 *
 * Two things are deliberately protected from deletion, per the product rules:
 *   - a LIVE map (mode:'live') is never deletable through the API - it is the
 *     picture the incident is being worked against, not a scratch scenario;
 *   - a map owned by a LEAD ("admin") can only be deleted by a lead, so an
 *     analyst can't remove a lead's work.
 * A normal analyst can still freely delete their OWN planning maps.
 *
 * The nodes/edges/zones payload is stored as opaque JSON the client already
 * serialises. We cap its size rather than validate its shape - a malformed map
 * only breaks the one analyst who saved it, and the render path is defensive.
 *
 * This module owns no storage - the caller persists what it hands back.
 */
import crypto from 'node:crypto';

export const MAP_MODES = ['planning', 'live'];
const clampStr = (v, n) => String(v == null ? '' : v).slice(0, n);
/** Cap the map payload so a save can't wedge the store; ~2MB of JSON is a very
    large hand-drawn estate, far past anything real. */
const MAX_PAYLOAD = 2 * 1024 * 1024;
function clampPayload(v) {
  let s;
  try { s = JSON.stringify(v ?? []); } catch { return []; }
  if (s.length > MAX_PAYLOAD) throw new Error('map is too large to save');
  return v ?? [];
}

export function makeMap(body, actor, num) {
  const name = clampStr(body.name, 160).trim() || `Map ${num}`;
  const mode = MAP_MODES.includes(body.mode) ? body.mode : 'planning';
  return {
    id: 'mp_' + crypto.randomBytes(9).toString('base64url'),
    num,
    name,
    mode,
    // Attribution and the role at save time come from the session, never the
    // body - the role is what the deletion rule reads later.
    ownerId: actor.shared ? '' : actor.id,
    ownerName: actor.shared ? 'analyst' : actor.name,
    ownerRole: actor.role || 'analyst',
    nodes: clampPayload(body.nodes),
    edges: clampPayload(body.edges),
    zones: (body.zones && typeof body.zones === 'object') ? body.zones : {},
    createdAt: Date.now(),
    updatedAt: Date.now(),
  };
}

/** Metadata only - what the picker lists without shipping every node. */
export function mapSummary(m) {
  return {
    id: m.id, num: m.num, name: m.name, mode: m.mode,
    ownerName: m.ownerName, ownerId: m.ownerId, ownerRole: m.ownerRole,
    nodeCount: Array.isArray(m.nodes) ? m.nodes.length : 0,
    updatedAt: m.updatedAt, createdAt: m.createdAt,
  };
}

/** Who may edit (overwrite) a map: its owner, or any lead. */
export function canEditMap(m, actor) {
  if (!actor) return false;
  if (actor.shared) return true;                 // the break-glass analyst token
  if (m.ownerId && m.ownerId === actor.id) return true;
  return actor.role === 'lead';
}

/** Why a delete is refused, or null when it's allowed. Encodes the rules:
    live maps are undeletable; a lead's map needs a lead; otherwise owner or
    lead. */
export function mapDeleteBlock(m, actor) {
  if (!actor) return 'not signed in';
  if (m.mode === 'live') return 'a live map cannot be deleted - switch it to a planning map first';
  const isLead = actor.role === 'lead' || actor.shared;
  if (m.ownerRole === 'lead' && !isLead) return "only a lead can delete a lead's map";
  const owns = actor.shared || (m.ownerId && m.ownerId === actor.id);
  if (!owns && !isLead) return "you can only delete your own maps";
  return null;
}

/** Apply an in-place update from a save. Owner/role/provenance are immutable. */
export function patchMap(m, body) {
  if (body.name !== undefined) m.name = clampStr(body.name, 160).trim() || m.name;
  if (body.mode !== undefined && MAP_MODES.includes(body.mode)) m.mode = body.mode;
  if (body.nodes !== undefined) m.nodes = clampPayload(body.nodes);
  if (body.edges !== undefined) m.edges = clampPayload(body.edges);
  if (body.zones !== undefined && typeof body.zones === 'object') m.zones = body.zones;
  m.updatedAt = Date.now();
  return m;
}

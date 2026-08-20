#!/usr/bin/env node
/**
 * Shared-map model. Zero dependencies.
 *
 * DESIGN RULE: stubs mimic hostile reality. The interesting cases here are the
 * protection rules - a live map that must not be deletable by anyone, a lead's
 * map that an analyst must not be able to delete, and provenance the body must
 * not be able to forge - not "a save round-trips".
 */
import { makeMap, patchMap, mapSummary, canEditMap, mapDeleteBlock, MAP_MODES } from '../server/maps.mjs';

let pass = 0, fail = 0;
const ok = (name, cond, extra = '') => {
  if (cond) { pass++; console.log(`  ok   ${name}`); }
  else { fail++; console.log(`  FAIL ${name}${extra ? '  -> ' + extra : ''}`); }
};
const eq = (name, a, b) => ok(name, a === b, `${JSON.stringify(a)} !== ${JSON.stringify(b)}`);
const section = s => console.log(`\n${s}`);
const threw = fn => { try { fn(); return false; } catch { return true; } };

const LEAD = { id: 'u_lead', name: 'lena', role: 'lead', shared: false };
const ANA = { id: 'u_ana', name: 'andy', role: 'analyst', shared: false };
const ANA2 = { id: 'u_ana2', name: 'ana-two', role: 'analyst', shared: false };
const SHARED = { id: 'analyst-token', name: 'analyst token', role: 'lead', shared: true };

section('map creation');
{
  const m = makeMap({ name: 'HQ estate', nodes: [{ uid: 'n1' }], edges: [], zones: { z1: {} } }, ANA, 1);
  eq('name kept', m.name, 'HQ estate');
  eq('defaults to planning mode', m.mode, 'planning');
  eq('owner comes from the session', m.ownerId, 'u_ana');
  eq('owner role recorded for the deletion rule', m.ownerRole, 'analyst');
  eq('nodes stored', m.nodes.length, 1);
  ok('an unnamed map still gets a name', makeMap({}, ANA, 7).name === 'Map 7');
  eq('the shared token has no owner id', makeMap({ name: 'x' }, SHARED, 2).ownerId, '');

  // provenance cannot be forged through the body
  const forged = makeMap({ name: 'x', ownerId: 'u_evil', ownerName: 'evil', ownerRole: 'lead' }, ANA, 3);
  eq('ownerId is not body-settable', forged.ownerId, 'u_ana');
  eq('ownerRole is not body-settable', forged.ownerRole, 'analyst');

  // an oversized payload is refused, not silently truncated
  const huge = new Array(60000).fill({ uid: 'n', x: 1, y: 1, label: 'x'.repeat(40) });
  ok('an over-large map is rejected', threw(() => makeMap({ name: 'big', nodes: huge }, ANA, 4)));
}

section('edit permission');
{
  const anaMap = makeMap({ name: 'a' }, ANA, 1);
  ok('the owner can edit', canEditMap(anaMap, ANA));
  ok('a different analyst cannot edit', !canEditMap(anaMap, ANA2));
  ok('a lead can edit anyone\'s', canEditMap(anaMap, LEAD));
  ok('the shared token can edit', canEditMap(anaMap, SHARED));
}

section('deletion rules');
{
  const anaMap = makeMap({ name: 'plan', mode: 'planning' }, ANA, 1);
  eq('the owner can delete their own planning map', mapDeleteBlock(anaMap, ANA), null);
  ok('another analyst cannot delete it', !!mapDeleteBlock(anaMap, ANA2));

  const leadMap = makeMap({ name: 'lead plan', mode: 'planning' }, LEAD, 2);
  ok('an analyst cannot delete a lead\'s map', !!mapDeleteBlock(leadMap, ANA));
  eq('a lead can delete a lead\'s map', mapDeleteBlock(leadMap, LEAD), null);

  const liveMap = makeMap({ name: 'the incident', mode: 'live' }, ANA, 3);
  ok('nobody can delete a live map - not the owner', !!mapDeleteBlock(liveMap, ANA));
  ok('nobody can delete a live map - not a lead', !!mapDeleteBlock(liveMap, LEAD));
  ok('nobody can delete a live map - not the shared token', !!mapDeleteBlock(liveMap, SHARED));
}

section('patching');
{
  const m = makeMap({ name: 'orig', mode: 'planning' }, ANA, 1);
  const owner = m.ownerId, num = m.num;
  patchMap(m, { name: 'renamed', mode: 'live', nodes: [{ uid: 'n1' }, { uid: 'n2' }] });
  eq('name patched', m.name, 'renamed');
  eq('mode patched', m.mode, 'live');
  eq('nodes patched', m.nodes.length, 2);
  patchMap(m, { mode: 'banana' });
  eq('an invalid mode is ignored', m.mode, 'live');
  patchMap(m, { ownerId: 'u_evil', num: 999, ownerRole: 'lead' });
  eq('a patch cannot rewrite the owner', m.ownerId, owner);
  eq('a patch cannot rewrite the number', m.num, num);
  eq('a patch cannot escalate the owner role', m.ownerRole, 'analyst');
}

section('summary');
{
  const m = makeMap({ name: 's', nodes: [{ uid: 'n1' }, { uid: 'n2' }, { uid: 'n3' }] }, LEAD, 1);
  const s = mapSummary(m);
  eq('summary carries the node count', s.nodeCount, 3);
  ok('summary carries no node payload', !('nodes' in s));
  ok('valid modes are the two expected', MAP_MODES.join(',') === 'planning,live');
}

console.log(`\n${pass + fail === pass ? 'PASSED' : 'FAILED'}  ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

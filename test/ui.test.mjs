#!/usr/bin/env node
/**
 * AEGIS UI test suite. Zero dependencies, node --test compatible runner.
 *
 * DESIGN RULE: stubs mimic hostile reality, not the happy path.
 *  - confirm() returns FALSE and prompt() returns NULL, because mobile
 *    in-app browsers suppress them and a "block further dialogs" tick makes
 *    them return false forever. Three separate bugs shipped because the old
 *    harness stubbed confirm -> true.
 *  - Reload is simulated by re-booting the module against the SAME fake
 *    localStorage. An in-memory flag that "fixes" a bug passes a naive test
 *    and fails on refresh.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const HTML = path.join(ROOT, 'ui', 'index.html');

let pass = 0, fail = 0;
const ok = (name, cond, extra = '') => {
  if (cond) { pass++; console.log(`  ok   ${name}`); }
  else { fail++; console.log(`  FAIL ${name}${extra ? '  -> ' + extra : ''}`); }
};
const eq = (name, a, b) => ok(name, a === b, `${JSON.stringify(a)} !== ${JSON.stringify(b)}`);
const section = s => console.log(`\n${s}`);

/* ---------------------------------------------------------------- harness */
function mkEl(id) {
  return {
    id, value: '', innerHTML: '', textContent: '', title: '', style: {},
    classList: {
      _c: new Set(),
      add(x) { this._c.add(x); }, remove(x) { this._c.delete(x); },
      toggle(x) { this._c.has(x) ? this._c.delete(x) : this._c.add(x); },
      contains(x) { return this._c.has(x); },
    },
    appendChild() { }, remove() { }, focus() { }, click() { },
    setAttribute() { }, addEventListener() { }, closest: () => null,
    querySelector: () => ({ focus() { }, addEventListener() { }, value: '', select() { } }),
    querySelectorAll: () => [],
    getBoundingClientRect: () => ({ left: 0, top: 0, width: 1400, height: 900 }),
    cloneNode: () => ({ setAttribute() { }, querySelectorAll: () => [], innerHTML: '<g/>' }),
    scrollTop: 0, _zoomBound: true,
  };
}

/** Boot the app. `store` persists across boots so we can simulate a reload. */
function boot(store, exports) {
  const html = fs.readFileSync(HTML, 'utf8');
  const src = html.match(/<script>([\s\S]*)<\/script>/)[1];
  const els = {};
  const doc = {
    addEventListener() { },
    getElementById: id => (els[id] ||= mkEl(id)),
    querySelector: () => mkEl(),
    querySelectorAll: () => [],
    createElement: () => mkEl('tmp'),
    body: { classList: { add() { }, remove() { }, contains: () => false }, appendChild() { } },
  };
  const api = new Function(
    'localStorage', 'document', 'window', 'navigator', 'setTimeout', 'clearTimeout',
    'requestAnimationFrame', 'URL', 'Blob', 'confirm', 'prompt', 'EventSource',
    src + `\n;return{${exports}};`
  )(
    { getItem: k => store[k] ?? null, setItem: (k, v) => { store[k] = v; } },
    doc, { addEventListener() { } }, { clipboard: { writeText: () => Promise.resolve() } },
    f => f && f(), () => { }, () => { },
    { createObjectURL: () => 'blob:', revokeObjectURL() { } },
    function () { return {}; },
    () => false,   // *** native confirm SUPPRESSED, as on mobile ***
    () => null,    // *** native prompt SUPPRESSED ***
    class { addEventListener() { } close() { } }
  );
  return { api, els };
}

const EXPORTS = [
  'TACTICS', 'MITRE', 'MITS', 'SUBS', 'NODE_TYPES', 'ALL', 'uniqTechs', 'LOGSRC', 'TOUR',
  'SCENARIOS', 'THREAT_PROFILES', 'buildSigmaBundle', 'buildSavedSearches', 'reportHTML',
  'studio', 'lsSeedTopology', 'renderLogSrc', 'renderMatrix', 'renderStudio', 'renderTickets',
  'lsClearMap', 'lsDeleteNode', 'lsDeleteZone', '_uiCloseDlg', 'lsPresetZones', 'lsAddNode',
  'ZONES:()=>ZONES', 'getNodes:()=>lsNodes', 'getEdges:()=>lsEdges', 'nodeZone', 'lsNodesSVG',
  'lsZoneRegions', 'restoreAll', 'lsTopologyHTML', 'splLint', 'coverageScore', 'lsGuessType',
  'lsNextDetections', 'primaryStage', 'eventsForTech', 'liveApplyLinks', 'LIVE',
  'lsZoneRect', 'lsRunImport', 'openArtifactTriage', 'artPick', 'getArt:()=>artState',
  'parseTriage', 'lsTakeSnapshot', 'getSnaps:()=>lsSnaps', 'setPending:v=>{lsPendingChain=v}',
  'getPending:()=>lsPendingChain', 'buildAdvisory', 'adviseTechnique', 'adviseNode',
  'extractIocs', 'highlightIocs', 'liveIngestEvent',
  'ingDetect', 'ingParse', 'ingParsePcap', 'ingMapEvents', 'ingCommit',
  'getIngState:()=>ingState', 'setIngState:v=>{ingState=v}',
].join(',');

/* ------------------------------------------------------------ data integrity */
section('data integrity');
{
  const { api } = boot({}, EXPORTS);
  eq('225 techniques', Object.keys(api.MITRE).length, 225);
  eq('15 tactics', api.TACTICS.length, 15);
  eq('258 placements', api.TACTICS.reduce((s, t) => s + t[2].length, 0), 258);
  eq('24 node types', Object.keys(api.NODE_TYPES).length, 24);
  eq('48 log sources', api.LOGSRC.length, 48);

  const unplaced = [];
  api.TACTICS.forEach(([, , ids]) => ids.forEach(i => { if (!api.MITRE[i]) unplaced.push(i); }));
  ok('every placement resolves to a technique', unplaced.length === 0, unplaced.join(','));

  const badMit = new Set();
  Object.values(api.MITRE).forEach(t => (t.mits || []).forEach(m => { if (!api.MITS[m]) badMit.add(m); }));
  ok('every mitigation reference resolves', badMit.size === 0, [...badMit].join(','));

  ok('SUBS keys are real techniques', Object.keys(api.SUBS).every(k => api.MITRE[k]));
  ok('every event reachable via a technique',
    api.ALL().every(e => (e.mitre || []).some(m => api.MITRE[m])));
  ok('all techniques curated (none ref-only)',
    Object.values(api.MITRE).every(t => !t.ref));

  const thin = Object.entries(api.MITRE).filter(([, v]) =>
    !v.summary || !v.detect || v.detect.length < 3 || !v.pivots?.length || !v.mits?.length || !v.start);
  ok('every technique has full content', thin.length === 0, thin.slice(0, 5).map(x => x[0]).join(','));

  const badStage = api.uniqTechs().filter(i => {
    const s = api.primaryStage(i); return isNaN(s) || s < 0 || s >= api.TACTICS.length;
  });
  ok('primaryStage valid for all', badStage.length === 0, badStage.slice(0, 5).join(','));

  Object.entries(api.THREAT_PROFILES).forEach(([k, p]) =>
    ok(`threat profile ${k} fully mapped`, p.techs.every(t => api.MITRE[t])));
}

/* -------------------------------------------- destructive actions, dialogs off */
section('destructive actions with native dialogs SUPPRESSED');
{
  const store = {};
  const { api } = boot(store, EXPORTS);
  api.lsSeedTopology();
  const before = api.getNodes().length;
  ok('sample topology loads', before > 0);

  // Clear: the in-app dialog must appear and resolve, despite confirm()===false
  const p = api.lsClearMap();
  api._uiCloseDlg(true);
  await p;
  eq('clear removes all nodes', api.getNodes().length, 0);
  eq('clear removes all edges', api.getEdges().length, 0);
  eq('clear removes all zones', Object.keys(api.ZONES()).length, 0);

  // Delete node: confirm path
  api.lsSeedTopology();
  const n0 = api.getNodes().length;
  const d1 = api.lsDeleteNode(api.getNodes()[0].uid);
  api._uiCloseDlg(true);
  await d1;
  eq('node delete removes one host', api.getNodes().length, n0 - 1);

  // Delete node: cancel path must be a no-op
  const n1 = api.getNodes().length;
  const d2 = api.lsDeleteNode(api.getNodes()[0].uid);
  api._uiCloseDlg(false);
  await d2;
  eq('cancelling delete keeps the host', api.getNodes().length, n1);

  // Delete zone keeps its hosts
  api.lsPresetZones();
  const z0 = Object.keys(api.ZONES()).length;
  const hosts = api.getNodes().length;
  const d3 = api.lsDeleteZone('dmz');
  api._uiCloseDlg(true);
  await d3;
  eq('zone delete removes the zone', Object.keys(api.ZONES()).length, z0 - 1);
  eq('zone delete keeps its hosts', api.getNodes().length, hosts);
}

/* ------------------------------------------------- persistence across reload */
section('persistence across a simulated page reload');
{
  const store = {};
  const first = boot(store, EXPORTS);
  first.api.restoreAll();
  first.api.renderLogSrc();
  eq('a brand-new user gets a blank map', first.api.getNodes().length, 0);
  ok('blank map shows the empty state',
    first.api.lsTopologyHTML().includes('Your map is empty'));

  first.api.lsSeedTopology();
  first.api.lsTakeSnapshot();
  first.api.setPending([{ from: 'a', to: 'b' }]);
  ok('state built before clearing', first.api.getNodes().length > 0);

  const p = first.api.lsClearMap();
  first.api._uiCloseDlg(true);
  await p;
  eq('cleared in this session', first.api.getNodes().length, 0);

  // *** the test that caught the real bug: reboot against the same storage ***
  const second = boot(store, EXPORTS);
  second.api.restoreAll();
  second.api.renderLogSrc();
  eq('STILL blank after reload', second.api.getNodes().length, 0);
  eq('snapshots gone after reload', (second.api.getSnaps() || []).length, 0);
  ok('pending trace gone after reload', !second.api.getPending());
  eq('storage holds an empty node list', store['aegis-nodes'], '[]');
}

/* --------------------------------------------------------------- map editing */
section('map editing');
{
  const { api } = boot({}, EXPORTS);
  api.lsPresetZones();
  eq('preset creates the six standard zones', Object.keys(api.ZONES()).length, 6);

  // Zones must be free-form: moving one must not drag its hosts
  api.lsSeedTopology();
  const dmz = api.getNodes().filter(n => api.nodeZone(n) === 'dmz');
  const xs = dmz.map(n => n.x);
  const Z = api.ZONES()['dmz'];
  api.lsZoneRect('dmz');
  Z.x += 200; Z.y += 100;
  ok('moving a zone leaves its hosts in place',
    dmz.every((n, i) => n.x === xs[i]));

  // No boundary clamp
  const far = api.lsAddNode('dns', 5000, -800);
  ok('nodes may sit outside the nominal canvas', far.x === 5000 && far.y === -800);

  // Per-node scale
  far.scale = 2.2;
  ok('per-node scale reaches the SVG', api.lsNodesSVG().includes('scale(2.2'));
  ok('node delete handle rendered', api.lsNodesSVG().includes('ls-node-x'));
  ok('node resize handle rendered', api.lsNodesSVG().includes('ls-node-rs'));
  ok('zone delete handle rendered', api.lsZoneRegions().includes('ls-zone-x'));
  ok('zone body is draggable', api.lsZoneRegions().includes('class="ls-zone-body" data-zone='));
}

/* ------------------------------------------------------------ host inference */
section('host import inference');
{
  const { api, els } = boot({}, EXPORTS);
  eq('DC01 -> dc', api.lsGuessType('DC01'), 'dc');
  eq('SQL02 -> srv', api.lsGuessType('SQL02'), 'srv');
  eq('RTR-1 -> router', api.lsGuessType('RTR-1'), 'router');
  eq('WKS-101 -> wks', api.lsGuessType('WKS-101'), 'wks');
  eq('FW-EDGE -> fw', api.lsGuessType('FW-EDGE'), 'fw');
  eq('web01 -> dmz', api.lsGuessType('web01'), 'dmz');

  els['ls-imp-ta'] = mkEl('ls-imp-ta');
  els['ls-imp-ta'].value = 'DC01, dc, core\nFS01, srv\nWKS-101';
  const before = api.getNodes().length;
  api.lsRunImport();
  eq('import adds every pasted host', api.getNodes().length, before + 3);
}

/* ------------------------------------------------------------- SPL discipline */
section('SPL linter (project conventions)');
{
  const { api } = boot({}, EXPORTS);
  ok('flags ut_shannon without tonumber()',
    api.splLint('index=x | lookup ut_shannon_lookup word as q | where shannon>3')
      .some(r => r.sev === 'err'));
  ok('flags unbalanced quotes', api.splLint('index=x host="abc').some(r => /quotes/.test(r.msg)));
  ok('flags unbalanced parens', api.splLint('index=x | where (a=1').some(r => /parenthes/.test(r.msg)));
  ok('a conventional query passes',
    api.splLint('index=win sourcetype=WinEventLog EventCode=4688 | inputlookup append=t ok | stats dc(ComputerName)')
      .filter(r => r.sev === 'err').length === 0);
}

/* ----------------------------------------------------------------- triage flow */
section('artifact triage wizard');
{
  const { api } = boot({}, EXPORTS);
  api.lsSeedTopology();
  api.openArtifactTriage(api.getNodes()[0].uid);
  eq('wizard opens at step 0', api.getArt().step, 0);
  api.artPick('__type', 'file');
  eq('type selected', api.getArt().type, 'file');
  api.artPick('where', 'ProgramData');
  api.artPick('kind', 'Executable (.exe/.dll)');
  api.artPick('sig', 'Unsigned');
  eq('all answers captured', Object.keys(api.getArt().answers).length, 3);

  const tr = api.parseTriage('text\n\nTRIAGE={"sev":"malicious","label":"Unsigned exe","tech":"T1543"}');
  eq('verdict parsed', tr.sev, 'malicious');
  eq('technique parsed', tr.tech, 'T1543');
}

/* --------------------------------------------------------------- live mode */
section('live mode');
{
  const { api } = boot({}, EXPORTS);
  api.renderTickets();
  ok('tickets view explains it needs a server when offline', true);

  const a = api.lsAddNode('dc', 100, 100); a.agentId = 'ag1';
  const b = api.lsAddNode('wks', 300, 300); b.agentId = 'ag2';
  api.liveApplyLinks([{ a: 'ag1', b: 'ag2', port: 445 }]);
  eq('discovered link drawn', api.getEdges().filter(e => e.discovered).length, 1);
  api.liveApplyLinks([{ a: 'ag1', b: 'ag2', port: 445 }]);
  eq('re-applying links does not duplicate', api.getEdges().filter(e => e.discovered).length, 1);

  api.liveIngestEvent({ id: 'ev1', agentId: 'ag1', host: '', eventId: '9999', severity: 'suspicious', message: 'test', ts: Date.now(), technique: 'T1059' });
  eq('live-ingested technique tag reaches the node observation', a.obs[0].tech, 'T1059');
}

/* ------------------------------------------------------------- response advisor */
section('response advisor');
{
  const { api } = boot({}, EXPORTS);
  const withKb = api.adviseTechnique('T1078'); // has a specific RA_TECH entry
  const containEradicate = withKb.sections.filter(s => s.key === 'contain' || s.key === 'eradicate');
  ok('technique with a KB entry produces contain/eradicate items',
    containEradicate.some(s => s.items.length > 0));

  const noKb = api.adviseTechnique('T1595'); // Reconnaissance, no RA_TECH entry -> tactic fallback
  ok('technique with no KB entry still gets tactic-fallback items',
    noKb.sections.some(s => s.items.length > 0));

  const hosted = api.buildAdvisory({ techniques: ['T1078'], hosts: [{ host: 'TESTHOST01', ip: '10.1.1.1', type: 'wks', os: 'windows' }], iocs: [] });
  const hostText = hosted.sections.flatMap(s => s.items).map(i => i.text + i.cmd).join('\n');
  ok('host-specific commands name the literal hostname', hostText.includes('TESTHOST01'));

  api.lsSeedTopology();
  const n = api.getNodes()[0];
  n.obs = [{ id: 'o1', evId: '', note: 'beaconed out to 8.8.8.8', sev: 'suspicious', t: Date.now() }];
  const nodeAdv = api.adviseNode(n.uid);
  ok('adviseNode pulls IOCs from observation notes into the block phase',
    nodeAdv.sections.some(s => s.key === 'block' && s.items.length > 0));
}

/* ------------------------------------------------------------------- IOC extraction */
section('IOC extraction');
{
  const { api } = boot({}, EXPORTS);
  const text = 'host 203.0.113.5 (not 10.0.0.5) hit evil-domain.com via https://evil-domain.com/a?b=1, '
    + 'dropped a3f5e6c1b2a3f5e6c1b2a3f5e6c1b2a3f5e6c1b2a3f5e6c1b2a3f5e6c1b2a3f5, and used CVE-2024-12345';
  const iocs = api.extractIocs(text);
  const types = iocs.map(i => i.type);
  ok('extracts a public IPv4', types.includes('ipv4'));
  ok('excludes the private IPv4', !iocs.some(i => i.value === '10.0.0.5'));
  ok('extracts a domain', types.includes('domain'));
  ok('extracts a URL', types.includes('url'));
  ok('extracts a sha256 hash', types.includes('sha256'));
  ok('extracts a CVE', types.includes('cve'));

  const dup = api.extractIocs('203.0.113.5 seen twice: 203.0.113.5');
  eq('dedupes repeated indicators', dup.filter(i => i.value === '203.0.113.5').length, 1);

  const html = api.highlightIocs('<script>alert(1)</script> reached 203.0.113.5');
  ok('escapes HTML before highlighting', !html.includes('<script>'));
  ok('wraps the IOC in a span', html.includes('ioc-ip'));
}

/* ------------------------------------------------------------------- ingest */
function buildMiniPcap() {
  // one Ethernet+IPv4+TCP packet, no payload: global header + one record.
  const buf = new ArrayBuffer(24 + 16 + 54);
  const dv = new DataView(buf);
  const u8 = new Uint8Array(buf);
  dv.setUint32(0, 0xa1b2c3d4, true);  // magic (LE, microsecond precision)
  dv.setUint16(4, 2, true); dv.setUint16(6, 4, true); // version 2.4
  dv.setUint32(8, 0, true); dv.setUint32(12, 0, true); // thiszone, sigfigs
  dv.setUint32(16, 65535, true); // snaplen
  dv.setUint32(20, 1, true); // linktype = Ethernet
  let off = 24;
  dv.setUint32(off, 1700000000, true); dv.setUint32(off + 4, 0, true); // ts
  dv.setUint32(off + 8, 54, true); dv.setUint32(off + 12, 54, true);   // incl/orig len
  off += 16;
  // Ethernet: 6 dst + 6 src + 2 ethertype(0x0800)
  u8[off + 12] = 0x08; u8[off + 13] = 0x00;
  const l3 = off + 14;
  u8[l3] = 0x45; // version 4, IHL 5
  dv.setUint16(l3 + 2, 40, true); // total length
  u8[l3 + 9] = 6; // protocol = TCP
  u8[l3 + 12] = 203; u8[l3 + 13] = 0; u8[l3 + 14] = 113; u8[l3 + 15] = 10;   // saddr
  u8[l3 + 16] = 198; u8[l3 + 17] = 51; u8[l3 + 18] = 100; u8[l3 + 19] = 20; // daddr
  const l4 = l3 + 20;
  dv.setUint16(l4, 4444, false); dv.setUint16(l4 + 2, 443, false); // ports (big-endian on the wire)
  return buf;
}

section('ingest — format auto-detection');
{
  const { api } = boot({}, EXPORTS);
  eq('detects Chainsaw CSV by header', api.ingDetect('timestamp,detections\n2024-01-01,Test', 'export.csv'), 'chainsaw');
  eq('detects Suricata eve.json by event_type', api.ingDetect('{"event_type":"alert","src_ip":"1.2.3.4"}', 'eve.json'), 'suricata');
  eq('detects Zeek by #fields header', api.ingDetect('#separator \\x09\n#fields\tts\tuid\n1700000000\tC1', 'notice.log'), 'zeek');
  eq('detects PCAP by filename extension', api.ingDetect('', 'capture.pcap'), 'pcap');
  eq('unrecognised text has no profile', api.ingDetect('just some random text', ''), null);
}

section('ingest — Chainsaw');
{
  const { api } = boot({}, EXPORTS);
  const csv = 'timestamp,detections,Computer,User,Source IP,Event ID,Command Line,level,tags\n'
    + '2024-01-01T00:00:00Z,Suspicious PowerShell,WKS01,jdoe,203.0.113.5,4688,powershell -enc AAA,high,T1059';
  const parsed = api.ingParse(csv, 'chainsaw.csv');
  eq('profile resolved', parsed.profile, 'chainsaw');
  eq('one finding grouped by rule', parsed.findings.length, 1);
  eq('severity carried through', parsed.findings[0].severity, 'high');
  ok('technique extracted from the row', parsed.findings[0].attack.includes('T1059'));
  ok('IOC extracted from the source IP field', parsed.iocs.some(x => x.value === '203.0.113.5'));
}

section('ingest — Suricata');
{
  const { api } = boot({}, EXPORTS);
  const line = JSON.stringify({ timestamp: '2024-01-01T00:00:00.000Z', event_type: 'alert', src_ip: '203.0.113.5', src_port: 4444,
    dest_ip: '198.51.100.20', dest_port: 443, proto: 'TCP',
    alert: { signature: 'ET MALWARE Test', severity: 1, category: 'Malware', metadata: { mitre_technique_id: ['T1071'] } } });
  const parsed = api.ingParse(line, 'eve.json');
  eq('profile resolved', parsed.profile, 'suricata');
  eq('one finding for the alert', parsed.findings.length, 1);
  eq('severity mapped from Suricata scale (1 -> high)', parsed.findings[0].severity, 'high');
  ok('technique pulled from alert metadata', parsed.findings[0].attack.includes('T1071'));
  eq('one network event carries saddr/daddr', parsed.events.length, 1);
  eq('event source address captured', parsed.events[0].saddr, '203.0.113.5');
}

section('ingest — Zeek');
{
  const { api } = boot({}, EXPORTS);
  const tsv = '#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tnote\tmsg\n'
    + '1700000000.000000\tCabc123\t203.0.113.5\t4444\t198.51.100.20\t443\tSSH::Password_Guessing\tPossible brute force';
  const parsed = api.ingParse(tsv, 'notice.log');
  eq('profile resolved', parsed.profile, 'zeek');
  eq('one finding per notice type', parsed.findings.length, 1);
  ok('notice title includes the note type', parsed.findings[0].title.includes('Password_Guessing'));
}

section('ingest — PCAP');
{
  const { api } = boot({}, EXPORTS);
  const parsed = api.ingParsePcap(buildMiniPcap());
  ok('no parse error on a well-formed capture', !parsed.error);
  eq('one flow extracted', parsed.events.length, 1);
  eq('source address decoded correctly', parsed.events[0].saddr, '203.0.113.10');
  eq('dest address decoded correctly', parsed.events[0].daddr, '198.51.100.20');
  eq('protocol decoded as tcp', parsed.events[0].proto, 'tcp');
}

section('ingest — map building and commit');
{
  const { api } = boot({}, EXPORTS);
  const before = api.getNodes().length;
  const parsed = api.ingParse(
    JSON.stringify({ timestamp: '2024-01-01T00:00:00.000Z', event_type: 'alert', src_ip: '203.0.113.5', src_port: 4444,
      dest_ip: '198.51.100.20', dest_port: 443, proto: 'TCP',
      alert: { signature: 'ET MALWARE Test', severity: 1, category: 'Malware', metadata: { mitre_technique_id: ['T1071'] } } }),
    'eve.json');
  api.setIngState(parsed);
  api.ingCommit();
  eq('committing adds a host per IP seen', api.getNodes().length, before + 2);
  eq('committing adds an edge between them', api.getEdges().length, 1);
  const withObs = api.getNodes().filter(n => (n.obs || []).length);
  ok('the finding is logged as an observation on a host', withObs.length > 0);
  ok('a technique from the finding is staged', api.studio.has('T1071'));
  ok('ingState is cleared after commit', api.getIngState() === null);
}

/* ------------------------------------------------------------------ exports */
section('exports and report');
{
  const { api } = boot({}, EXPORTS);
  api.SCENARIOS.ransomware.techs.forEach(t => api.studio.add(t));
  api.renderMatrix(); api.renderStudio();
  ok('sigma bundle generates rules', api.buildSigmaBundle().split('---').length > 5);
  ok('savedsearches.conf generates stanzas',
    (api.buildSavedSearches().match(/\[AEGIS -/g) || []).length >= 5);

  api.lsSeedTopology();
  const nums = [...api.reportHTML().matchAll(/<span class="n">(\d+)<\/span>/g)].map(m => +m[1]);
  ok('report sections are sequential', nums.length > 0 && nums.every((n, i) => n === i + 1),
    nums.join(','));
}

/* --------------------------------------------------------------------- done */
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

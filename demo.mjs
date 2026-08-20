#!/usr/bin/env node
/**
 * Seed a running AEGIS server with a realistic incident so you can see what
 * the console looks like with data in it.
 *
 *   node demo.mjs                 seed against the local server
 *   node demo.mjs --url http://…  seed a different server
 *
 * Reads the tokens from server/config.json. Everything it creates goes
 * through the normal API - no back doors - so this doubles as an end-to-end
 * check that enrolment, telemetry, tickets, cases and chat all work.
 *
 * Safe to run more than once; it just adds another round of data.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const val = (f, d) => { const i = argv.indexOf(f); return i > -1 && argv[i + 1] ? argv[i + 1] : d; };

let cfg;
try { cfg = JSON.parse(fs.readFileSync(path.join(ROOT, 'server', 'config.json'), 'utf8')); }
catch { console.error('No server/config.json - run `npm run setup` first.'); process.exit(1); }

const BASE = (val('--url', `http://127.0.0.1:${cfg.port || 8787}`)).replace(/\/$/, '');
const ANALYST = cfg.analystToken;
const ENROLL = cfg.enrollmentToken;

const api = async (p, opts = {}, tok = ANALYST) => {
  const r = await fetch(BASE + p, {
    ...opts,
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + tok, ...(opts.headers || {}) },
  });
  if (!r.ok) throw new Error(`${opts.method || 'GET'} ${p} -> ${r.status} ${await r.text()}`);
  return r.json();
};

const HOSTS = [
  { hostname: 'DC01', os: 'Windows Server 2022', ip: '10.10.1.10', roles: ['dc'] },
  { hostname: 'FS01', os: 'Windows Server 2019', ip: '10.10.1.20', roles: ['srv'] },
  { hostname: 'WEB01', os: 'Ubuntu Server 24.04', ip: '10.10.9.5', roles: ['dmz'] },
  { hostname: 'WKS-042', os: 'Windows 11', ip: '10.10.5.42', roles: ['wks'] },
  { hostname: 'WKS-108', os: 'Windows 11', ip: '10.10.5.108', roles: ['wks'] },
];

/* A coherent intrusion rather than random noise: exploited web server ->
   credential theft -> lateral movement to the file server -> ransomware
   preparation. It reads as a story on the map and in the timeline. */
const STORY = [
  ['WEB01', 'auditd', '1100', 'malicious', 'Webshell written to /var/www/html/uploads/x.php', 'T1505'],
  ['WEB01', 'syslog', 'sudo', 'suspicious', 'sudo: www-data ran /bin/bash', 'T1548'],
  ['WKS-042', 'Microsoft-Windows-PowerShell/Operational', '4104', 'malicious', 'powershell -enc SQBFAFgA… downloadstring', 'T1059.001'],
  ['WKS-042', 'Microsoft-Windows-Sysmon/Operational', '10', 'malicious', 'lsass.exe access by procdump.exe', 'T1003.001'],
  ['WKS-042', 'Security', '4688', 'suspicious', 'C:\\Users\\Public\\svc.exe launched from a suspicious path', 'T1036'],
  ['DC01', 'Security', '4625', 'suspicious', 'Failed logon burst for admin from 10.10.5.42', 'T1110'],
  ['DC01', 'Security', '4624', 'info', 'Successful logon type 3 for svc_backup from 10.10.5.42', 'T1078'],
  ['DC01', 'Security', '4728', 'malicious', 'svc_backup added to Domain Admins', 'T1098'],
  ['FS01', 'Security', '5145', 'suspicious', 'Share access: \\\\FS01\\Finance by svc_backup', 'T1021.002'],
  ['FS01', 'System', '7045', 'malicious', 'Service installed: C:\\Windows\\Temp\\enc.exe', 'T1543.003'],
  ['FS01', 'Security', '4688', 'malicious', 'vssadmin delete shadows /all /quiet', 'T1490'],
  ['FS01', 'System', '104', 'malicious', 'System event log cleared', 'T1070.001'],
];

const log = (...a) => console.log('  ', ...a);

(async () => {
  console.log('\n  Seeding AEGIS demo data →', BASE, '\n');

  // 1. enrol the estate
  const agents = {};
  for (const h of HOSTS) {
    const r = await (await fetch(BASE + '/api/enroll', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enrollmentToken: ENROLL, ...h, version: '1.1.0' }),
    })).json();
    agents[h.hostname] = r;
    log('enrolled', h.hostname.padEnd(9), h.ip);
  }

  // 2. tell the server who talks to whom, so the map draws real links
  const peers = {
    'WKS-042': ['10.10.1.10', '10.10.1.20'],
    'DC01': ['10.10.5.42'],
    'FS01': ['10.10.5.42', '10.10.1.10'],
    'WEB01': ['10.10.5.42'],
    'WKS-108': ['10.10.1.10'],
  };
  for (const [host, ips] of Object.entries(peers)) {
    const a = agents[host];
    await fetch(BASE + '/api/discovery', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Agent-Id': a.agentId, 'X-Agent-Key': a.agentKey },
      body: JSON.stringify({
        peers: ips.map(ip => ({ ip, port: 445, proto: 'tcp' })),
        listening: [445, 3389],
        logging: { sysmon: host !== 'WKS-108', scriptBlock: true, cmdLine: true, shareAudit: host === 'FS01' },
      }),
    });
  }
  log('topology  ', Object.keys(peers).length, 'hosts reporting peers');

  // 3. the intrusion itself
  const t0 = Date.now() - 1000 * 60 * 90;
  for (let i = 0; i < STORY.length; i++) {
    const [host, channel, eventId, severity, message, technique] = STORY[i];
    const a = agents[host];
    await fetch(BASE + '/api/events', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Agent-Id': a.agentId, 'X-Agent-Key': a.agentKey },
      body: JSON.stringify({ events: [{ ts: t0 + i * 1000 * 60 * 7, channel, eventId, severity, message, technique, fields: {} }] }),
    });
  }
  log('telemetry ', STORY.length, 'events across the kill chain');

  // 4. a case, with the tickets under it
  const kase = await api('/api/cases', {
    method: 'POST',
    body: JSON.stringify({
      title: 'Ransomware staging on the finance share',
      severity: 'critical', status: 'contained',
      execSummary: 'An internet-facing web server was exploited and used to reach a workstation, where credentials were stolen. Those credentials were used to reach the finance file server, where backups were deleted and encryption tooling was staged. Encryption did not run.',
      scope: 'WEB01 (entry), WKS-042 (credential theft), DC01 (privilege escalation), FS01 (staging). No data is believed to have left the estate; egress logs show no bulk transfer.',
      remediation: 'All four hosts isolated and rebuilt. svc_backup and every account with a session on WKS-042 reset; krbtgt rotated twice. Webshell removed and the application patched. Shadow copies restored from off-site backup.',
    }),
  });
  log('case      ', '#' + kase.num, kase.title);

  const tickets = [
    ['Webshell dropped on WEB01', 'Recently-modified PHP in the web root with eval/base64_decode. Entry point for the intrusion.', 'critical', 'WEB01', 'T1505',
      'An internet-facing server was compromised through its web application and used as the way in.'],
    ['LSASS access on WKS-042', 'procdump.exe accessed lsass.exe. Every credential cached on this host must be treated as stolen.', 'critical', 'WKS-042', 'T1003.001',
      'Stored passwords on an affected workstation were exposed and have all been changed.'],
    ['svc_backup added to Domain Admins', 'Group change on DC01 from the compromised workstation. Not a change request.', 'high', 'DC01', 'T1098',
      'An account was given administrator rights it should not have had. The rights were removed and the account reset.'],
    ['Shadow copies deleted on FS01', 'vssadmin delete shadows /all /quiet, immediately before encryption tooling was staged.', 'critical', 'FS01', 'T1490',
      'Local backups on the file server were deleted in preparation for ransomware. Off-site backups were unaffected and were used to restore.'],
  ];
  for (const [title, body, severity, host, technique, formalSummary] of tickets) {
    const t = await api('/api/tickets', { method: 'POST', body: JSON.stringify({ title, body, severity, host, technique, caseId: kase.id }) });
    await api(`/api/tickets/${t.id}`, { method: 'PATCH', body: JSON.stringify({ includeInFormal: true, formalSummary }) });
    await api(`/api/tickets/${t.id}/comments`, { method: 'POST', body: JSON.stringify({ text: 'Host isolated and evidence captured.' }) });
  }
  log('tickets   ', tickets.length, 'raised, curated for the formal report');

  // 5. a little chatter, because an empty panel shows nothing
  for (const text of [
    'FS01 is isolated - shadow copies are gone but the off-site backup is intact.',
    'Confirmed lsass access on WKS-042. Rotating everything that had a session there.',
    'krbtgt reset once, second pass scheduled after replication.',
  ]) await api('/api/chat', { method: 'POST', body: JSON.stringify({ text }) });
  log('chat      ', '3 messages');

  console.log(`\n  Done. Open ${BASE} and connect with the analyst token.\n`);
})().catch(e => { console.error('\n  Failed:', e.message, '\n'); process.exit(1); });

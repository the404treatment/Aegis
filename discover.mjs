#!/usr/bin/env node
/**
 * Network check: find the machines on your network that AEGIS could collect
 * from, and work out how each one would need to be reached.
 *
 *   node discover.mjs                    scan the subnets this machine is on
 *   node discover.mjs --range 10.0.0.0/24
 *   node discover.mjs --json targets.json   write a target file for deployment
 *
 * This is a TCP connect scan against a small set of admin ports, plus reverse
 * DNS. It does not authenticate, log in, or send anything to the hosts it
 * finds - it only asks whether a port accepts a connection, which is what any
 * `telnet host 445` would do.
 *
 * Only scan networks you are responsible for. On a corporate network, tell
 * whoever runs it first: a sweep across every host looks exactly like the
 * reconnaissance AEGIS itself is built to detect, and it will (correctly)
 * light up an IDS.
 *
 * Zero dependencies.
 */
import net from 'node:net';
import os from 'node:os';
import dns from 'node:dns/promises';
import fs from 'node:fs';

const argv = process.argv.slice(2);
const has = f => argv.includes(f);
const val = (f, d) => { const i = argv.indexOf(f); return i > -1 && argv[i + 1] ? argv[i + 1] : d; };

const COLOUR = process.stdout.isTTY && !process.env.NO_COLOR;
const w = code => s => (COLOUR ? `\x1b[${code}m${s}\x1b[0m` : String(s));
const c = { b: w(1), dim: w(2), g: w(32), y: w(33), cy: w(36), r: w(31) };

/* Ports that tell us how (and whether) we could deploy to a host.
   Deliberately a short list: this is a deployment survey, not a port scan. */
const PROBES = [
  { port: 445, label: 'SMB', os: 'windows' },
  { port: 5985, label: 'WinRM', os: 'windows', deploy: 'winrm' },
  { port: 3389, label: 'RDP', os: 'windows' },
  { port: 22, label: 'SSH', os: 'linux', deploy: 'ssh' },
];
const CONNECT_TIMEOUT = Number(val('--timeout', 400));
const CONCURRENCY = Number(val('--concurrency', 256));

const probe = (host, port) => new Promise(resolve => {
  const s = new net.Socket();
  let done = false;
  const finish = ok => { if (done) return; done = true; s.destroy(); resolve(ok); };
  s.setTimeout(CONNECT_TIMEOUT);
  s.once('connect', () => finish(true));
  s.once('timeout', () => finish(false));
  s.once('error', () => finish(false));
  s.connect(port, host);
});

/** Expand a CIDR into host addresses. IPv4 only, /16 at the widest. */
function expandCidr(cidr) {
  const [base, bitsRaw] = cidr.split('/');
  const bits = Number(bitsRaw);
  if (!base || !Number.isInteger(bits) || bits < 16 || bits > 32) {
    throw new Error(`bad range "${cidr}" - use CIDR between /16 and /32, e.g. 10.0.0.0/24`);
  }
  const octets = base.split('.').map(Number);
  if (octets.length !== 4 || octets.some(o => !Number.isInteger(o) || o < 0 || o > 255)) {
    throw new Error(`bad address in "${cidr}"`);
  }
  const toInt = o => ((o[0] << 24) >>> 0) + (o[1] << 16) + (o[2] << 8) + o[3];
  const toIp = n => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
  const mask = bits === 32 ? 0xffffffff : (~((1 << (32 - bits)) - 1)) >>> 0;
  const net0 = (toInt(octets) & mask) >>> 0;
  const size = bits === 32 ? 1 : 2 ** (32 - bits);
  const out = [];
  // skip network and broadcast on anything wider than a /31
  const start = size > 2 ? 1 : 0;
  const end = size > 2 ? size - 1 : size;
  for (let i = start; i < end; i++) out.push(toIp((net0 + i) >>> 0));
  return out;
}

/** The subnets this machine is actually on, as CIDR. */
function localRanges() {
  const out = [];
  for (const [name, addrs] of Object.entries(os.networkInterfaces())) {
    for (const a of addrs || []) {
      if (a.family !== 'IPv4' || a.internal) continue;
      const bits = a.netmask.split('.').reduce((n, o) => n + ((Number(o) >>> 0).toString(2).match(/1/g) || []).length, 0);
      if (bits < 22) continue;   // don't sweep something enormous by accident
      const virtual = /vmware|virtualbox|hyper-v|vethernet|nord|wireguard|tailscale|zerotier|docker|wsl/i.test(name);
      out.push({ name, cidr: `${a.address}/${bits}`, self: a.address, virtual });
    }
  }
  return out;
}

async function pool(items, limit, fn) {
  const out = [];
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (i < items.length) { const n = i++; out[n] = await fn(items[n], n); }
  }));
  return out;
}

(async () => {
  console.log('');
  console.log(c.b('  AEGIS network check'));
  console.log(c.dim('  ' + '─'.repeat(64)));

  let ranges;
  const explicit = val('--range', null);
  if (explicit) {
    ranges = [{ name: 'specified', cidr: explicit, self: null, virtual: false }];
  } else {
    ranges = localRanges().filter(r => !r.virtual);
    const skipped = localRanges().filter(r => r.virtual);
    if (!ranges.length) {
      console.log(c.r('  No usable network found.'));
      console.log('  Pass one explicitly:  node discover.mjs --range 10.0.0.0/24\n');
      process.exit(1);
    }
    ranges.forEach(r => console.log(`  scanning        ${c.cy(r.cidr)} ${c.dim('(' + r.name + ')')}`));
    skipped.forEach(r => console.log(c.dim(`  skipping        ${r.cidr} (${r.name}, virtual)`)));
  }

  let hosts = [];
  for (const r of ranges) {
    try { hosts.push(...expandCidr(r.cidr).map(ip => ({ ip, via: r.name, self: r.self }))); }
    catch (e) { console.log(c.r('  ' + e.message)); process.exit(1); }
  }
  // don't probe ourselves
  hosts = hosts.filter(h => h.ip !== h.self);
  console.log(`  addresses       ${hosts.length}`);
  console.log(c.dim('  This is a connect scan on a handful of admin ports. Only run it on'));
  console.log(c.dim('  networks you are responsible for - it looks like recon, because it is.'));
  console.log('');

  process.stdout.write('  probing… ');
  const found = [];
  let done = 0;
  await pool(hosts, CONCURRENCY, async h => {
    const open = [];
    for (const p of PROBES) if (await probe(h.ip, p.port)) open.push(p);
    done++;
    if (done % 32 === 0) process.stdout.write('.');
    if (!open.length) return;
    let name = '';
    try { const r = await dns.reverse(h.ip); name = (r && r[0]) || ''; } catch { }
    const isWin = open.some(p => p.os === 'windows');
    const isNix = open.some(p => p.os === 'linux');
    found.push({
      ip: h.ip,
      name,
      os: isWin && !isNix ? 'windows' : isNix && !isWin ? 'linux' : isWin ? 'windows' : 'unknown',
      open: open.map(p => p.label),
      // how we could push an agent, if at all
      deploy: open.find(p => p.deploy === 'winrm') ? 'winrm'
        : open.find(p => p.deploy === 'ssh') ? 'ssh' : null,
    });
  });
  console.log('');
  console.log('');

  found.sort((a, b) => a.ip.localeCompare(b.ip, undefined, { numeric: true }));

  if (!found.length) {
    console.log(c.y('  Nothing responded.'));
    console.log('  Either the network is empty, or a firewall is dropping the probes.');
    console.log('  Agents can still be installed by hand - see INSTALL.md.\n');
  } else {
    console.log(c.b(`  ${found.length} host${found.length === 1 ? '' : 's'} responded`));
    console.log(c.dim('  ' + '─'.repeat(64)));
    console.log(c.dim('  address          name                      os        open           deploy via'));
    for (const h of found) {
      const via = h.deploy ? c.g(h.deploy) : c.dim('manual');
      console.log(`  ${h.ip.padEnd(16)} ${(h.name || '—').slice(0, 24).padEnd(25)} ${h.os.padEnd(9)} ${h.open.join(',').padEnd(14)} ${via}`);
    }
    const reachable = found.filter(h => h.deploy).length;
    console.log('');
    console.log(`  ${c.g(reachable)} of ${found.length} could take an agent push (WinRM or SSH).`);
    if (reachable < found.length) {
      console.log(c.dim('  The rest need the agent installed by hand, by GPO, or by your own'));
      console.log(c.dim('  management tooling - see INSTALL.md.'));
    }
  }

  const outFile = val('--json', null);
  if (outFile) {
    fs.writeFileSync(outFile, JSON.stringify({ scannedAt: new Date().toISOString(), hosts: found }, null, 2) + '\n');
    console.log('');
    console.log(`  Target list written to ${c.cy(outFile)}`);
    console.log(c.dim('  Review it, delete anything that should not get an agent, then:'));
    console.log(`    ${c.cy(`node deploy-agents.mjs --targets ${outFile}`)}`);
  } else if (found.some(h => h.deploy)) {
    console.log('');
    console.log(c.dim('  Save this as a target list to deploy from:'));
    console.log(`    ${c.cy('node discover.mjs --json targets.json')}`);
  }
  console.log('');
})();

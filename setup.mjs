#!/usr/bin/env node
/**
 * AEGIS setup. One command to go from a fresh clone to a running server that
 * agents on the network can actually reach.
 *
 *   node setup.mjs            interactive-ish: picks sane defaults, explains them
 *   node setup.mjs --lan      bind to all interfaces (agents can reach it)
 *   node setup.mjs --local    bind to loopback only (this machine only)
 *   node setup.mjs --port N   use a different port
 *
 * Idempotent: re-running keeps the tokens and data you already have. Rotating
 * a token is an explicit --rotate, never a side effect of running setup again.
 *
 * Zero dependencies, like the rest of the project.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const CFG_PATH = path.join(ROOT, 'server', 'config.json');
const argv = process.argv.slice(2);
const has = f => argv.includes(f);
const val = (f, d) => { const i = argv.indexOf(f); return i > -1 && argv[i + 1] ? argv[i + 1] : d; };

// Colour only when a human is watching. Piped into a file or an older console
// the escape codes are just noise, and this output is meant to be copied.
const COLOUR = process.stdout.isTTY && !process.env.NO_COLOR;
const w = code => s => (COLOUR ? `\x1b[${code}m${s}\x1b[0m` : String(s));
const c = { b: w(1), dim: w(2), g: w(32), y: w(33), cy: w(36), r: w(31) };
const line = () => console.log(c.dim('  ' + '─'.repeat(64)));
const token = () => crypto.randomBytes(24).toString('base64url');

/** Best-guess LAN address: a private IPv4 on a real, non-virtual adapter. */
function lanIp() {
  const ifs = os.networkInterfaces();
  const candidates = [];
  for (const [name, addrs] of Object.entries(ifs)) {
    for (const a of addrs || []) {
      if (a.family !== 'IPv4' || a.internal) continue;
      // Virtual adapters (VMware/Hyper-V/VPN) usually aren't the address the
      // rest of the office can route to, so rank them last rather than
      // silently picking one and sending every agent to a dead end.
      const virtual = /vmware|virtualbox|hyper-v|vethernet|loopback|nord|wireguard|tailscale|zerotier|docker|wsl/i.test(name);
      candidates.push({ name, ip: a.address, virtual });
    }
  }
  candidates.sort((x, y) => (x.virtual === y.virtual ? 0 : x.virtual ? 1 : -1));
  return candidates;
}

/** Is this binary actually on PATH? */
function have(bin) {
  try {
    execFileSync(process.platform === 'win32' ? 'where' : 'sh',
      process.platform === 'win32' ? [bin] : ['-c', `command -v ${bin}`], { stdio: 'ignore' });
    return true;
  } catch { return false; }
}

/**
 * Which host firewall is actually installed.
 *
 * Printing the ufw command *and* the firewalld command and letting the reader
 * pick sends everyone running neither - Kali, Arch, most containers, plenty of
 * minimal server images - off installing packages that do not exist, to solve
 * a problem they may not have. Several distributions ship no active host
 * firewall at all, in which case the port is already reachable and the correct
 * instruction is "do nothing, go test it".
 */
function firewallAdvice(port) {
  if (have('ufw')) return { tool: 'ufw', cmds: [`sudo ufw allow ${port}/tcp`] };
  if (have('firewall-cmd')) return {
    tool: 'firewalld',
    cmds: [`sudo firewall-cmd --add-port=${port}/tcp --permanent`, 'sudo firewall-cmd --reload'],
  };
  // nft/iptables rules here are runtime-only on purpose: making them survive a
  // reboot differs per distro (nftables.conf, iptables-persistent, NetworkManager)
  // and guessing wrong writes a rule to a file the system does not read.
  if (have('nft')) return {
    tool: 'nftables',
    cmds: [`sudo nft add rule inet filter input tcp dport ${port} accept`],
    volatile: true,
  };
  if (have('iptables')) return {
    tool: 'iptables',
    cmds: [`sudo iptables -I INPUT -p tcp --dport ${port} -j ACCEPT`],
    volatile: true,
  };
  return { tool: null, cmds: [] };
}

console.log('');
console.log(c.b('  AEGIS setup'));
line();

/* ---------------------------------------------------------------- node */
const major = Number(process.versions.node.split('.')[0]);
if (major < 18) {
  console.log(c.r(`  Node ${process.versions.node} is too old - AEGIS needs 18 or newer.`));
  console.log('  Install a current Node from https://nodejs.org and run this again.');
  process.exit(1);
}
console.log(`  node            ${c.g(process.versions.node)}`);

/* -------------------------------------------------------------- config */
let cfg = {};
let existing = false;
if (fs.existsSync(CFG_PATH)) {
  try { cfg = JSON.parse(fs.readFileSync(CFG_PATH, 'utf8')); existing = true; }
  catch { console.log(c.y('  existing config.json is not valid JSON - writing a fresh one')); }
}

const nics = lanIp();
const primary = nics.find(n => !n.virtual) || nics[0];
const wantLocal = has('--local');
const host = wantLocal ? '127.0.0.1' : '0.0.0.0';
const port = Number(val('--port', cfg.port || 8787));

// Tokens are generated once and then left alone. Re-running setup must never
// silently invalidate every enrolled agent.
const rotate = has('--rotate');
const enrollmentToken = (!rotate && cfg.enrollmentToken) || token();
const analystToken = (!rotate && cfg.analystToken) || token();

cfg = {
  ...cfg,
  host, port,
  dataDir: cfg.dataDir || './server/data',
  uiDir: cfg.uiDir || './ui',
  enrollmentToken, analystToken,
  // Named accounts on by default, so every action in the case file is
  // attributable. `?? true` and not `= true`: re-running setup must not
  // silently switch accounts back on for someone who deliberately turned
  // them off. The first account is created from the login screen, so this
  // cannot lock anyone out.
  requireLogin: cfg.requireLogin ?? true,
};

fs.mkdirSync(path.dirname(CFG_PATH), { recursive: true });
fs.writeFileSync(CFG_PATH, JSON.stringify(cfg, null, 2) + '\n');
console.log(`  config          ${c.g(existing ? 'updated' : 'created')} ${c.dim('server/config.json')}`);
if (rotate) console.log(c.y('  tokens          ROTATED - every enrolled agent must re-enroll'));

/* --------------------------------------------------------------- build */
try {
  execFileSync(process.execPath, [path.join(ROOT, 'build.mjs')], { stdio: 'pipe' });
  console.log(`  console         ${c.g('built')} ${c.dim('ui/index.html')}`);
} catch (e) {
  console.log(c.r('  build FAILED'));
  console.log(String(e.stdout || e.message));
  process.exit(1);
}

/* ---------------------------------------------------------------- done */
const reachAt = wantLocal ? '127.0.0.1' : (primary ? primary.ip : '<this-machine-ip>');
const serverUrl = `http://${reachAt}:${port}`;

console.log('');
console.log(c.b('  Ready.'));
line();
console.log(`  Open the console   ${c.cy(`http://127.0.0.1:${port}`)}`);
if (!wantLocal) {
  console.log(`  Agents report to   ${c.cy(serverUrl)}`);
  if (primary) console.log(c.dim(`                     (via ${primary.name})`));
  if (nics.length > 1) {
    console.log(c.dim('  Other addresses on this machine:'));
    nics.filter(n => n !== primary).forEach(n =>
      console.log(c.dim(`      ${n.ip.padEnd(16)} ${n.name}${n.virtual ? ' (virtual - probably not this one)' : ''}`)));
  }
}
console.log('');
console.log('  Analyst token   ' + c.b(analystToken));
console.log('  Enrollment      ' + c.b(enrollmentToken));
console.log(c.dim('  (also printed each time the server starts)'));

console.log('');
console.log(c.b('  Start it'));
line();
console.log(`    ${c.cy('npm start')}          ${c.dim('or double-click start.cmd / ./start.sh')}`);

if (!wantLocal) {
  console.log('');
  console.log(c.b('  Let agents through the firewall'));
  line();
  if (process.platform === 'win32') {
    console.log('  Windows blocks inbound ' + port + ' by default. In an ' + c.b('admin') + ' PowerShell:');
    console.log(c.cy(`    New-NetFirewallRule -DisplayName "AEGIS ${port}" -Direction Inbound \``));
    console.log(c.cy(`      -Protocol TCP -LocalPort ${port} -Action Allow -Profile Domain,Private`));
    console.log(c.dim('  Domain,Private on purpose - this should not be open on a public network.'));
  } else {
    const fw = firewallAdvice(port);
    if (!fw.tool) {
      console.log(`  ${c.g('No host firewall found on this machine')} ${c.dim('(no ufw, firewalld, nft or iptables).')}`);
      console.log(c.dim(`  Nothing to open - port ${port} should already be reachable. Test it from`));
      console.log(c.dim('  another machine before changing anything:'));
      console.log(`    ${c.cy(`curl -s http://${reachAt}:${port}/api/health`)}`);
    } else {
      console.log(c.dim(`  Detected ${fw.tool}:`));
      fw.cmds.forEach(cmd => console.log(`    ${c.cy(cmd)}`));
      if (fw.volatile) {
        console.log(c.dim('  That rule applies now but does not survive a reboot - persisting it'));
        console.log(c.dim(`  differs per distro, so make it permanent the way yours expects.`));
      }
    }
  }

  console.log('');
  console.log(c.b('  Deploy an agent'));
  line();
  console.log('  Windows endpoint, in an ' + c.b('admin') + ' PowerShell:');
  console.log(c.cy(`    .\\aegis-agent.ps1 -Server ${serverUrl} \``));
  console.log(c.cy(`      -EnrollmentToken ${enrollmentToken} -Install`));
  console.log('');
  console.log('  Linux/macOS endpoint, as root:');
  // Invoked through python3 rather than ./aegis-agent.py on purpose: a ZIP
  // download (rather than a git clone) does not preserve the executable bit,
  // and `sudo ./aegis-agent.py` then fails with a misleading "command not
  // found" that reads like the file is missing. Naming the interpreter works
  // either way.
  console.log(c.cy(`    sudo python3 agents/aegis-agent.py --server ${serverUrl} \\`));
  console.log(c.cy(`      --token ${enrollmentToken} --once`));
  console.log('');
  console.log(c.y('  These tokens are secrets. The server has no TLS of its own, so on an'));
  console.log(c.y('  untrusted network put a TLS proxy in front - see deploy/README-deploy.md.'));
}
console.log('');

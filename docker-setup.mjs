#!/usr/bin/env node
/**
 * One command instead of the several copy-paste steps a Docker install
 * otherwise needs: writes deploy/config.json with real tokens and the
 * container-correct paths, asks (once, only when there is a terminal to ask)
 * whether other machines should be able to reach this server, then runs
 * `docker compose up -d --build`.
 *
 *   node docker-setup.mjs            asks about LAN exposure if run interactively
 *   node docker-setup.mjs --lan      expose to the LAN, no prompt
 *   node docker-setup.mjs --local    localhost only, no prompt (also the default
 *                                    when run non-interactively, e.g. from CI)
 *   node docker-setup.mjs --port N   use a different port
 *   node docker-setup.mjs --rotate   issue new tokens even if config.json already exists
 *
 * What this does NOT do: install Docker itself. Same reasoning as
 * setup-local-ai.mjs not installing an inference runtime - downloading and
 * running someone else's installer from a script is the supply-chain problem
 * AEGIS exists to help you detect. It checks for Docker and tells you what to
 * install if it is missing, and stops there.
 *
 * Idempotent, like setup.mjs: re-running keeps existing tokens unless
 * --rotate is passed. host/dataDir/uiDir inside deploy/config.json are always
 * forced to the values the container needs (they are not a deployment choice
 * the way they are for a native install - a wrong value there is a container
 * that starts and answers nothing, not a preference).
 *
 * Zero dependencies.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { createInterface } from 'node:readline/promises';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const DEPLOY_DIR = path.join(ROOT, 'deploy');
const CFG_PATH = path.join(DEPLOY_DIR, 'config.json');
const ENV_PATH = path.join(DEPLOY_DIR, '.env');
const DATA_DIR = path.join(DEPLOY_DIR, 'data');

const argv = process.argv.slice(2);
const has = f => argv.includes(f);
const val = (f, d) => { const i = argv.indexOf(f); return i > -1 && argv[i + 1] ? argv[i + 1] : d; };

const COLOUR = process.stdout.isTTY && !process.env.NO_COLOR;
const w = k => s => (COLOUR ? `\x1b[${k}m${s}\x1b[0m` : String(s));
const c = { b: w(1), dim: w(2), g: w(32), y: w(33), r: w(31), cy: w(36) };
const say = (...a) => console.log(...a);
const line = () => say(c.dim('  ' + '-'.repeat(64)));
const token = () => crypto.randomBytes(24).toString('base64url');
const isPlaceholder = v => !v || /CHANGE-ME/i.test(v);

/** Is this binary actually on PATH? */
function have(bin) {
  try {
    execFileSync(process.platform === 'win32' ? 'where' : 'sh',
      process.platform === 'win32' ? [bin] : ['-c', `command -v ${bin}`], { stdio: 'ignore' });
    return true;
  } catch { return false; }
}

/** Which host firewall exists here - same reasoning as setup.mjs: naming a
 *  tool the machine does not have sends people installing packages to solve a
 *  problem they may not have. */
function firewallAdvice(port) {
  if (have('ufw')) return { tool: 'ufw', cmds: [`sudo ufw allow ${port}/tcp`] };
  if (have('firewall-cmd')) return {
    tool: 'firewalld',
    cmds: [`sudo firewall-cmd --add-port=${port}/tcp --permanent`, 'sudo firewall-cmd --reload'],
  };
  if (have('nft')) return {
    tool: 'nftables',
    cmds: [`sudo nft add rule inet filter input tcp dport ${port} accept`], volatile: true,
  };
  if (have('iptables')) return {
    tool: 'iptables',
    cmds: [`sudo iptables -I INPUT -p tcp --dport ${port} -j ACCEPT`], volatile: true,
  };
  return { tool: null, cmds: [] };
}

/** Same heuristic as setup.mjs: a private IPv4 on a real, non-virtual adapter. */
function lanIp() {
  const candidates = [];
  for (const [name, addrs] of Object.entries(os.networkInterfaces())) {
    for (const a of addrs || []) {
      if (a.family !== 'IPv4' || a.internal) continue;
      const virtual = /vmware|virtualbox|hyper-v|vethernet|loopback|nord|wireguard|tailscale|zerotier|docker|wsl/i.test(name);
      candidates.push({ name, ip: a.address, virtual });
    }
  }
  candidates.sort((x, y) => (x.virtual === y.virtual ? 0 : x.virtual ? 1 : -1));
  return candidates;
}

say('');
say(c.b('  AEGIS Docker setup'));
line();

/* ---------------------------------------------------------------- docker */
function sh(cmd, args) { try { return execFileSync(cmd, args, { stdio: 'pipe' }).toString(); } catch { return null; } }

if (!sh('docker', ['--version'])) {
  say(`  ${c.r('Docker was not found.')}`);
  say('');
  say(`  ${c.b('Install it first:')}`);
  say(`     Windows / macOS   ${c.cy('https://www.docker.com/products/docker-desktop/')}`);
  say(`     Linux             ${c.cy('https://docs.docker.com/engine/install/')}`);
  say(`     Proxmox           see the Docker-on-Proxmox section of INSTALL.md - Docker does not`);
  say(`                       run on the Proxmox host itself`);
  say('');
  say(`  ${c.dim('Then run this again:')}  ${c.cy('node docker-setup.mjs')}`);
  say('');
  process.exit(1);
}

let compose = ['docker', 'compose'];
if (!sh('docker', ['compose', 'version'])) {
  if (sh('docker-compose', ['--version'])) {
    compose = ['docker-compose'];
  } else {
    say(`  ${c.r('Docker is installed, but the Compose plugin is not.')}`);
    say(`  ${c.dim('Install it:')} ${c.cy('https://docs.docker.com/compose/install/')}`);
    say('');
    process.exit(1);
  }
}
say(`  docker          ${c.g('found')}`);

/* -------------------------------------------------------------- config */
let cfg = {};
let existing = false;
if (fs.existsSync(CFG_PATH)) {
  try { cfg = JSON.parse(fs.readFileSync(CFG_PATH, 'utf8').replace(/^﻿/, '')); existing = true; }
  catch { say(c.y('  existing deploy/config.json is not valid JSON - writing a fresh one')); }
}

const port = Number(val('--port', cfg.port || 8787));
const rotate = has('--rotate');
const enrollmentToken = (!rotate && !isPlaceholder(cfg.enrollmentToken)) ? cfg.enrollmentToken : token();
const analystToken = (!rotate && !isPlaceholder(cfg.analystToken)) ? cfg.analystToken : token();

/* ------------------------------------------------------------ LAN choice */
async function askLan() {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  say('');
  say(`  ${c.b('Should other machines on your network be able to reach this server?')}`);
  say(`  ${c.dim('Choose yes if agents will run on different machines than this one.')}`);
  say(`  ${c.dim('Choose no for a single-machine lab, or if you will put a reverse proxy in front.')}`);
  const ans = (await rl.question(`  Expose to the network? ${c.dim('[y/N]')} `)).trim().toLowerCase();
  rl.close();
  return ans === 'y' || ans === 'yes';
}

let lan, lanSource;
if (has('--lan')) { lan = true; lanSource = 'flag'; }
else if (has('--local')) { lan = false; lanSource = 'flag'; }
else if (process.stdin.isTTY && process.stdout.isTTY) { lan = await askLan(); lanSource = 'you answered'; }
else { lan = false; lanSource = 'default - no terminal available to ask; pass --lan to be explicit'; }

/* -------------------------------------------------------------- write */
cfg = {
  ...cfg,
  // Not a deployment choice: the container's own listener has to bind every
  // interface or Docker's port forwarding has nothing to deliver traffic to,
  // regardless of whether the *host* side is published to the LAN below.
  host: '0.0.0.0',
  port,
  // Must match the Dockerfile's COPY destinations and docker-compose.yml's
  // volume mount, not the native install's paths.
  dataDir: '/app/server/data',
  uiDir: '/app/ui',
  enrollmentToken, analystToken,
  requireLogin: cfg.requireLogin ?? true,
};

fs.mkdirSync(DEPLOY_DIR, { recursive: true });
fs.writeFileSync(CFG_PATH, JSON.stringify(cfg, null, 2) + '\n');
say(`  config          ${c.g(existing ? 'updated' : 'created')} ${c.dim('deploy/config.json')}`);
if (rotate) say(c.y('  tokens          ROTATED - every enrolled agent must re-enroll'));

fs.writeFileSync(ENV_PATH,
  `AEGIS_BIND=${lan ? '0.0.0.0' : '127.0.0.1'}\nAEGIS_PORT=${port}\n`);
say(`  network         ${c.g(lan ? 'exposed to your LAN' : 'localhost only')} ${c.dim(`(${lanSource})`)}`);

// Docker auto-creates a missing bind-mount source on first run, usually
// root-owned on native Linux hosts - creating it ourselves first, owned by
// whoever is running this script, avoids a permission error on first start.
fs.mkdirSync(DATA_DIR, { recursive: true });

/* --------------------------------------------------------------- build */
say('');
say(c.b('  Building and starting the container'));
line();
const up = spawnSync(compose[0], [...compose.slice(1), 'up', '-d', '--build'],
  { cwd: DEPLOY_DIR, stdio: 'inherit' });
if (up.status !== 0) {
  say('');
  say(`  ${c.r('docker compose failed.')} ${c.dim('The output above is from Docker itself.')}`);
  say(`  ${c.dim('Common cause: another container or process already has port ' + port + '.')}`);
  process.exit(1);
}

/* ---------------------------------------------------------------- done */
const nics = lanIp();
const primary = nics.find(n => !n.virtual) || nics[0];
const reachAt = lan ? (primary ? primary.ip : '<this-machine-ip>') : '127.0.0.1';

say('');
say(c.b('  Ready.'));
line();
say(`  Open the console   ${c.cy(`http://127.0.0.1:${port}`)}  ${c.dim('(from this machine)')}`);
if (lan) {
  say(`  Agents report to   ${c.cy(`http://${reachAt}:${port}`)}`);
  if (primary) say(c.dim(`                     (via ${primary.name})`));
} else {
  say(c.dim('  This container only accepts connections from this machine.'));
  say(c.dim('  To let agents on other machines reach it: node docker-setup.mjs --lan'));
}
say('');
say('  Analyst token   ' + c.b(analystToken));
say('  Enrollment      ' + c.b(enrollmentToken));
say(c.dim('  (also stored in deploy/config.json, and shown again by `docker compose logs aegis`)'));

if (lan) {
  say('');
  say(c.b('  Let agents through the firewall (run on this machine)'));
  line();
  if (process.platform === 'win32') {
    say('  In an ' + c.b('admin') + ' PowerShell:');
    say(c.cy(`    New-NetFirewallRule -DisplayName "AEGIS ${port}" -Direction Inbound \``));
    say(c.cy(`      -Protocol TCP -LocalPort ${port} -Action Allow -Profile Domain,Private`));
  } else {
    const fw = firewallAdvice(port);
    if (!fw.tool) {
      say(`  ${c.g('No host firewall found')} ${c.dim('- nothing to open. Test from another machine:')}`);
      say(`    ${c.cy(`curl -s http://${reachAt}:${port}/api/health`)}`);
    } else {
      say(c.dim(`  Detected ${fw.tool}:`));
      fw.cmds.forEach(cmd => say(`    ${c.cy(cmd)}`));
      if (fw.volatile) say(c.dim('  Runtime-only - persist it the way your distribution expects.'));
    }
  }

  say('');
  say(c.b('  Deploy an agent'));
  line();
  say('  Windows endpoint, in an ' + c.b('admin') + ' PowerShell:');
  say(c.cy(`    .\\aegis-agent.ps1 -Server http://${reachAt}:${port} -EnrollmentToken ${enrollmentToken} -Install`));
  say('');
  say('  Linux/macOS endpoint, as root:');
  say(c.cy(`    sudo python3 agents/aegis-agent.py --server http://${reachAt}:${port} --token ${enrollmentToken} --once`));
}

say('');
say(c.y('  These tokens are secrets. The server has no TLS of its own - put a TLS'));
say(c.y('  reverse proxy in front before this crosses a network you do not trust.'));
say(c.dim('  (deploy/Caddyfile is a ready-made starting point.)'));
say('');
say(c.dim('  Manage it: docker compose logs -f aegis   |   docker compose down   |   git pull && node docker-setup.mjs'));
say('');

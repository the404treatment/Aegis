#!/usr/bin/env node
/**
 * Push the AEGIS agent to the hosts found by `discover.mjs`.
 *
 *   node discover.mjs --json targets.json     # 1. survey the network
 *   node deploy-agents.mjs --targets targets.json          # 2. see the plan
 *   node deploy-agents.mjs --targets targets.json --confirm # 3. do it
 *
 * Deliberate design decisions, because this pushes software onto machines:
 *
 *  - It does NOTHING without --confirm. The default run prints the plan.
 *  - It never handles your password. Windows deployment uses PowerShell
 *    remoting, which prompts for credentials itself; Linux uses your existing
 *    ssh setup. Nothing is read from a flag (flags leak into shell history and
 *    the process list) and nothing is stored.
 *  - It only touches hosts listed in the file you pass. Edit that file to
 *    control scope — the network scan suggests, you decide.
 *  - The agent it installs is read-only and takes no commands back from the
 *    server. It is a collector, not a management channel.
 *
 * Use this on machines you administer. Installing software on hosts you do not
 * own is not a grey area, whatever the tooling makes convenient.
 *
 * Zero dependencies.
 */
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const has = f => argv.includes(f);
const val = (f, d) => { const i = argv.indexOf(f); return i > -1 && argv[i + 1] ? argv[i + 1] : d; };

const COLOUR = process.stdout.isTTY && !process.env.NO_COLOR;
const w = code => s => (COLOUR ? `\x1b[${code}m${s}\x1b[0m` : String(s));
const c = { b: w(1), dim: w(2), g: w(32), y: w(33), cy: w(36), r: w(31) };

/* ------------------------------------------------------------- inputs */
const targetsFile = val('--targets', 'targets.json');
if (!fs.existsSync(targetsFile)) {
  console.error(`\n  No target file at ${targetsFile}.`);
  console.error('  Run the network check first:  node discover.mjs --json targets.json\n');
  process.exit(1);
}
let targets;
try { targets = JSON.parse(fs.readFileSync(targetsFile, 'utf8')).hosts || []; }
catch (e) { console.error(`\n  ${targetsFile} is not valid JSON: ${e.message}\n`); process.exit(1); }

let cfg;
try { cfg = JSON.parse(fs.readFileSync(path.join(ROOT, 'server', 'config.json'), 'utf8')); }
catch { console.error('\n  No server/config.json — run `npm run setup` first.\n'); process.exit(1); }

/** The address agents should report to — the same logic setup uses. */
function serverUrl() {
  const explicit = val('--server', null);
  if (explicit) return explicit.replace(/\/$/, '');
  if (cfg.host && cfg.host !== '0.0.0.0' && cfg.host !== '::') return `http://${cfg.host}:${cfg.port}`;
  for (const [name, addrs] of Object.entries(os.networkInterfaces())) {
    if (/vmware|virtualbox|hyper-v|vethernet|nord|wireguard|tailscale|zerotier|docker|wsl/i.test(name)) continue;
    for (const a of addrs || []) if (a.family === 'IPv4' && !a.internal) return `http://${a.address}:${cfg.port}`;
  }
  return `http://127.0.0.1:${cfg.port}`;
}
const SERVER = serverUrl();
const ENROLL = cfg.enrollmentToken;
// Install the agent under a dull name so an intruder on an endpoint scanning
// the task list for "AEGIS" finds nothing. Whatever you deploy with, you
// uninstall with — see docs/RUNBOOK.md section 7. Windows only; the ssh path
// runs the agent one-shot rather than installing a service.
const AGENT_NAME = (val('--agent-name', '') || '').replace(/[^A-Za-z0-9._-]/g, '');

const deployable = targets.filter(h => h.deploy === 'winrm' || h.deploy === 'ssh');
const manual = targets.filter(h => !h.deploy);

/* --------------------------------------------------------------- plan */
console.log('');
console.log(c.b('  AEGIS agent deployment'));
console.log(c.dim('  ' + '─'.repeat(64)));
console.log(`  target file     ${targetsFile}`);
console.log(`  agents report to  ${c.cy(SERVER)}`);
if (AGENT_NAME) console.log(`  install as      ${c.cy(AGENT_NAME)}  ${c.dim('(task + folder; uninstall with the same --agent-name)')}`);
console.log(`  hosts in file   ${targets.length}`);
console.log('');

if (!deployable.length) {
  console.log(c.y('  None of these hosts can take a push.'));
  console.log('  WinRM (5985) or SSH (22) needs to be reachable and you need admin on it.');
  console.log('  Install by hand or by GPO/Intune/Ansible instead — see INSTALL.md.\n');
  process.exit(0);
}

console.log(c.b('  Will deploy to:'));
for (const h of deployable) {
  console.log(`    ${h.ip.padEnd(16)} ${(h.name || '—').slice(0, 26).padEnd(27)} ${c.g(h.deploy)}`);
}
if (manual.length) {
  console.log('');
  console.log(c.dim(`  Skipping ${manual.length} host${manual.length === 1 ? '' : 's'} with no remote-admin port open:`));
  manual.forEach(h => console.log(c.dim(`    ${h.ip.padEnd(16)} ${(h.name || '—').slice(0, 26)}`)));
}

if (!has('--confirm')) {
  console.log('');
  console.log(c.y('  This was a dry run. Nothing has been changed.'));
  console.log('');
  console.log('  Read the list above. Remove anything from ' + targetsFile + ' that should');
  console.log('  not receive an agent, then run again with --confirm:');
  console.log(`    ${c.cy(`node deploy-agents.mjs --targets ${targetsFile} --confirm`)}`);
  console.log('');
  console.log(c.dim('  You will be prompted for credentials by Windows/ssh themselves.'));
  console.log(c.dim('  This tool never sees, stores or transmits your password.'));
  console.log('');
  process.exit(0);
}

/* ------------------------------------------------------------- deploy */
const win = deployable.filter(h => h.deploy === 'winrm');
const nix = deployable.filter(h => h.deploy === 'ssh');
const results = [];

if (win.length) {
  if (process.platform !== 'win32') {
    console.log(c.y(`\n  Skipping ${win.length} Windows host(s): PowerShell remoting needs to run from Windows.`));
  } else {
    console.log('');
    console.log(c.b(`  Deploying to ${win.length} Windows host${win.length === 1 ? '' : 's'} over WinRM`));
    console.log(c.dim('  Windows will prompt for the account to use. It needs local admin on the targets.'));
    const agent = path.join(ROOT, 'agents', 'aegis-agent.ps1');
    const hostList = win.map(h => h.ip).join(',');
    // The remote script is passed as a file and the credential is gathered by
    // Get-Credential in the operator's own session — it never reaches Node.
    const ps = `
$ErrorActionPreference = 'Continue'
$cred = Get-Credential -Message 'Account with local admin on the target machines'
$hosts = '${hostList}'.Split(',')
foreach ($h in $hosts) {
  Write-Host ""
  Write-Host "  -> $h" -ForegroundColor Cyan
  try {
    Invoke-Command -ComputerName $h -Credential $cred -ErrorAction Stop -FilePath '${agent.replace(/'/g, "''")}' \
      -ArgumentList '-Server','${SERVER}','-EnrollmentToken','${ENROLL}'${AGENT_NAME ? `,'-Name','${AGENT_NAME}'` : ''},'-Install'
    Write-Host "     installed" -ForegroundColor Green
  } catch {
    Write-Host "     FAILED: $($_.Exception.Message)" -ForegroundColor Red
  }
}`;
    const r = spawnSync('powershell', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', ps], { stdio: 'inherit' });
    results.push({ kind: 'windows', code: r.status });
  }
}

if (nix.length) {
  console.log('');
  console.log(c.b(`  Deploying to ${nix.length} Linux/macOS host${nix.length === 1 ? '' : 's'} over SSH`));
  console.log(c.dim('  Uses your existing ssh configuration and keys.'));
  const user = val('--ssh-user', os.userInfo().username);
  const agent = path.join(ROOT, 'agents', 'aegis-agent.py');
  for (const h of nix) {
    console.log('');
    console.log(c.cy(`  -> ${h.ip}`));
    try {
      execFileSync('scp', ['-o', 'StrictHostKeyChecking=accept-new', agent, `${user}@${h.ip}:/tmp/aegis-agent.py`], { stdio: 'inherit' });
      execFileSync('ssh', ['-o', 'StrictHostKeyChecking=accept-new', `${user}@${h.ip}`,
        `sudo python3 /tmp/aegis-agent.py --server ${SERVER} --token ${ENROLL} --once`], { stdio: 'inherit' });
      console.log(c.g('     installed'));
      results.push({ kind: 'ssh', host: h.ip, ok: true });
    } catch (e) {
      console.log(c.r('     FAILED: ' + e.message.split('\n')[0]));
      results.push({ kind: 'ssh', host: h.ip, ok: false });
    }
  }
}

console.log('');
console.log(c.b('  Done.'));
console.log(`  Check the console at ${c.cy(SERVER)} — enrolled hosts appear on the Network Map.`);
console.log(c.dim('  Anything that failed can be installed by hand; see INSTALL.md.'));
console.log('');

#!/usr/bin/env node
/**
 * Change AEGIS's service identity.
 *
 *   node harden.mjs --show                     # what am I running as?
 *   node harden.mjs --name svc-telemetry       # rename the service
 *   node harden.mjs --name svc-telemetry --port 9443 --rotate
 *   node harden.mjs --revert                   # back to the defaults
 *
 * Why this exists
 * ---------------
 * AEGIS holds the incident record: every ticket, every case, the evidence, and
 * the audit chain the formal report is signed against. An attacker who works
 * out that the SOC runs AEGIS knows the service name, the port, the install
 * path and the endpoint layout, because they are all published in this repo.
 * That is a reasonable thing to fix on a real deployment.
 *
 * This is **not** security through obscurity as a substitute for controls. It
 * is a delaying tactic layered on top of them, and it buys one specific thing:
 * an attacker probing for `aegis.service` on 8787 and finding nothing has to
 * make more noise to find it — and noise is what you are watching for. See
 * docs/DEFENDING-AEGIS.md for the detections that turn that noise into an
 * alert.
 *
 * What it changes: the service/task name, the listening port, and optionally
 * the tokens. What it does not change: the code, the data, or your accounts.
 *
 * Zero dependencies.
 */
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const CFG_PATH = path.join(ROOT, 'server', 'config.json');
const STATE_PATH = path.join(ROOT, 'server', 'service.json');

const argv = process.argv.slice(2);
const has = f => argv.includes(f);
const val = (f, d) => { const i = argv.indexOf(f); return i > -1 && argv[i + 1] ? argv[i + 1] : d; };

const C = process.stdout.isTTY && !process.env.NO_COLOR;
const w = k => s => (C ? `\x1b[${k}m${s}\x1b[0m` : String(s));
const c = { b: w(1), d: w(2), g: w(32), y: w(33), r: w(31), cy: w(36) };
const say = (...a) => console.log(...a);
const die = m => { say(''); say(`  ${c.r('ERROR')}  ${m}`); say(''); process.exit(1); };

const DEFAULTS = { name: 'aegis', port: 8787, display: 'AEGIS Server' };

const readJson = (f, d) => { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return d; } };
const state = () => ({ ...DEFAULTS, ...readJson(STATE_PATH, {}) });

/* A service name has to be safe in a systemd unit filename, a launchd label
   and a Windows task name all at once. Anything outside this set is a foot-gun
   in at least one of them. */
const NAME_RE = /^[a-z0-9][a-z0-9._-]{1,38}$/i;

/* ----------------------------------------------------------------- show */
function show() {
  const s = state();
  const cfg = readJson(CFG_PATH, {});
  say('');
  say(`  ${c.b('AEGIS service identity')}`);
  say(`  ${c.d('-'.repeat(62))}`);
  say(`  service name    ${c.cy(s.name)}${s.name === DEFAULTS.name ? c.d('   (the published default)') : c.g('   (changed)')}`);
  say(`  display name    ${s.display}`);
  say(`  port            ${c.cy(String(cfg.port || s.port))}${(cfg.port || s.port) === DEFAULTS.port ? c.d('   (the published default)') : c.g('   (changed)')}`);
  say(`  install path    ${ROOT}`);
  say('');
  if (s.name === DEFAULTS.name && (cfg.port || s.port) === DEFAULTS.port) {
    say(`  ${c.y('This deployment is discoverable by anyone who has read the AEGIS repo.')}`);
    say(`  ${c.d('That is fine on a lab. On a network with an adversary on it, consider:')}`);
    say('');
    say(`     ${c.cy('node harden.mjs --name svc-telemetry --port 9443 --rotate')}`);
    say('');
    say(`  ${c.d('Then read docs/DEFENDING-AEGIS.md for what to alert on.')}`);
  } else {
    say(`  ${c.g('This deployment does not match the published defaults.')}`);
    say(`  ${c.d('Revert with:')}  ${c.cy('node harden.mjs --revert')}`);
  }
  say('');
}

if (has('--show') || !argv.length) { show(); process.exit(0); }

/* --------------------------------------------------------------- inputs */
const revert = has('--revert');
const newName = revert ? DEFAULTS.name : val('--name', '');
const newPort = revert ? DEFAULTS.port : Number(val('--port', 0));
const newDisplay = revert ? DEFAULTS.display : val('--display', newName ? `${newName} service` : '');

if (!revert && !newName && !newPort && !has('--rotate')) {
  die('nothing to do. Pass --name, --port, --rotate, --revert or --show.');
}
if (newName && !NAME_RE.test(newName)) {
  die(`"${newName}" will not work as a service name.\n         Use letters, digits, dot, dash or underscore; 2-39 characters.`);
}
if (newPort && (!Number.isInteger(newPort) || newPort < 1 || newPort > 65535)) {
  die(`"${val('--port', '')}" is not a valid port.`);
}
// Ports under 1024 need root on Unix, which is exactly what the installer
// avoided. Refusing here beats a service that silently fails to start.
if (newPort && newPort < 1024 && process.platform !== 'win32') {
  die(`port ${newPort} is privileged and would need root.\n         AEGIS runs as your user by design — pick a port above 1024.`);
}

const prev = state();
const cfg = readJson(CFG_PATH, null);
if (!cfg) die('no server/config.json — run `npm run setup` first.');

const name = newName || prev.name;
const port = newPort || cfg.port || prev.port;
const display = newDisplay || prev.display;

say('');
say(`  ${c.b('Changing the AEGIS service identity')}`);
say(`  ${c.d('-'.repeat(62))}`);
say(`  name    ${prev.name}  ${c.d('->')}  ${c.cy(name)}`);
say(`  port    ${cfg.port || prev.port}  ${c.d('->')}  ${c.cy(String(port))}`);

/* ------------------------------------------------------------- rotate */
if (has('--rotate')) {
  cfg.enrollmentToken = crypto.randomBytes(24).toString('base64url');
  cfg.analystToken = crypto.randomBytes(24).toString('base64url');
  say(`  tokens  ${c.y('ROTATED')} ${c.d('— every enrolled agent must re-enrol, every console must sign in again')}`);
}

/* -------------------------------------------------------------- write */
cfg.port = port;
fs.writeFileSync(CFG_PATH, JSON.stringify(cfg, null, 2) + '\n');
fs.writeFileSync(STATE_PATH, JSON.stringify({ name, port, display, changedAt: new Date().toISOString() }, null, 2) + '\n');

/* ------------------------------------------------------------ service */
say('');
say(`  ${c.b('Re-registering the service')}`);
const node = process.execPath;
const args = [path.join(ROOT, 'server', 'aegis-server.mjs'), '--config', path.join(ROOT, 'server', 'config.json')];
let done = false;

function sh(cmd, a, opts = {}) { try { return execFileSync(cmd, a, { stdio: 'pipe', ...opts }); } catch { return null; } }

if (process.platform === 'win32') {
  // Remove the old task before creating the new one, or a rename leaves two.
  sh('powershell', ['-NoProfile', '-Command',
    `Get-ScheduledTask -TaskName '${prev.display}' -EA SilentlyContinue | Unregister-ScheduledTask -Confirm:$false -EA SilentlyContinue`]);
  const ps = `
$a = New-ScheduledTaskAction -Execute '${node}' -Argument '"${args[0]}" --config "${args[2]}"' -WorkingDirectory '${ROOT}'
$t = New-ScheduledTaskTrigger -AtLogOn
$s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
$s.DisallowStartIfOnBatteries = $false
Register-ScheduledTask -TaskName '${display}' -Action $a -Trigger $t -Settings $s -Description '${display}' | Out-Null
Start-ScheduledTask -TaskName '${display}'`;
  const r = spawnSync('powershell', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', ps], { stdio: 'pipe' });
  if (r.status === 0) { say(`  ${c.g('registered')}  Scheduled Task "${display}"`); done = true; }
  else say(`  ${c.y('could not re-register the Scheduled Task')} ${c.d('- do it by hand, or re-run install.ps1')}`);
} else if (process.platform === 'darwin') {
  const dir = path.join(os.homedir(), 'Library', 'LaunchAgents');
  const oldPlist = path.join(dir, `com.${prev.name}.server.plist`);
  const newPlist = path.join(dir, `com.${name}.server.plist`);
  sh('launchctl', ['unload', oldPlist]);
  if (oldPlist !== newPlist) fs.rmSync(oldPlist, { force: true });
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(newPlist, `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.${name}.server</string>
  <key>ProgramArguments</key><array>
    <string>${node}</string><string>${args[0]}</string><string>--config</string><string>${args[2]}</string>
  </array>
  <key>WorkingDirectory</key><string>${ROOT}</string>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>${path.join(ROOT, name + '.log')}</string>
  <key>StandardErrorPath</key><string>${path.join(ROOT, name + '.log')}</string>
</dict></plist>\n`);
  if (sh('launchctl', ['load', newPlist]) !== null) { say(`  ${c.g('registered')}  launchd agent com.${name}.server`); done = true; }
  else say(`  ${c.y('wrote the plist but could not load it')} ${c.d('- launchctl load ' + newPlist)}`);
} else {
  const dir = path.join(os.homedir(), '.config', 'systemd', 'user');
  const oldUnit = path.join(dir, `${prev.name}.service`);
  const newUnit = path.join(dir, `${name}.service`);
  sh('systemctl', ['--user', 'disable', '--now', `${prev.name}.service`]);
  if (oldUnit !== newUnit) fs.rmSync(oldUnit, { force: true });
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(newUnit, `[Unit]
Description=${display}
After=network.target

[Service]
Type=simple
WorkingDirectory=${ROOT}
ExecStart=${node} ${args[0]} --config ${args[2]}
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
`);
  sh('systemctl', ['--user', 'daemon-reload']);
  if (sh('systemctl', ['--user', 'enable', '--now', `${name}.service`]) !== null) {
    say(`  ${c.g('registered')}  systemd user unit ${name}.service`); done = true;
  } else say(`  ${c.y('wrote the unit but could not enable it')} ${c.d(`- systemctl --user enable --now ${name}.service`)}`);
}

/* --------------------------------------------------------------- after */
say('');
say(`  ${c.g('Done.')}`);
say('');
if (newPort) {
  say(`  ${c.b('The port changed. Two things need doing:')}`);
  say('');
  say(`  1. Open the new port, close the old one:`);
  if (process.platform === 'win32') {
    say(`     ${c.cy(`New-NetFirewallRule -DisplayName "${display}" -Direction Inbound -Protocol TCP -LocalPort ${port} -Action Allow -Profile Domain,Private`)}`);
    say(`     ${c.cy(`Remove-NetFirewallRule -DisplayName "AEGIS ${prev.port}" -EA SilentlyContinue`)}`);
  } else {
    say(`     ${c.cy(`sudo ufw allow ${port}/tcp && sudo ufw delete allow ${prev.port}/tcp`)}`);
  }
  say('');
  say(`  2. Re-point your agents. They hold the old address and will fail quietly:`);
  say(`     ${c.d('re-run the agent installer with the new -Server / --server value.')}`);
  say('');
}
if (has('--rotate')) {
  say(`  ${c.b('Tokens were rotated:')}`);
  say(`     analyst     ${c.cy(cfg.analystToken)}`);
  say(`     enrollment  ${c.cy(cfg.enrollmentToken)}`);
  say(`     ${c.d('Every agent must re-enrol. Named accounts are unaffected — people sign in as themselves.')}`);
  say('');
}
if (newName) {
  say(`  ${c.b('The process name follows on restart.')}`);
  say(`     ${c.d(`It will report as "${name}" in ps / top / Task Manager instead of naming AEGIS.`)}`);
  say(`     ${c.d('Restart the service to pick it up, then confirm:')}`);
  say(`     ${c.cy(process.platform === 'win32'
    ? `Get-CimInstance Win32_Process -Filter "Name='node.exe'" | Select ProcessId,CommandLine`
    : `ps -eo pid,comm,args | grep -i ${name}`)}`);
  say('');
}
say(`  ${c.d('Make the change detectable, and see what else to hide:')}  ${c.cy('docs/RUNBOOK.md §7, docs/DEFENDING-AEGIS.md')}`);
say(`  ${c.d('Anything probing the old name or port is, by definition, not you.')}`);
say('');
if (!done) process.exitCode = 2;

#!/usr/bin/env node
/**
 * Build a self-contained AEGIS bundle for a network with no internet.
 *
 *   node bundle-airgap.mjs                    # for this machine's platform
 *   node bundle-airgap.mjs --target linux-x64
 *   node bundle-airgap.mjs --target win-x64
 *   node bundle-airgap.mjs --no-node          # skip the runtime; smaller
 *
 * Produces dist/aegis-airgap-<target>.tar.gz containing AEGIS, a pinned Node
 * runtime, and a run script. Copy it across on whatever media your enclave
 * allows, extract, run. Nothing is downloaded at run time.
 *
 * The Node download is verified against the SHASUMS256.txt published beside
 * it on nodejs.org. That file is fetched over TLS from the same origin, so
 * this is an integrity check against a corrupted or truncated download - not
 * a defence against nodejs.org itself. Verify out-of-band if your threat
 * model needs more; the checksum is printed so you can.
 *
 * Zero dependencies.
 */
import fs from 'node:fs';
import path from 'node:path';
import https from 'node:https';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const has = f => argv.includes(f);
const val = (f, d) => { const i = argv.indexOf(f); return i > -1 && argv[i + 1] ? argv[i + 1] : d; };

const C = process.stdout.isTTY && !process.env.NO_COLOR;
const w = c => s => (C ? `\x1b[${c}m${s}\x1b[0m` : String(s));
const c = { b: w(1), d: w(2), g: w(32), y: w(33), r: w(31), cy: w(36) };

const NODE_VERSION = val('--node-version', process.versions.node);
const WITH_NODE = !has('--no-node');

function defaultTarget() {
  const p = process.platform, a = process.arch;
  const os = p === 'win32' ? 'win' : p === 'darwin' ? 'darwin' : 'linux';
  const arch = a === 'arm64' ? 'arm64' : a === 'x64' ? 'x64' : a;
  return `${os}-${arch}`;
}
const TARGET = val('--target', defaultTarget());
const IS_WIN = TARGET.startsWith('win');
const EXT = IS_WIN ? 'zip' : 'tar.gz';

/* ------------------------------------------------------------------ util */
const get = url => new Promise((resolve, reject) => {
  https.get(url, { headers: { 'user-agent': 'aegis-bundler' } }, res => {
    if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
      res.resume(); return resolve(get(res.headers.location));
    }
    if (res.statusCode !== 200) { res.resume(); return reject(new Error(`HTTP ${res.statusCode} for ${url}`)); }
    const chunks = [];
    res.on('data', d => chunks.push(d));
    res.on('end', () => resolve(Buffer.concat(chunks)));
  }).on('error', reject);
});

const sha256 = buf => crypto.createHash('sha256').update(buf).digest('hex');
const say = (...a) => console.log(...a);

/* Run a command, surfacing its failure rather than swallowing it. */
function run(cmd, args, opts = {}) {
  try { return execFileSync(cmd, args, { stdio: 'pipe', ...opts }); }
  catch (e) { throw new Error(`${cmd} failed: ${(e.stderr || e.message || '').toString().trim().split('\n')[0]}`); }
}

/* --------------------------------------------------------------- build */
say('');
say(c.b('  AEGIS air-gap bundle'));
say(c.d('  ' + '-'.repeat(62)));
say(`  target          ${c.cy(TARGET)}`);
say(`  node runtime    ${WITH_NODE ? c.cy('v' + NODE_VERSION) : c.y('not included (--no-node)')}`);

const DIST = path.join(ROOT, 'dist');
const STAGE = path.join(DIST, `aegis-airgap-${TARGET}`);
fs.rmSync(STAGE, { recursive: true, force: true });
fs.mkdirSync(STAGE, { recursive: true });

/* 1. build the console so the bundle needs no build step on the far side */
say('');
say(c.b('  building the console'));
run(process.execPath, [path.join(ROOT, 'build.mjs')], { cwd: ROOT });
say(c.g('    ui/index.html built'));

/* 2. copy AEGIS itself, excluding anything local, generated or secret */
const SKIP = new Set(['node_modules', '.git', 'dist', 'data', 'assets', '.github']);
const SKIP_FILE = new Set(['config.json', 'targets.json', 'aegis-v3.html', '.DS_Store']);
let copied = 0;
function copyTree(src, dst) {
  for (const e of fs.readdirSync(src, { withFileTypes: true })) {
    if (SKIP.has(e.name) || SKIP_FILE.has(e.name)) continue;
    if (e.name.endsWith('.log') || e.name.endsWith('.tmp')) continue;
    const s = path.join(src, e.name), d = path.join(dst, e.name);
    if (e.isDirectory()) { fs.mkdirSync(d, { recursive: true }); copyTree(s, d); }
    else { fs.copyFileSync(s, d); copied++; }
  }
}
const APP = path.join(STAGE, 'aegis');
fs.mkdirSync(APP, { recursive: true });
copyTree(ROOT, APP);
say(c.g(`    ${copied} files staged`));

/* 3. the Node runtime, checksum-verified */
if (WITH_NODE) {
  say('');
  say(c.b('  fetching the Node runtime'));
  const name = `node-v${NODE_VERSION}-${TARGET}`;
  const file = `${name}.${EXT}`;
  const base = `https://nodejs.org/dist/v${NODE_VERSION}`;

  say(c.d(`    ${base}/${file}`));
  const bin = await get(`${base}/${file}`);
  const sums = (await get(`${base}/SHASUMS256.txt`)).toString('utf8');

  const line = sums.split('\n').find(l => l.trim().endsWith(' ' + file) || l.trim().endsWith('  ' + file));
  if (!line) throw new Error(`${file} is not listed in SHASUMS256.txt - is ${TARGET} a real Node target?`);
  const expected = line.trim().split(/\s+/)[0];
  const actual = sha256(bin);
  if (actual !== expected) {
    throw new Error(`checksum mismatch for ${file}\n    expected ${expected}\n    got      ${actual}\n    Refusing to bundle it.`);
  }
  say(c.g(`    sha256 verified  ${expected.slice(0, 16)}…`));

  const archive = path.join(STAGE, file);
  fs.writeFileSync(archive, bin);

  // Unpack so the far side needs no tooling beyond what extracted the bundle.
  say(c.d('    unpacking'));
  if (IS_WIN) {
    // tar ships with Windows 10+ and handles zip.
    run('tar', ['-xf', archive, '-C', STAGE]);
  } else {
    run('tar', ['-xzf', archive, '-C', STAGE]);
  }
  fs.rmSync(archive, { force: true });
  fs.renameSync(path.join(STAGE, name), path.join(STAGE, 'node'));
  fs.writeFileSync(path.join(STAGE, 'NODE-SHA256.txt'),
    `${expected}  ${file}\nVerified at bundle time against ${base}/SHASUMS256.txt\n`);
  say(c.g('    node/ ready'));
}

/* 4. run scripts */
const NODE_BIN = WITH_NODE ? (IS_WIN ? '"%~dp0node\\node.exe"' : '"$DIR/node/bin/node"') : (IS_WIN ? 'node' : 'node');

if (IS_WIN) {
  fs.writeFileSync(path.join(STAGE, 'run.cmd'), [
    '@echo off',
    'REM AEGIS air-gapped launcher. Nothing here reaches the network.',
    'setlocal',
    'cd /d "%~dp0aegis"',
    `set "AEGIS_NODE=${NODE_BIN}"`,
    'if not exist "server\\config.json" (',
    '  echo   First run: generating tokens and configuring...',
    `  ${NODE_BIN} setup.mjs`,
    ')',
    'echo.',
    'echo   Starting AEGIS. Close this window to stop it.',
    'echo.',
    `${NODE_BIN} server\\aegis-server.mjs --config server\\config.json`,
    'pause',
  ].join('\r\n') + '\r\n');
} else {
  fs.writeFileSync(path.join(STAGE, 'run.sh'), `#!/usr/bin/env sh
# AEGIS air-gapped launcher. Nothing here reaches the network.
set -eu
DIR=$(cd "$(dirname "$0")" && pwd)
NODE=${WITH_NODE ? '"$DIR/node/bin/node"' : 'node'}
command -v "$NODE" >/dev/null 2>&1 || [ -x "$NODE" ] || { echo "node not found"; exit 1; }
cd "$DIR/aegis"
if [ ! -f server/config.json ]; then
  echo "  First run: generating tokens and configuring..."
  "$NODE" setup.mjs
fi
echo ""
echo "  Starting AEGIS. Ctrl-C to stop."
echo ""
exec "$NODE" server/aegis-server.mjs --config server/config.json
`, { mode: 0o755 });
}

fs.writeFileSync(path.join(STAGE, 'README.txt'), `AEGIS - air-gapped bundle
=========================

Built for : ${TARGET}
Node      : ${WITH_NODE ? 'v' + NODE_VERSION + ' (included, sha256 in NODE-SHA256.txt)' : 'NOT included - install Node 18+ yourself'}
Built at  : ${new Date().toISOString()}

This bundle is entirely self-contained. It does not download anything, phone
home, check a licence, or contact a CDN. You can run it on a network with no
route to the internet and it behaves identically.

To start
--------
  ${IS_WIN ? 'Double-click run.cmd' : './run.sh'}

First run generates your tokens, builds nothing (the console is prebuilt),
and starts the server. It prints the address your agents should report to.

The console will ask you to create the first account. That account is the
lead and can add everyone else. Every action is recorded against the person
who took it, in a hash-chained audit log.

To add endpoints
----------------
Copy the agent from aegis/agents/ to each machine:

  Windows      aegis-agent.ps1   (admin PowerShell, -Install to run on a schedule)
  Linux/macOS  aegis-agent.py    (needs root to read the logs)

Both are single files with no dependencies beyond PowerShell 5.1 / Python 3.8.
Point them at the address the server printed, with the enrollment token from
aegis/server/config.json.

The agents are read-only. They report; they take no commands back. There is
no remote-exec channel, by design.

Firewall
--------
Some systems block the port until you allow it; many Linux images run no host
firewall at all, in which case there is nothing to do. Check first with
  command -v ufw firewall-cmd nft iptables

  Windows     New-NetFirewallRule -DisplayName "AEGIS 8787" -Direction Inbound \`
                -Protocol TCP -LocalPort 8787 -Action Allow -Profile Domain,Private
  ufw         sudo ufw allow 8787/tcp
  firewalld   sudo firewall-cmd --add-port=8787/tcp --permanent && sudo firewall-cmd --reload
  nftables    sudo nft add rule inet filter input tcp dport 8787 accept
  iptables    sudo iptables -I INPUT -p tcp --dport 8787 -j ACCEPT
  none found  nothing to open - test with curl before changing anything

Full documentation is in aegis/INSTALL.md.
`);

/* 5. tarball */
say('');
say(c.b('  packing'));
const out = path.join(DIST, `aegis-airgap-${TARGET}.tar.gz`);
fs.rmSync(out, { force: true });
run('tar', ['-czf', out, '-C', DIST, path.basename(STAGE)]);
fs.rmSync(STAGE, { recursive: true, force: true });

const size = fs.statSync(out).size;
const digest = sha256(fs.readFileSync(out));
fs.writeFileSync(out + '.sha256', `${digest}  ${path.basename(out)}\n`);

say('');
say(c.g('  Bundle ready.'));
say('');
say(`    ${c.cy(path.relative(ROOT, out))}   ${(size / 1048576).toFixed(1)} MB`);
say(`    ${c.d('sha256')}  ${digest}`);
say('');
say(c.d('  Copy it across, extract, and run the launcher inside.'));
say(c.d(`  Verify after transfer:  shasum -a 256 -c ${path.basename(out)}.sha256`));
say('');

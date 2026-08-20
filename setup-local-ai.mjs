#!/usr/bin/env node
/**
 * Set up the local AI companion.
 *
 *   npm run ai:setup              # detect what's running, pull a model, wire it up
 *   npm run ai:setup -- --model hf.co/bartowski/Qwen2.5-7B-Instruct-GGUF:Q4_K_M
 *   npm run ai:setup -- --check   # just report, change nothing
 *
 * What this does and does not do:
 *
 *   - It does NOT install an inference runtime. Downloading and running someone
 *     else's installer from a script is the supply-chain problem AEGIS exists
 *     to help you detect; it prints the command and lets you run it.
 *   - It DOES find a runtime you already have, pull a suitable model from
 *     Hugging Face through it, write the config, and verify the whole path with
 *     a real question.
 *
 * Everything stays on this machine. No key, no account, no telemetry.
 *
 * Zero dependencies.
 */
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawn, execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { detect, resolveProvider, complete, COMPANION_SYSTEM, httpJson, PROBE_TARGETS } from './server/llm.mjs';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const CFG_PATH = path.join(ROOT, 'server', 'config.json');
const argv = process.argv.slice(2);
const has = f => argv.includes(f);
const val = (f, d) => { const i = argv.indexOf(f); return i > -1 && argv[i + 1] ? argv[i + 1] : d; };

const C = process.stdout.isTTY && !process.env.NO_COLOR;
const w = k => s => (C ? `\x1b[${k}m${s}\x1b[0m` : String(s));
const c = { b: w(1), d: w(2), g: w(32), y: w(33), r: w(31), cy: w(36) };
const say = (...a) => console.log(...a);

/**
 * The default model.
 *
 * Chosen for the job rather than for benchmark scores: the companion writes two
 * or three sentences about a burst of telemetry, many times an hour, on
 * whatever hardware the SOC happens to have. A 3B at Q4 runs on a laptop with
 * no GPU, answers in a couple of seconds, and is entirely good enough to say
 * "this is a Kerberoasting pattern, check 4769 for RC4 requests". A 70B would
 * be better at it and would also make the feature unusable on the machines
 * most people will run this on.
 *
 * Override with --model. Anything Ollama can pull works, including any GGUF on
 * Hugging Face via the hf.co/ prefix.
 */
const DEFAULT_MODEL = 'hf.co/bartowski/Llama-3.2-3B-Instruct-GGUF:Q4_K_M';
const BIGGER_MODEL  = 'hf.co/bartowski/Qwen2.5-7B-Instruct-GGUF:Q4_K_M';

const INSTALL_HINT = {
  win32:  'winget install Ollama.Ollama     (or download from https://ollama.com/download)',
  darwin: 'brew install ollama              (or download from https://ollama.com/download)',
  linux:  'curl -fsSL https://ollama.com/install.sh | sh',
};

say('');
say(`  ${c.b('AEGIS local AI companion')}`);
say(`  ${c.d('-'.repeat(62))}`);
say(`  ${c.d('A model on this machine. No API key, no internet, nothing leaves the host.')}`);
say('');

/* ------------------------------------------------------------- 1. detect */
say(`  ${c.b('1. Looking for a local model server')}`);
let found = await detect();

if (!found.length) {
  const hint = INSTALL_HINT[process.platform] || INSTALL_HINT.linux;
  say(`     ${c.y('none running.')}`);
  say('');
  say(`  ${c.b('Install one - Ollama is the easiest:')}`);
  say('');
  say(`     ${c.cy(hint)}`);
  say('');
  say(`  ${c.d('Then run this again:')}  ${c.cy('npm run ai:setup')}`);
  say('');
  say(`  ${c.d('Already have LM Studio, llama.cpp, Jan or vLLM? Start it and re-run -')}`);
  say(`  ${c.d('AEGIS speaks to all of them. Ports probed:')}`);
  for (const t of PROBE_TARGETS) say(`  ${c.d(`     ${t.name.padEnd(12)} ${t.base}`)}`);
  say('');
  say(`  ${c.d('This is optional. AEGIS works fully without it.')}`);
  say('');
  process.exit(has('--check') ? 0 : 1);
}

for (const f of found) {
  say(`     ${c.g('found')}  ${f.name.padEnd(11)} ${c.d(f.base)}  ${f.models.length} model${f.models.length === 1 ? '' : 's'}`);
}
const provider = found[0];

/* -------------------------------------------------------------- 2. model */
say('');
say(`  ${c.b('2. Model')}`);

let model = val('--model', '');
const wantBig = has('--bigger');
if (!model) {
  if (provider.models.length) {
    // Prefer something already pulled - re-downloading 2GB because a flag
    // wasn't passed would be rude.
    model = provider.models[0];
    say(`     using   ${c.cy(model)}  ${c.d('(already available)')}`);
  } else {
    model = wantBig ? BIGGER_MODEL : DEFAULT_MODEL;
  }
}

const havePulled = provider.models.includes(model);
if (!havePulled && provider.kind === 'ollama' && !has('--check')) {
  say(`     pulling ${c.cy(model)}`);
  say(`     ${c.d('from Hugging Face, via Ollama. First run downloads ~2GB.')}`);
  say('');
  const ok = await pullOllama(model);
  if (!ok) {
    say('');
    say(`  ${c.r('The pull failed.')} Check the model name and your connection, or pull manually:`);
    say(`     ${c.cy(`ollama pull ${model}`)}`);
    say('');
    process.exit(1);
  }
  say('');
  say(`     ${c.g('pulled')}  ${model}`);
} else if (!havePulled && !has('--check')) {
  say(`     ${c.y('note')}    ${provider.name} has no model named ${model}.`);
  say(`     ${c.d('Load one in its own interface, then re-run this.')}`);
}

/* -------------------------------------------------------------- 3. config */
if (!has('--check')) {
  say('');
  say(`  ${c.b('3. Wiring it into AEGIS')}`);
  let cfg = {};
  try { cfg = JSON.parse(fs.readFileSync(CFG_PATH, 'utf8')); }
  catch { say(`     ${c.y('no server/config.json yet - run `npm run setup` first.')}`); process.exit(1); }

  cfg.llm = {
    ...(cfg.llm || {}),
    enabled: true,
    endpoint: provider.base,
    kind: provider.kind,
    name: provider.name,
    model,
    // Watch is the whole point: an assistant you have to prompt is one you use
    // only when you already know what to ask.
    watch: cfg.llm?.watch !== false,
    watchDebounceMs: cfg.llm?.watchDebounceMs ?? 4000,
  };
  fs.writeFileSync(CFG_PATH, JSON.stringify(cfg, null, 2) + '\n');
  say(`     ${c.g('written')} server/config.json`);
  say(`     ${c.d(`endpoint ${provider.base}`)}`);
  say(`     ${c.d(`model    ${model}`)}`);
  say(`     ${c.d(`watch    ${cfg.llm.watch ? 'on - it comments on telemetry unprompted' : 'off'}`)}`);
}

/* ------------------------------------------------------------- 4. verify */
say('');
say(`  ${c.b('4. Asking it a real question')}`);
const prov = { ...provider, model };
const started = Date.now();
const r = await complete(prov, {
  system: COMPANION_SYSTEM,
  messages: [{ role: 'user', content:
    'Windows Security 4625 failed logon, 40 times in 60 seconds, from one source IP against one account, '
    + 'then a single 4624 type 3 success for that account. Two sentences: what is this, and what next?' }],
  maxTokens: 200,
  timeoutMs: 180000,   // a first request loads the weights; be patient once
});
const secs = ((Date.now() - started) / 1000).toFixed(1);

if (!r.ok) {
  say(`     ${c.r('failed')}  ${r.error}`);
  say('');
  say(`  ${c.d('The model is configured but did not answer. Common causes: the model is')}`);
  say(`  ${c.d('still loading, or the machine is short on RAM. Try again in a minute.')}`);
  say('');
  process.exit(1);
}

say(`     ${c.g('answered')} in ${secs}s`);
say('');
for (const line of r.text.split('\n')) say(`     ${c.d('|')} ${line}`);
say('');
say(`  ${c.g('Local AI is ready.')}`);
say('');
say(`  ${c.d('Restart AEGIS to pick it up:')}  ${c.cy('npm start')}`);
say(`  ${c.d('In the console the companion appears in the top bar. It comments on')}`);
say(`  ${c.d('suspicious telemetry on its own, and you can ask it things directly.')}`);
say('');
say(`  ${c.d('Turn the unprompted part off:')} set ${c.cy('"llm": { "watch": false }')} in server/config.json`);
say('');

/* ------------------------------------------------------------------ util */
/** Stream `ollama pull` so a 2GB download shows progress instead of hanging. */
function pullOllama(name) {
  return new Promise(resolve => {
    let bin = 'ollama';
    try { execFileSync(process.platform === 'win32' ? 'where' : 'which', [bin], { stdio: 'ignore' }); }
    catch {
      // Ollama is running (we probed it) but its CLI is not on PATH - pull over
      // the HTTP API instead so this still works.
      return resolve(pullOverHttp(name));
    }
    const ps = spawn(bin, ['pull', name], { stdio: ['ignore', 'inherit', 'inherit'] });
    ps.on('error', () => resolve(pullOverHttp(name)));
    ps.on('close', code => resolve(code === 0));
  });
}

/** Fallback: Ollama's pull API, reporting progress as it streams. */
async function pullOverHttp(name) {
  say(`     ${c.d('(pulling over the API)')}`);
  try {
    const r = await httpJson(`${provider.base}/api/pull`, {
      method: 'POST', body: { name, stream: false }, timeoutMs: 3600e3,
    });
    return r.status === 200;
  } catch (e) { say(`     ${c.r(e.message)}`); return false; }
}

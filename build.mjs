#!/usr/bin/env node
/**
 * AEGIS build — concatenates src/ modules into the single-file ui/index.html.
 *
 * There is no bundler on purpose. The app is one global scope; modules are
 * plain script fragments joined in the order given by src/manifest.json.
 * That order is load-bearing: data before the code that reads it.
 *
 *   node build.mjs            # build
 *   node build.mjs --watch    # rebuild on change
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const SRC = path.join(ROOT, 'src');
const OUT = path.join(ROOT, 'ui', 'index.html');

function build() {
  const t0 = Date.now();
  const manifest = JSON.parse(fs.readFileSync(path.join(SRC, 'manifest.json'), 'utf8'));
  const shell = fs.readFileSync(path.join(SRC, 'shell.html'), 'utf8');
  const styles = fs.readFileSync(path.join(SRC, 'styles.css'), 'utf8');

  const missing = manifest.order.filter(f => !fs.existsSync(path.join(SRC, f)));
  if (missing.length) {
    console.error('[build] missing modules:\n  ' + missing.join('\n  '));
    process.exit(1);
  }

  const script = manifest.order
    .map(f => `/* ==== ${f} ==== */\n` + fs.readFileSync(path.join(SRC, f), 'utf8').trim())
    .join('\n\n');

  // Guard: the placeholders must exist or we would silently emit a broken file.
  for (const ph of ['/*{{STYLES}}*/', '/*{{SCRIPT}}*/']) {
    if (!shell.includes(ph)) { console.error(`[build] shell.html is missing ${ph}`); process.exit(1); }
  }

  const html = shell
    .replace('/*{{STYLES}}*/', () => styles)
    .replace('/*{{SCRIPT}}*/', () => script);

  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, html);

  // Fast structural checks — catches a truncated module immediately.
  const open = (html.match(/<div/g) || []).length;
  const close = (html.match(/<\/div>/g) || []).length;
  let syntax = 'OK';
  try { new Function(script); } catch (e) { syntax = 'FAIL: ' + e.message; }

  console.log(`[build] ${manifest.order.length} modules -> ui/index.html  ${(html.length / 1024).toFixed(0)}KB  ${Date.now() - t0}ms`);
  console.log(`[build] js ${syntax} | divs ${open}/${close} ${open === close ? 'balanced' : 'MISMATCH'}`);
  if (syntax !== 'OK' || open !== close) process.exit(1);
}

build();

if (process.argv.includes('--watch')) {
  console.log('[build] watching src/ ...');
  let timer = null;
  fs.watch(SRC, { recursive: true }, () => {
    clearTimeout(timer);
    timer = setTimeout(() => { try { build(); } catch (e) { console.error('[build]', e.message); } }, 120);
  });
}

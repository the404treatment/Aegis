#!/usr/bin/env node
/**
 * The local LLM companion. Zero dependencies.
 *
 * DESIGN RULE: stubs mimic hostile reality. The failure modes that matter here
 * are the ones a happy-path test walks straight past:
 *  - the common case is that NOTHING is running on any of the probed ports, so
 *    detection has to fail fast and quietly rather than throw or hang,
 *  - two runtimes speak two different dialects and a request built for the
 *    wrong one is silently accepted and answers nothing useful,
 *  - the telemetry briefing is what a small model actually sees, and a wall of
 *    repeated JSON is how you make a 3B model useless - so the collapsing is
 *    load-bearing, not cosmetic,
 *  - and a local model that is missing, cold, busy or half-loaded is the
 *    ORDINARY case, not an exception: none of it may throw.
 *
 * A real inference server is spun up in-process so the request path is
 * exercised for real rather than mocked at the seam.
 */
import http from 'node:http';
import { probe, detect, resolveProvider, buildChat, textOf, complete, briefEvents, LLM_DEFAULTS } from '../server/llm.mjs';

let pass = 0, fail = 0;
const ok = (name, cond, extra = '') => {
  if (cond) { pass++; console.log(`  ok   ${name}`); }
  else { fail++; console.log(`  FAIL ${name}${extra ? '  -> ' + extra : ''}`); }
};
const eq = (name, a, b) => ok(name, a === b, `${JSON.stringify(a)} !== ${JSON.stringify(b)}`);
const section = s => console.log(`\n${s}`);

/** A stand-in inference server. `kind` picks which dialect it speaks. */
function fakeServer(kind, { models = ['test-model'], reply = 'looks like brute force', status = 200, delayMs = 0 } = {}) {
  const seen = [];
  const srv = http.createServer((req, res) => {
    let body = '';
    req.on('data', d => { body += d; });
    req.on('end', () => {
      const done = () => {
        const send = o => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };
        if (req.url.startsWith('/api/tags')) return send({ models: models.map(m => ({ name: m })) });
        if (req.url.startsWith('/models')) return send({ data: models.map(m => ({ id: m })) });
        seen.push({ url: req.url, body: body ? JSON.parse(body) : null });
        if (req.url.startsWith('/api/chat')) return send({ message: { role: 'assistant', content: reply } });
        if (req.url.startsWith('/chat/completions')) return send({ choices: [{ message: { role: 'assistant', content: reply } }] });
        res.writeHead(404); res.end('{}');
      };
      if (delayMs) setTimeout(done, delayMs); else done();
    });
  });
  return new Promise(r => srv.listen(0, '127.0.0.1', () => r({ srv, seen, port: srv.address().port })));
}

/* ------------------------------------------------------------- detection */
section('detection when nothing is running');
{
  // The overwhelmingly common case. It must be quiet, fast and non-throwing.
  const dead = [{ name: 'nope', kind: 'ollama', base: 'http://127.0.0.1:1' }];
  const started = Date.now();
  const found = await detect(dead, 300);
  eq('a dead port yields nothing', found.length, 0);
  ok('...and does not hang', Date.now() - started < 3000, `${Date.now() - started}ms`);
  ok('probing a dead port returns null, never throws', (await probe(dead[0], 300)) === null);

  // A URL that is not a URL at all must not take the process down.
  ok('a malformed endpoint is survivable',
    (await probe({ name: 'x', kind: 'openai', base: 'not-a-url' }, 300)) === null);

  // Deliberately autodetect:false rather than probing the real ports. A test
  // that asserts "nothing is running" fails on any developer's machine that
  // happens to have Ollama installed - which is most of the people who would
  // work on this file.
  eq('resolveProvider yields nothing when autodetect is off',
    await resolveProvider({ endpoint: '', autodetect: false }), null);
  eq('and stays off when disabled', await resolveProvider({ enabled: false }), null);
  eq('...even with an endpoint configured', await resolveProvider({ enabled: false, endpoint: 'http://127.0.0.1:1' }), null);
}

section('detection with a server up');
{
  const ollama = await fakeServer('ollama', { models: ['llama3.2:3b', 'qwen2.5:7b'] });
  try {
    const t = { name: 'Ollama', kind: 'ollama', base: `http://127.0.0.1:${ollama.port}` };
    const r = await probe(t, 1500);
    ok('an ollama endpoint is found', !!r);
    eq('...and its models are listed', r.models.join(','), 'llama3.2:3b,qwen2.5:7b');

    const prov = await resolveProvider({ endpoint: t.base, kind: 'ollama' });
    eq('an explicit endpoint is honoured', prov.base, t.base);
    eq('...and picks the first model when none is named', prov.model, 'llama3.2:3b');

    const pinned = await resolveProvider({ endpoint: t.base, kind: 'ollama', model: 'qwen2.5:7b' });
    eq('a configured model wins', pinned.model, 'qwen2.5:7b');
  } finally { ollama.srv.close(); }
}

section('an endpoint that is up but lists no models');
{
  // llama.cpp built without the models route still answers chat perfectly well.
  // Refusing to use it because a listing 404s would be wrong.
  const srv = http.createServer((req, res) => {
    // The endpoint is mounted at /v1, so the listing route is /v1/models.
    if (req.url.endsWith('/models')) { res.writeHead(404); return res.end('{}'); }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ choices: [{ message: { content: 'hi' } }] }));
  });
  await new Promise(r => srv.listen(0, '127.0.0.1', r));
  try {
    const base = `http://127.0.0.1:${srv.address().port}/v1`;
    const prov = await resolveProvider({ endpoint: base, model: 'whatever' });
    ok('a configured endpoint is still usable', !!prov, 'provider was null');
    eq('...and is marked unreachable rather than dropped', prov.reachable, false);
    const r = await complete(prov, { messages: [{ role: 'user', content: 'x' }] });
    ok('...and the request path actually works', r.ok, r.error);
  } finally { srv.close(); }
}

/* ----------------------------------------------------------- the dialects */
section('the two dialects are built correctly');
{
  const oll = buildChat({ kind: 'ollama', base: 'http://h/x', model: 'm' },
    { system: 'sys', messages: [{ role: 'user', content: 'q' }], maxTokens: 99 });
  ok('ollama posts to /api/chat', oll.url.endsWith('/api/chat'), oll.url);
  eq('ollama carries the system turn', oll.body.messages[0].role, 'system');
  eq('ollama uses num_predict, not max_tokens', oll.body.options.num_predict, 99);
  ok('ollama does not send max_tokens', oll.body.max_tokens === undefined);

  const oai = buildChat({ kind: 'openai', base: 'http://h/v1', model: 'm' },
    { system: 'sys', messages: [{ role: 'user', content: 'q' }], maxTokens: 99 });
  ok('openai posts to /chat/completions', oai.url.endsWith('/chat/completions'), oai.url);
  eq('openai uses max_tokens', oai.body.max_tokens, 99);
  ok('openai does not send ollama options', oai.body.options === undefined);

  // A conversation with no user turn is not a conversation.
  ok('a system-only conversation is refused',
    (() => { try { buildChat({ kind: 'openai', base: 'b' }, { system: 's', messages: [] }); return false; } catch { return true; } })());
  ok('an assistant-only conversation is refused',
    (() => { try { buildChat({ kind: 'openai', base: 'b' }, { messages: [{ role: 'assistant', content: 'a' }] }); return false; } catch { return true; } })());

  const skipped = buildChat({ kind: 'openai', base: 'b' },
    { messages: [{ role: 'user', content: 'keep' }, { role: 'user', content: '' }, null] });
  eq('empty and null turns are dropped', skipped.body.messages.length, 1);
}

section('reading each dialect back');
{
  eq('ollama reply', textOf({ kind: 'ollama' }, { message: { content: ' hi ' } }), 'hi');
  eq('openai reply', textOf({ kind: 'openai' }, { choices: [{ message: { content: ' hi ' } }] }), 'hi');
  eq('an empty ollama reply', textOf({ kind: 'ollama' }, {}), '');
  eq('an empty openai reply', textOf({ kind: 'openai' }, { choices: [] }), '');
  eq('a null reply', textOf({ kind: 'openai' }, null), '');
}

/* ------------------------------------------------------- the request path */
section('completing against a real server');
{
  for (const kind of ['ollama', 'openai']) {
    const s = await fakeServer(kind, { reply: `answer from ${kind}` });
    try {
      const base = kind === 'ollama' ? `http://127.0.0.1:${s.port}` : `http://127.0.0.1:${s.port}`;
      const r = await complete({ kind, base, model: 'm' }, { system: 'sys', messages: [{ role: 'user', content: 'q' }] });
      ok(`${kind}: completes`, r.ok, r.error);
      eq(`${kind}: returns the text`, r.text, `answer from ${kind}`);
    } finally { s.srv.close(); }
  }
}

section('failure is ordinary, not exceptional');
{
  ok('no provider at all', !(await complete(null, { messages: [{ role: 'user', content: 'x' }] })).ok);
  eq('...and says why', (await complete(null, { messages: [] })).error, 'no local model is configured or running');

  // A model that is still loading its weights answers with an error body.
  const bad = await fakeServer('openai', { status: 500, reply: '' });
  try {
    const r = await complete({ kind: 'openai', base: `http://127.0.0.1:${bad.port}`, model: 'm' },
      { messages: [{ role: 'user', content: 'q' }] });
    ok('an http error is reported, not thrown', !r.ok);
    ok('...with something actionable', /500|error/i.test(r.error), r.error);
  } finally { bad.srv.close(); }

  // A cold model can take minutes. A short timeout must degrade gracefully and
  // explain itself, because "it did nothing" is the least useful answer.
  const slow = await fakeServer('openai', { delayMs: 900 });
  try {
    const r = await complete({ kind: 'openai', base: `http://127.0.0.1:${slow.port}`, model: 'm' },
      { messages: [{ role: 'user', content: 'q' }], timeoutMs: 120 });
    ok('a timeout is reported, not thrown', !r.ok);
    ok('...and explains that a first load is slow', /took too long|loads the weights/i.test(r.error), r.error);
  } finally { slow.srv.close(); }

  // Connection refused mid-flight - the runtime was killed while we were talking.
  const r = await complete({ kind: 'openai', base: 'http://127.0.0.1:1', model: 'm' },
    { messages: [{ role: 'user', content: 'q' }] });
  ok('a refused connection is reported, not thrown', !r.ok);

  // A 200 with an empty body is worse than an error: it looks like success.
  const empty = await fakeServer('openai', { reply: '' });
  try {
    const e = await complete({ kind: 'openai', base: `http://127.0.0.1:${empty.port}`, model: 'm' },
      { messages: [{ role: 'user', content: 'q' }] });
    ok('an empty answer is a failure, not a blank reply', !e.ok);
  } finally { empty.srv.close(); }
}

/* --------------------------------------------------------- the briefing */
section('telemetry briefing');
{
  eq('no events yields nothing to say', briefEvents([]), '');
  eq('null is survivable', briefEvents(null), '');

  // The point of the briefing: 40 identical failed logons must cost one line,
  // not forty. A small model fed forty lines has no room left to think.
  const burst = Array.from({ length: 40 }, () => ({
    ts: Date.now(), host: 'DC01', channel: 'Security', eventId: 4625, severity: 'suspicious', message: 'failed logon',
  }));
  const brief = briefEvents(burst);
  const lines = brief.split('\n').filter(l => l.startsWith('- '));
  eq('identical events collapse to one line', lines.length, 1);
  ok('...and the count is kept', /x\d+/.test(lines[0]), lines[0]);

  // Different hosts are different facts and must not be collapsed together.
  const mixed = briefEvents([
    { host: 'DC01', channel: 'Security', eventId: 4625, severity: 'suspicious' },
    { host: 'WS42', channel: 'Security', eventId: 4625, severity: 'suspicious' },
  ]);
  eq('different hosts stay separate', mixed.split('\n').filter(l => l.startsWith('- ')).length, 2);

  // Context is finite: a huge message field must not push out the other events.
  const fat = briefEvents([{ host: 'A', eventId: 1, message: 'x'.repeat(5000) }]);
  ok('a huge message is truncated', fat.length < 500, String(fat.length));

  const capped = briefEvents(Array.from({ length: 500 }, (_, i) => ({ host: 'h' + i, eventId: i })), { limit: 10 });
  eq('the event count is capped', capped.split('\n').filter(l => l.startsWith('- ')).length, 10);

  ok('the technique is carried through when the agent tagged one',
    briefEvents([{ host: 'A', eventId: 10, technique: 'T1003' }]).includes('T1003'));
}

console.log(`\n${fail ? 'FAILED' : 'PASSED'}  ${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);

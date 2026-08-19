/**
 * Local LLM companion.
 *
 * Every AI feature in AEGIS runs through here, and every one of them runs on
 * the AEGIS host. There is no path out to a hosted API and no key anywhere in
 * the codebase, deliberately: a SOC console that ships telemetry, hostnames and
 * case detail to a third party is a data-egress problem wearing a helpful hat,
 * and it makes the tool unusable on exactly the air-gapped networks it suits
 * best.
 *
 * Two surfaces share this one model. The AI Analyst tab answers long questions
 * you type, with your staged techniques and hunt map as context. The Companion
 * does short, continuous work — reading telemetry as it lands and saying
 * something useful without being asked.
 *
 * It talks to whatever local inference server is already running rather than
 * embedding one. That is deliberate:
 *
 *   - AEGIS has zero dependencies and must stay that way. Bundling llama.cpp
 *     or an ONNX runtime would end that, and would tie the project to one
 *     inference stack that ages badly.
 *   - The good local runtimes already speak HTTP, and all but Ollama speak the
 *     same OpenAI-shaped dialect, so supporting "any of them" is barely more
 *     code than supporting one.
 *   - Models come from Hugging Face either way. Ollama pulls GGUF straight
 *     from `hf.co/...`; llama.cpp, LM Studio and Jan all load HF GGUF files.
 *     The user picks the model; we do not ship one.
 *
 * Nothing here leaves the machine. That is the point.
 *
 * Zero dependencies.
 */
import http from 'node:http';
import https from 'node:https';

export const LLM_DEFAULTS = {
  enabled: true,        // honoured only when an endpoint is actually reachable
  endpoint: '',         // blank = probe the well-known local ports
  model: '',            // blank = use whatever the endpoint reports first
  autodetect: true,
  timeoutMs: 120000,
  maxTokens: 1200,      // companion output is short by design; see SYSTEM below
};

/**
 * Where local inference servers listen, in the order we try them.
 *
 * `kind` matters: Ollama has its own chat API, everything else here speaks the
 * OpenAI shape. Both are handled below.
 */
export const PROBE_TARGETS = [
  { name: 'Ollama',    kind: 'ollama', base: 'http://127.0.0.1:11434' },
  { name: 'LM Studio', kind: 'openai', base: 'http://127.0.0.1:1234/v1' },
  { name: 'llama.cpp', kind: 'openai', base: 'http://127.0.0.1:8080/v1' },
  { name: 'Jan',       kind: 'openai', base: 'http://127.0.0.1:1337/v1' },
  { name: 'vLLM/TGI',  kind: 'openai', base: 'http://127.0.0.1:8000/v1' },
];

/* ------------------------------------------------------------------ http */
/** Minimal JSON over HTTP. node:http rather than fetch so Node 18 stays quiet. */
export function httpJson(url, { method = 'GET', body = null, timeoutMs = 8000, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(url); } catch (e) { return reject(new Error(`bad url: ${url}`)); }
    const lib = u.protocol === 'https:' ? https : http;
    const payload = body == null ? null : Buffer.from(JSON.stringify(body));
    const req = lib.request({
      hostname: u.hostname,
      port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search,
      method,
      headers: {
        accept: 'application/json',
        ...(payload ? { 'content-type': 'application/json', 'content-length': payload.length } : {}),
        ...headers,
      },
    }, res => {
      let buf = '';
      res.setEncoding('utf8');
      res.on('data', d => { buf += d; });
      res.on('end', () => {
        let data = null;
        try { data = buf ? JSON.parse(buf) : null; } catch { /* non-JSON is a valid failure */ }
        resolve({ status: res.statusCode, data, raw: buf });
      });
    });
    req.setTimeout(timeoutMs, () => req.destroy(new Error('timed out')));
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

/* --------------------------------------------------------------- detect */
/** Ask one endpoint what it is and what models it has. Never throws. */
export async function probe(target, timeoutMs = 1500) {
  try {
    if (target.kind === 'ollama') {
      const r = await httpJson(`${target.base}/api/tags`, { timeoutMs });
      if (r.status !== 200 || !r.data) return null;
      const models = (r.data.models || []).map(m => m.name).filter(Boolean);
      return { ...target, models, ok: true };
    }
    const r = await httpJson(`${target.base}/models`, { timeoutMs });
    if (r.status !== 200 || !r.data) return null;
    const models = (r.data.data || []).map(m => m.id).filter(Boolean);
    return { ...target, models, ok: true };
  } catch { return null; }
}

/**
 * Find a local model server. Probes concurrently — a stopped port refuses
 * instantly, so the whole sweep costs about one timeout in the worst case
 * rather than five.
 */
export async function detect(targets = PROBE_TARGETS, timeoutMs = 1500) {
  const found = await Promise.all(targets.map(t => probe(t, timeoutMs)));
  // Preserve PROBE_TARGETS order so detection is deterministic when a machine
  // happens to be running two runtimes at once.
  return found.filter(Boolean);
}

/** Resolve config + detection into the endpoint we will actually use. */
export async function resolveProvider(cfg = {}) {
  const c = { ...LLM_DEFAULTS, ...cfg };
  if (c.enabled === false) return null;

  if (c.endpoint) {
    // An explicitly configured endpoint is used as given. Its kind is inferred
    // from the shape of the URL: Ollama's API is not under /v1.
    const kind = c.kind || (/\/v1\/?$/.test(c.endpoint) ? 'openai' : 'ollama');
    const base = c.endpoint.replace(/\/$/, '');
    // Recognise a known runtime by its address so the console can say "Ollama"
    // rather than "configured", which tells the analyst nothing.
    const known = PROBE_TARGETS.find(t => t.base === base);
    const target = { name: c.name || (known && known.name) || 'local', kind, base };
    const live = await probe(target, 2500);
    // Still return the target when the probe fails: the endpoint may simply
    // not implement a model-listing route. Let the actual request be the judge.
    return { ...(live || target), models: live ? live.models : [], model: c.model || (live && live.models[0]) || '', reachable: !!live };
  }

  if (!c.autodetect) return null;
  const [first] = await detect();
  if (!first) return null;
  return { ...first, model: c.model || first.models[0] || '', reachable: true };
}

/* ------------------------------------------------------------------ chat */
/**
 * The companion's brief.
 *
 * Written for a small local model, which is a different audience from a
 * frontier one: short instructions, one job, an explicit refusal path. The
 * length cap is here rather than only in max_tokens because a 3B model asked
 * for "a sentence" will otherwise write an essay and get truncated mid-word.
 */
export const COMPANION_SYSTEM = `You are the local analyst companion inside AEGIS, a SOC console.

You help a security analyst think, in real time, while they work an incident.

Rules:
- Be brief. Two or three sentences, or a short list. Never write an essay.
- Lead with what matters: what this looks like, and what to check next.
- Name concrete things - event IDs, process names, ATT&CK technique IDs, hosts.
- If the evidence is thin, say so plainly. Do not invent detail that is not in
  what you were given. "Not enough here to say" is a useful answer.
- No preamble, no sign-off, no offers to help further.`;

/** Build the request body for whichever dialect the endpoint speaks. */
export function buildChat(provider, { system, messages, maxTokens, stream = false }) {
  const model = provider.model || '';
  const msgs = [];
  if (system) msgs.push({ role: 'system', content: system });
  for (const m of messages || []) {
    if (!m || !m.content) continue;
    msgs.push({ role: m.role === 'assistant' ? 'assistant' : 'user', content: String(m.content) });
  }
  if (!msgs.some(m => m.role === 'user')) throw new Error('needs at least one user message');

  if (provider.kind === 'ollama') {
    return {
      url: `${provider.base}/api/chat`,
      body: { model, messages: msgs, stream, options: { num_predict: maxTokens || LLM_DEFAULTS.maxTokens } },
    };
  }
  return {
    url: `${provider.base}/chat/completions`,
    body: { model, messages: msgs, stream, max_tokens: maxTokens || LLM_DEFAULTS.maxTokens },
  };
}

/** Pull the assistant text out of either dialect's response. */
export function textOf(provider, data) {
  if (!data) return '';
  if (provider.kind === 'ollama') return String((data.message && data.message.content) || '').trim();
  const ch = (data.choices || [])[0];
  return String((ch && ch.message && ch.message.content) || '').trim();
}

/**
 * One completion. Resolves with {ok, text, error} — a local model being busy,
 * cold-loading a 4GB file, or missing is an ordinary condition here, not an
 * exception worth unwinding the request for.
 */
export async function complete(provider, { system, messages, maxTokens, timeoutMs }) {
  if (!provider) return { ok: false, error: 'no local model is configured or running' };
  let req;
  try { req = buildChat(provider, { system, messages, maxTokens }); }
  catch (e) { return { ok: false, error: e.message }; }

  try {
    const r = await httpJson(req.url, {
      method: 'POST', body: req.body,
      timeoutMs: timeoutMs || LLM_DEFAULTS.timeoutMs,
    });
    if (r.status !== 200) {
      const msg = (r.data && (r.data.error?.message || r.data.error)) || `HTTP ${r.status}`;
      return { ok: false, error: String(msg).slice(0, 300) };
    }
    const text = textOf(provider, r.data);
    if (!text) return { ok: false, error: 'the model returned nothing' };
    return { ok: true, text, model: provider.model };
  } catch (e) {
    return { ok: false, error: e.message === 'timed out'
      ? 'the local model took too long — a first request loads the weights and can be slow'
      : e.message };
  }
}

/* ------------------------------------------------------- event briefing */
/**
 * Turn raw telemetry into the prompt the companion actually sees.
 *
 * Local models have small context windows and get worse, not better, when fed
 * a wall of JSON. This hands over a compact, deduplicated summary — which is
 * also what a human would want to read.
 */
export function briefEvents(events, { host = '', limit = 25 } = {}) {
  const rows = (events || []).slice(-limit);
  if (!rows.length) return '';
  const lines = [];
  const seen = new Map();
  for (const e of rows) {
    // Collapse repeats: "4625 x40" tells the model more than forty identical
    // lines, and costs a fortieth of the context.
    const key = `${e.host || ''}|${e.channel || ''}|${e.eventId || ''}|${e.severity || ''}`;
    const cur = seen.get(key);
    if (cur) { cur.n++; continue; }
    seen.set(key, { n: 1, e });
  }
  for (const { n, e } of seen.values()) {
    const bits = [
      e.ts ? new Date(e.ts).toISOString().slice(11, 19) : '',
      e.host || '',
      e.channel ? `${e.channel}/${e.eventId || '?'}` : (e.eventId || ''),
      e.severity || '',
      e.technique || '',
      (e.message || '').replace(/\s+/g, ' ').slice(0, 160),
    ].filter(Boolean);
    lines.push(`- ${bits.join('  ')}${n > 1 ? `   (x${n})` : ''}`);
  }
  return `${host ? `Host: ${host}\n` : ''}Recent telemetry:\n${lines.join('\n')}`;
}

/** The standing question the companion answers about a burst of telemetry. */
export const WATCH_PROMPT =
  'Assess the telemetry above. In two or three sentences: what does this look like, '
  + 'how concerned should the analyst be, and what is the single most useful next check? '
  + 'If it looks like normal activity, say so and stop.';

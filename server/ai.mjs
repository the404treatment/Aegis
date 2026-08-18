/**
 * AI Analyst proxy.
 *
 * The console's AI tab was originally written to run inside the claude.ai
 * Artifacts sandbox, where a bare `fetch` to api.anthropic.com is authenticated
 * for you. Served from anywhere else — GitHub Pages, or this server on your own
 * network — that request carries no key and is blocked by CORS besides, so the
 * feature simply could not work outside the sandbox.
 *
 * This module is the fix: the browser posts to AEGIS, AEGIS calls Anthropic.
 * That buys three things beyond "it works":
 *
 *   - The API key stays on the server. It is never sent to a browser, never in
 *     the built ui/index.html, never in the repo. This is the hard rule in
 *     CLAUDE.md and the reason a client-side key was never an option.
 *   - Same-origin, so no CORS and no third-party request from the analyst's
 *     browser.
 *   - One place to bound spend. The model and token ceiling are set here from
 *     config; a compromised or buggy client cannot raise them.
 *
 * Zero dependencies — node:https only, same as the Splunk HEC sender.
 */
import https from 'node:https';

export const AI_DEFAULTS = {
  enabled: true,          // honoured only when a key is actually present
  apiKey: '',             // prefer the ANTHROPIC_API_KEY env var over writing this to disk
  model: 'claude-opus-5',
  maxTokens: 16000,
  timeoutMs: 120000,      // thinking models take their time on hard questions
};

/** Env wins over config so a key need never be written to disk at all. */
export function aiKey(ai) {
  return String(process.env.ANTHROPIC_API_KEY || (ai && ai.apiKey) || '').trim();
}

/** The AI tab is available only when it is switched on AND has a key. */
export function aiEnabled(ai) {
  return !!(ai && ai.enabled !== false) && !!aiKey(ai);
}

/**
 * Bound what the client can ask for. The route is analyst-gated, so this is not
 * a trust boundary against strangers — it is a blast radius limit. A runaway
 * loop in the console should cost pennies, not a month of budget.
 */
export function sanitiseMessages(raw, opts = {}) {
  const maxMessages = opts.maxMessages || 24;
  const maxChars = opts.maxChars || 120000;
  if (!Array.isArray(raw) || !raw.length) throw new Error('messages must be a non-empty array');

  const out = [];
  for (const m of raw.slice(-maxMessages)) {
    if (!m || typeof m !== 'object') continue;
    const role = m.role === 'assistant' ? 'assistant' : 'user';
    // The console only ever sends plain strings. Anything else is a bug or an
    // attempt to smuggle a content block through; stringify and move on.
    const content = typeof m.content === 'string' ? m.content : JSON.stringify(m.content ?? '');
    if (!content.trim()) continue;
    out.push({ role, content });
  }
  if (!out.length) throw new Error('messages contained nothing to send');

  // The API rejects a conversation that opens on the assistant.
  while (out.length && out[0].role === 'assistant') out.shift();
  // A TRAILING assistant turn is an assistant prefill, which current models
  // reject outright. The console always appends a user turn before asking, but
  // a chat log restored from storage or trimmed at the wrong boundary can end
  // on the assistant — and that turns a working chat into a hard 400.
  while (out.length && out[out.length - 1].role === 'assistant') out.pop();
  if (!out.length) throw new Error('messages must contain at least one user turn');

  let total = out.reduce((n, m) => n + m.content.length, 0);
  // Drop from the front — the oldest turns are the least load-bearing.
  while (total > maxChars && out.length > 1) {
    total -= out.shift().content.length;
    while (out.length && out[0].role === 'assistant') total -= out.shift().content.length;
  }
  if (out.length === 1 && out[0].content.length > maxChars) {
    out[0] = { ...out[0], content: out[0].content.slice(0, maxChars) };
  }
  return out;
}

/**
 * Build the upstream request body. Model and max_tokens come from config, not
 * from the caller, so the client cannot swap in a costlier model.
 */
export function buildRequest(ai, { system, messages }) {
  const body = {
    model: (ai && ai.model) || AI_DEFAULTS.model,
    max_tokens: Number((ai && ai.maxTokens) || AI_DEFAULTS.maxTokens),
    messages: sanitiseMessages(messages),
  };
  if (system && String(system).trim()) body.system = String(system).slice(0, 40000);
  return body;
}

/** Pull the plain text out of a Messages response, ignoring thinking blocks. */
export function textOf(data) {
  if (!data || !Array.isArray(data.content)) return '';
  return data.content.filter(b => b && b.type === 'text').map(b => b.text || '').join('').trim();
}

/**
 * POST to the Messages API. Resolves with {status, data} for any HTTP reply —
 * including 4xx/5xx, which carry a useful error body worth passing on — and
 * rejects only when the request could not be made at all.
 */
export function callAnthropic(ai, payload) {
  const key = aiKey(ai);
  if (!key) return Promise.reject(new Error('no API key configured'));
  const body = JSON.stringify(payload);

  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: 'api.anthropic.com',
      port: 443,
      path: '/v1/messages',
      method: 'POST',
      headers: {
        'x-api-key': key,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(body),
      },
    }, res => {
      let buf = '';
      res.setEncoding('utf8');
      res.on('data', d => { buf += d; });
      res.on('end', () => {
        let data;
        try { data = JSON.parse(buf); }
        catch { data = { error: { message: `non-JSON reply from the API (HTTP ${res.statusCode})` } }; }
        resolve({ status: res.statusCode, data });
      });
    });
    req.setTimeout(Number((ai && ai.timeoutMs) || AI_DEFAULTS.timeoutMs), () => {
      req.destroy(new Error('the model took too long to answer'));
    });
    req.on('error', reject);
    req.end(body);
  });
}

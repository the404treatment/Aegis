# CLAUDE.md

## Project
**AEGIS** — SOC detection-engineering console + agent platform.
- `src/` → built into `ui/index.html`, a self-contained browser app (ATT&CK matrix, hunt map, detection studio, AI analyst, tickets).
- `server/` + `agents/` → deployable ingest platform that feeds the console in real time.

## Commands
```bash
npm run build      # src/ -> ui/index.html (+ syntax & div-balance gate)
npm run dev        # rebuild on change
npm test           # build, then 62 UI assertions
npm run test:ui    # tests only, skip build
npm start          # server on :8787, serves ui/ and the API
npm run serve      # build + start
npm run lint:agent # python agent syntax
```
`ui/index.html` is **generated** — it is gitignored. Never edit it; edit `src/` and rebuild.

## Tech Stack
- **UI**: vanilla JS, no framework, no bundler. One global scope. `src/manifest.json` defines concatenation order and is **load-bearing** — data modules before the code that reads them.
- **Server**: Node 18+ ESM, **zero dependencies** (`node:http/https/fs/path/crypto`). JSON + NDJSON store.
- **Realtime**: Server-Sent Events. No WebSocket library.
- **Agents**: PowerShell 5.1+ (Windows), Python 3.8+ stdlib (Linux/macOS). No third-party modules.
- **AI**: `fetch` → `https://api.anthropic.com/v1/messages`, model `claude-sonnet-4-6`, `max_tokens: 1000`. Never embed an API key.
- **Integrations**: Splunk HEC out, Slack/Teams webhook out.

## Layout
```
src/shell.html         HTML shell with /*{{STYLES}}*/ and /*{{SCRIPT}}*/ placeholders
src/styles.css         all CSS
src/manifest.json      concatenation order
src/data/*.js          WIN, AWS, LOGSRC, NODE_TYPES, TACTICS, MITS, SUBS, MITRE, ALERT_META
src/app/core.js        state, helpers, persistence, undo, nav
src/app/matrix.js      matrix, peek, drawer, event cards
src/app/studio.js      detection studio, Sigma, savedsearches, RBA
src/app/map-*.js       zones / nodes / animation / tools / interaction
src/app/triage.js      artifact triage wizard
src/app/live.js        server connection + ticketing UI
src/app/auth.js        login veil, session handling, identity chip
src/app/cases.js       case files, evidence upload, ticket linking
src/app/siem.js        event search console
src/app/ingest.js      Chainsaw / Suricata / Zeek / PCAP parsers + wizard
src/app/advisor.js     offline response playbooks
src/app/ioc.js         IOC extraction + highlighting
src/app/improvements.js bulk import, build-next ranking, SPL lint, scorecard, tuning log
src/app/dialogs.js     uiConfirm / uiPrompt
src/app/report.js      report generator
src/app/ai.js          AI calls, incident context, tour, boot

server/aegis-server.mjs  HTTP API, SSE, agent ingest, static UI
server/auth.mjs          accounts, sessions, capabilities (opt-in)
server/cases.mjs         case model + evidence decode/hash
server/lake.mjs          event-search query language
server/audit.mjs         hash-chained audit log
```

## Architecture
```
Endpoints                 Server (:8787)              Analyst browser
aegis-agent.ps1  --HTTPS--> /api/enroll               ui/index.html
aegis-agent.py             /api/heartbeat   --SSE-->  live map
  (read-only)              /api/events      <-REST->  tickets
                           /api/discovery             triage
                           /api/tickets
                                 | HEC
                              Splunk
```
- **Auth**: enrollment token (shared, rotate post-rollout) → per-agent key → analyst token. Agents write only their own telemetry; they cannot read hosts or tickets, and there is **no remote-exec channel by design**.
- **Discovery**: agents report established TCP peers + logging posture. A link is drawn only when *both* ends are enrolled agents. Discovered edges carry `discovered:true` and are replaced each refresh; hand-drawn edges are never touched.
- **Offline**: with no server the console is fully functional and local-only via `localStorage`.

## Hard Rules
1. **Never use native `confirm()` / `prompt()`.** Mobile in-app browsers suppress them and a "block further dialogs" tick makes them return false forever — this shipped three separate broken-button bugs. Use `await uiConfirm(msg,{title,ok,danger})` and `await uiPrompt(label,def,opts)`; callers must be `async`.
2. **Never edit `ui/index.html`.** Edit `src/`, run `npm run build`.
3. **No `<form>` tags** in the UI; use click handlers.
4. **Map canvas is unbounded** — `LS_W=1400 LS_H=900` is nominal only. Do not reintroduce coordinate clamps; Fit/pan recovers off-screen items.
5. **Zones start empty.** `ZONES = {}` on first run; the six defaults are opt-in via `lsPresetZones()`. Clear must leave zero zones.
6. **Dragging a zone moves only the rectangle**, never its member hosts.

## UI Conventions
- Theme: bg `#0a0a12`, violet `#8b7bff`, sky `#5cc8ff`, magenta `#ff4d8f`, amber `#ffb547`, mint `#3ddc97`. Sora for UI, IBM Plex Mono (`--mono`) for data/IDs.
- `localStorage` keys: `aegis-{studio,notes,nodes,edges,nodeseq,maturity,answers,zones,snaps,tune,live,lastchain,coach-*,toured}`.
- SPL conventions (enforced by `splLint`): broad alerting + `outputlookup`/`inputlookup` suppression; `dc(ComputerName)` scoring; `ut_shannon_lookup` **always** wrapped in `tonumber()`; 4657 uses `Object_Name`=key and `New_Value`=data.

## Data Invariants — `npm test` asserts all of these
- 15 tactics (Defense Evasion split into **Stealth** + **Defense Impairment**), 258 placements.
- 225 techniques, **all curated** (`ref:false`), each with `summary` / `detect[]`≥3 / `pivots[]` / `mits[]` / `start`.
- Every mitigation ref resolves; every event reachable via ≥1 technique; `SUBS` keys ⊂ `MITRE`.
- 24 node types, 48 log sources, report sections sequential 1–11.
- Known gap: `T1genc` ("Generate Content") is an unverified placeholder ID with its MITRE link suppressed.

## Testing Rule
Stubs must **mimic hostile reality**, not the happy path. `test/ui.test.mjs` stubs `confirm → false` and `prompt → null`, and simulates a page reload by re-booting the module against the *same* fake `localStorage`. An in-memory flag that "fixes" a bug passes a naive test and fails on refresh — that is exactly how the clear-map bug survived three rounds. Keep both properties when adding tests.

## Notes
- `str_replace`-style edits break on apostrophes inside template literals; reword or splice.
- `server/config.json` holds live tokens and is gitignored. Commit only `config.example.json`.
- The server prints both tokens on startup and generates them if absent.

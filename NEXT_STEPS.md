# Next Steps

Priority-ordered roadmap for AEGIS. Top item first.

## 1. Zero-friction onboarding — get a live demo up with no install

**Problem:** `ui/index.html` is the entire app, but it's build-generated and gitignored
(see `CLAUDE.md`). Anyone landing on the GitHub repo today has to install Node 18+,
clone, and run `npm run build` before they can open anything. That's a hard stop for
"try it in 10 seconds."

**Fix — GitHub Pages via Actions:**
- Add `.github/workflows/pages.yml`: on push to `main`, run `node build.mjs`, publish
  `ui/index.html` to a `gh-pages` branch (or Pages' native build artifact flow).
- The console already runs fully offline/local-only against `localStorage` (see
  CLAUDE.md → Architecture), so a static Pages deploy is a fully working demo, not a
  stripped-down one. No server, no backend, nothing to configure.
- Result: `https://the404treatment.github.io/Aegis/` opens the working console
  directly. Zero install for anyone who just wants the ATT&CK matrix, hunt map, and
  detection studio.

**Secondary — trim the README quickstart** for people who *do* want the local
server + agent stack (live map, tickets):
```bash
git clone https://github.com/the404treatment/Aegis.git
cd Aegis
npm run serve   # build + start on :8787
```
No `npm install` step needed — the project has zero dependencies.

## 2. Skyhawk feature port — ✅ complete

Porting the best parts of [xGhst0/skyhawk](https://github.com/xGhst0/skyhawk) — a full
incident-response case-management app — into AEGIS, rekeyed to AEGIS's own architecture
(vanilla JS, offline-first, zero-dependency server, push-only read-only agents). Explicit
non-goal carried through every phase: Skyhawk's pull-based agent task queue is **not**
being ported — AEGIS's agents stay push-only with no remote-exec channel by design.

| Phase | Content | Status |
|---|---|---|
| 0 | Response advisor (`src/app/advisor.js`), IOC auto-classifier (`src/app/ioc.js`), hash-chained audit log (`server/audit.mjs`) | ✅ done |
| 1 | Agent event-ID enrichment → live technique tagging (`agents/aegis-agent.ps1` → `/api/events` → hunt-map badge) | ✅ done |
| 2 | Client-side ingest parsers (Chainsaw/Suricata/Zeek/PCAP) — runs in-browser, offline, feeding the hunt map | ✅ done |
| 3 | Event lake + SIEM query tab (global scope, not per-case — no case entity exists yet) | ✅ done |
| 4 | Auth/RBAC + login, additive/opt-in (`CFG.requireLogin`, default off) — existing `analystToken` deploys keep working unmodified | ✅ done |
| 5 | Case-file layer + evidence upload — a lightweight `Case` container (not a retrofit of tickets into Skyhawk's 6-state approval workflow); tickets gain one optional `caseId` field | ✅ done |
| 6 | Formal report freeze/sign (`server/report.mjs`) — lead-gated, anonymised, version-stamped, hash-recorded snapshot | ✅ done |
| 7 | Team chat (`src/app/chat.js`) — reuses the server's existing SSE `broadcast()`, not Skyhawk's 2.5s polling | ✅ done |

Phase 4 (auth) was ordered ahead of Phase 5 (cases) deliberately: Skyhawk's finding
approval workflow needs real user roles to mean anything ("who can approve" is
meaningless without identity), so retrofitting roles after the case model existed would
have meant reworking it.

### What was deliberately not ported

- **The pull-based agent task queue.** Skyhawk's server queues collectors for agents to
  poll. AEGIS's agents are push-only with no remote-exec channel by design — a documented
  hard invariant. This is the one subsystem that is architecturally incompatible, not
  merely unported.
- **The six-state finding approval workflow** (Draft → Submitted → UnderReview →
  Approved/Parked/Rejected). It exists to serve multi-analyst peer review, which is a much
  larger feature than the formal report needs. The two fields the report filter actually
  uses (`includeInFormal`, `formalSummary`) live on the ticket instead.
- **Skyhawk's own ~140-technique ATT&CK list.** AEGIS has its own curated 225-technique
  set and custom 15-tactic taxonomy; everything ported resolves against that rather than
  carrying a second, divergent catalogue.
- **The regulatory-clock subsystem** (SEC 8-K / GDPR-33 / DORA / NIS2 timers). It is
  unintegrated dead code in the source — no routes, no UI — so there was nothing working
  to port. It remains a candidate feature, not a port.

### Follow-on candidates

- Per-case scoping for Event Search — currently global; now that cases exist it is a
  filter on the existing query, not new storage.
- Evidence retention/GC — files are content-addressed and never pruned today.
- Regulatory notification clocks, if the deadlines matter to your reporting obligations.

## 3. CI on every push/PR

No workflow currently runs `npm test`. Add `.github/workflows/test.yml` (Node 18,
`npm test`) so a broken build or a failed data-integrity assertion is caught before
merge instead of discovered later. Natural pairing with the Pages workflow in #1 —
gate the Pages publish on tests passing.

## 4. Repo hygiene (uncommitted / stray files found in the working tree)

- `aegis-v3.html` (untracked, 7255 lines) — looks like a pre-refactor monolith left
  over from before the `src/` modular split. Decide: delete, or move to an `archive/`
  folder if it's kept intentionally as a reference.
- `ui.test.mjs` (untracked, repo root) — byte-identical duplicate of
  `test/ui.test.mjs`. Remove the stray root copy.
- `deploy/install-agent.sh` — working copy lost its executable bit (755 → 644).
  Restore with `chmod +x deploy/install-agent.sh` before it's committed, or the
  deploy step breaks for anyone who pulls it as-is.

## 5. Documentation drift

`src/app/improvements.js` (bulk host import, "what to build next" ranking, SPL
convention linter, coverage scorecard, tuning log) is wired into the build via
`src/manifest.json` but isn't listed in `CLAUDE.md`'s Layout section. Add it so the
architecture doc stays a complete map of `src/app/`.

## 6. Known data gap

`T1genc` ("Generate Content") is a placeholder MITRE ATT&CK technique ID with its
link intentionally suppressed (flagged already in `CLAUDE.md` → Data Invariants).
Needs either a verified real ATT&CK ID or removal from the technique set.

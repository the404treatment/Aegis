# Next Steps

Priority-ordered roadmap for AEGIS. Top item first.

## 1. Zero-friction onboarding — ✅ done

`.github/workflows/pages.yml` builds `src/` and publishes the console on every push to
`main`, gated on the test suite passing. Because the console is fully functional with no
backend, the static deploy is the real app rather than a preview — anything that needs
the server shows its usual "connect to a server" state.

Live at **https://the404treatment.github.io/Aegis/**.

For anyone who wants the full server + agent stack instead:
```bash
git clone https://github.com/the404treatment/Aegis.git
cd Aegis
npm run serve   # build + start on :8787
```
No `npm install` step — the project has zero dependencies.

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

## 3. CI on every push/PR — ✅ done

`.github/workflows/test.yml` runs the full suite on push and PR across Node 18 (the
declared floor) and 22, plus syntax checks on both agent scripts. It also asserts the
project is still dependency-free, so if that ever changes the workflow fails loudly
rather than silently skipping an install step.

## 4. Repo hygiene — mostly resolved

- ~~`ui.test.mjs` (stray root duplicate)~~ — removed. It was byte-identical to
  `test/ui.test.mjs` at `3960e86`, so the content remains in git history.
- `aegis-v3.html` — the pre-refactor monolith. **Left on disk deliberately**: it was
  never committed, so deleting it is irreversible and that is your call, not a
  cleanup script's. It is now gitignored so it no longer clutters `git status`.
  Delete it locally whenever you're satisfied nothing in it is still wanted.
- `deploy/install-agent.sh` — the working copy still shows a mode change (755 → 644),
  a Windows checkout artifact rather than a real edit. It has been left unstaged
  throughout. If you ever commit it, run `git update-index --chmod=+x
  deploy/install-agent.sh` first so the executable bit survives for Linux users.

## 5. Documentation drift

`src/app/improvements.js` (bulk host import, "what to build next" ranking, SPL
convention linter, coverage scorecard, tuning log) is wired into the build via
`src/manifest.json` but isn't listed in `CLAUDE.md`'s Layout section. Add it so the
architecture doc stays a complete map of `src/app/`.

## 6. Known data gap

`T1genc` ("Generate Content") is a placeholder MITRE ATT&CK technique ID with its
link intentionally suppressed (flagged already in `CLAUDE.md` → Data Invariants).
Needs either a verified real ATT&CK ID or removal from the technique set.

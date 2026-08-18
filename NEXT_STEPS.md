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

## 2. CI on every push/PR

No workflow currently runs `npm test`. Add `.github/workflows/test.yml` (Node 18,
`npm test`) so a broken build or a failed data-integrity assertion is caught before
merge instead of discovered later. Natural pairing with the Pages workflow in #1 —
gate the Pages publish on tests passing.

## 3. Repo hygiene (uncommitted / stray files found in the working tree)

- `aegis-v3.html` (untracked, 7255 lines) — looks like a pre-refactor monolith left
  over from before the `src/` modular split. Decide: delete, or move to an `archive/`
  folder if it's kept intentionally as a reference.
- `ui.test.mjs` (untracked, repo root) — byte-identical duplicate of
  `test/ui.test.mjs`. Remove the stray root copy.
- `deploy/install-agent.sh` — working copy lost its executable bit (755 → 644).
  Restore with `chmod +x deploy/install-agent.sh` before it's committed, or the
  deploy step breaks for anyone who pulls it as-is.

## 4. Documentation drift

`src/app/improvements.js` (bulk host import, "what to build next" ranking, SPL
convention linter, coverage scorecard, tuning log) is wired into the build via
`src/manifest.json` but isn't listed in `CLAUDE.md`'s Layout section. Add it so the
architecture doc stays a complete map of `src/app/`.

## 5. Known data gap

`T1genc` ("Generate Content") is a placeholder MITRE ATT&CK technique ID with its
link intentionally suppressed (flagged already in `CLAUDE.md` → Data Invariants).
Needs either a verified real ATT&CK ID or removal from the technique set.

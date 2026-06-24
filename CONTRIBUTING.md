# Contributing to SentinelView

Thanks for your interest in contributing! This guide covers how to set up the
project, the standards we follow, and how to propose changes.

## Getting Started

```bash
git clone https://github.com/BasitS-hash/siem-dashboard.git
cd siem-dashboard
npm install          # installs all workspaces
npm run dev          # backend (3001) + frontend (5200)
```

The repo is an **npm workspaces monorepo** with two packages: `backend`
(Node + Express + Socket.io) and `frontend` (React + Vite). Run workspace
scripts with `--workspace=backend` or `--workspace=frontend`.

## Development Workflow

1. **Branch** off `main`:
   ```bash
   git checkout -b feat/your-feature
   ```
2. **Make focused changes.** Keep files cohesive (~200–400 lines, 800 max) and
   functions small.
3. **Write tests first** where practical. New logic in the detection engine,
   parsers, validators, or CSV export should ship with Vitest coverage.
4. **Verify locally** before pushing (see below).
5. **Open a PR** against `main` with a clear description and test notes.

## Before You Push — Quality Gates

All of these must pass; CI enforces them on every PR:

```bash
# Type-check both workspaces
npm run typecheck --workspace=backend
npm run typecheck --workspace=frontend

# Run tests
npm run test --workspace=backend
npm run test --workspace=frontend

# Production build
npm run build
```

## Coding Standards

- **TypeScript everywhere.** Avoid `any`; prefer `unknown` + narrowing for
  untrusted input. Add explicit types to exported/public functions.
- **Immutability.** Return new objects rather than mutating inputs.
- **Validate at boundaries.** Any new REST endpoint or socket event must
  validate and sanitize its input — add a pure validator in `validation.ts`
  and unit-test it.
- **No secrets in source.** Use environment variables; document new ones in
  `.env.example`.
- **No debug `console.log`** in committed code (structured server-side logging
  is fine).
- **Security output safety.** Any new export/render path that includes
  user-influenced data must be injection-safe (see `exportCsv.ts` for the CSV
  pattern).

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add Sigma rule import to the detection engine
fix: clamp limit query param on /api/logs
test: cover lateral-movement detection edge cases
docs: document ALLOWED_ORIGINS in the README
chore: pin frontend dependency versions
ci: add Trivy container scan
refactor: extract CSV serialization helpers
perf: memoize stats computation
```

## Adding a Detection Rule

1. Add the attack type to `AttackType` in `backend/src/types.ts`.
2. Add its MITRE mapping to `MITRE_MAP` in `threatDetector.ts`.
3. Implement the detection branch in `runDetections`, using the windowed
   tracker and the de-dup `isSeen`/`markSeen` pattern.
4. Add Vitest cases covering both the trigger and the non-trigger boundary.
5. Document the rule in the README's detection-rules table.

## Reporting Bugs & Security Issues

- **Bugs / features:** open a GitHub issue with reproduction steps.
- **Security vulnerabilities:** do **not** open a public issue — follow
  [SECURITY.md](SECURITY.md).

## Code of Conduct

Be respectful and constructive. Assume good faith, keep discussions focused on
the work, and help reviewers by keeping PRs small and well-described.

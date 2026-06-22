# LLM Guardian - Agent Instructions

## Project Goal
Build an AI Red Team evaluation agent that tests local vulnerable LLM target agents and generates structured security reports.

## Language Rule
All developer-facing material must be written in English: code comments, docs, prompts, tests, commit messages, and Codex instructions.

## Repository Safety Check
Before editing any file, always run and inspect:
- `pwd`
- `git remote -v`
- `git branch --show-current`
- `git status --short`

Do not edit anything unless:
- The current repository is `llm-guardian`.
- The current branch is `feature/*` or `fix/*`.

If either check fails:
- Stop immediately.
- Report the mismatch or uncertainty.
- Do not guess or continue.

## Non-Negotiable Rules
- Work in small vertical slices.
- Prefer small vertical slices over broad refactors.
- Keep changes scoped to the requested slice.
- Read docs/PRD.md, docs/ARCHITECTURE.md, and docs/TEST_STRATEGY.md before implementation.
- Write or update tests before implementation.
- Every implementation slice must include relevant tests.
- Every completed slice must run `./verify.sh`.
- Never suppress errors silently.
- Never hardcode API keys or secrets.
- Never read .env files.
- Never test real third-party systems.
- Unit tests must not call real LLM APIs.
- Do not add external services unless explicitly requested.
- Do not leave temporary diff, debug, or report files unless they are intentional project artifacts.
- If unsure, stop and report the uncertainty instead of guessing.

## Test Command
Run before every completion:

```bash
./verify.sh
```

## Git Workflow
- Codex may edit files for the current task.
- Codex must never edit files outside `llm-guardian`.
- Codex must work only on a `feature/*` or `fix/*` branch and never directly on `main`.
- Codex must run `python scripts/verify.py` before every commit.
- Codex must run `git diff --check` before every commit.
- Codex must inspect `git status --short` before every commit.
- Codex must not commit secrets, `.env` files, caches, generated reports, virtual environments, or binary planning documents.
- Codex may create local commits when explicitly instructed.
- Codex must not push unless explicitly instructed by the user.
- Codex must not push to `main`.
- Codex may push only to the current `feature/*` or `fix/*` branch, and only when explicitly instructed.
- Codex must never use `git push --force`.

## Definition of Done
A task is done only when:
- Tests pass.
- verify.sh passes.
- Public behavior matches the docs.
- Errors are explicit and actionable.
- README or docs are updated if behavior changed.

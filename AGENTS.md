# LLM Guardian - Agent Instructions

## Project Goal
Build an AI Red Team evaluation agent that tests local vulnerable LLM target agents and generates structured security reports.

## Language Rule
All developer-facing material must be written in English: code comments, docs, prompts, tests, commit messages, and Codex instructions.

## Non-Negotiable Rules
- Work in small vertical slices.
- Read docs/PRD.md, docs/ARCHITECTURE.md, and docs/TEST_STRATEGY.md before implementation.
- Write or update tests before implementation.
- Never suppress errors silently.
- Never hardcode API keys or secrets.
- Never read .env files.
- Never test real third-party systems.
- Unit tests must not call real LLM APIs.
- Do not add external services unless explicitly requested.

## Test Command
Run before every completion:

```bash
./verify.sh
```

## Git Workflow
- Codex may edit files for the current task.
- Codex must run `python scripts/verify.py` before every commit.
- Codex must run `git diff --check` before every commit.
- Codex must inspect `git status --short` before every commit.
- Codex must not commit secrets, `.env` files, caches, generated reports, virtual environments, or binary planning documents.
- Codex may create local commits when explicitly instructed.
- Codex must not push to `main`.
- Codex may push only to the current `feature/*` branch, and only when explicitly instructed.
- Codex must never use `git push --force`.

## Definition of Done
A task is done only when:
- Tests pass.
- verify.sh passes.
- Public behavior matches the docs.
- Errors are explicit and actionable.
- README or docs are updated if behavior changed.

# LLM Guardian - Agent Instructions

## Project Mission
LLM Guardian is evolving from a deterministic LLM security evaluator into an authorized AI security research and offensive testing platform.

The existing local/offline evaluator is a stable product surface and must remain functional while the new bounty track is added incrementally.

The bounty track is intended only for systems that are owned by the operator or explicitly authorized for security testing, including bug bounty assets that are clearly in scope.

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

## Required Context
Before implementing bounty-track work, read:
- `docs/BOUNTY_MVP_PRD.md`
- `docs/BOUNTY_ROADMAP.md`
- `docs/OFFENSIVE_ARCHITECTURE.md`
- `docs/AUTHORIZATION_AND_SCOPE.md`
- `docs/CODEX_WORKFLOW.md`
- `docs/TEST_STRATEGY.md`

For legacy evaluator work, also read:
- `docs/PRD.md`
- `docs/ARCHITECTURE.md`

## Non-Negotiable Engineering Rules
- Work in small vertical slices.
- Prefer narrow changes over broad refactors.
- Preserve existing deterministic/offline behavior unless the task explicitly changes it.
- Write or update tests before implementation.
- Every implementation slice must include relevant tests.
- Never suppress errors silently.
- Never hardcode API keys or secrets.
- Never read `.env` files.
- Unit tests must not call real LLM APIs or real third-party targets.
- Do not add external services unless explicitly requested.
- Do not leave temporary diff, debug, cache, or generated report files unless they are intentional artifacts.
- If unsure, stop and report the uncertainty instead of guessing.

## Authorization and Network Safety
The scope/authorization layer is a hard security boundary, not a prompt-level suggestion.

- No network-capable offensive action may bypass the scope guard.
- Scope decisions must fail closed.
- Redirects, discovered hosts, resolved IPs, and tool-generated targets must be revalidated before execution.
- Out-of-scope actions must be blocked before any network request is emitted.
- Every allow/block decision must be auditable.
- Real-target execution must remain disabled until the roadmap milestone that explicitly enables authorized network execution.
- Even after authorized execution exists, never add capabilities for denial-of-service, persistence, destructive actions, malware deployment, credential theft, social engineering, phishing, or stealth/evasion unless the project owner creates a separate explicitly reviewed scope for that capability.
- Bug bounty program restrictions override generic tool capability.

## Bounty Track Design Principles
- Authorization before automation.
- Deterministic policy enforcement outside the LLM.
- LLMs may propose actions; deterministic code decides whether actions are permitted.
- Evidence must be reproducible and attributable to an authorized run.
- Human review remains required before reporting a real vulnerability.
- Costly models are reserved for high-value reasoning; bulk processing should use cheaper deterministic or model-assisted stages.
- Build reusable primitives before platform UI or SaaS features.

## Test and Verification Gate
Run before every completion:

```bash
./verify.sh
```

Also run:

```bash
python scripts/verify.py
git diff --check
git status --short
```

## Git Workflow
- Codex may edit files for the current task.
- Codex must never edit files outside `llm-guardian`.
- Codex must work only on a `feature/*` or `fix/*` branch and never directly on `main`.
- Codex must inspect the diff before committing.
- Codex must not commit secrets, `.env` files, caches, generated reports, virtual environments, or binary planning documents.
- Codex may create local commits only when explicitly instructed.
- Codex must not push unless explicitly instructed by the user.
- Codex must not push to `main`.
- Codex may push only to the current `feature/*` or `fix/*` branch, and only when explicitly instructed.
- Codex must never use `git push --force`.

## Definition of Done
A task is done only when:
- The requested slice is implemented and no unrelated scope was added.
- Relevant tests pass.
- `./verify.sh` passes.
- `python scripts/verify.py` passes.
- `git diff --check` passes.
- Existing legacy evaluator behavior remains intact unless explicitly changed.
- Authorization/scope invariants remain intact for bounty-track work.
- Errors are explicit and actionable.
- README or docs are updated when public behavior or architecture changes.
- The final Codex summary follows `docs/CODEX_WORKFLOW.md`.

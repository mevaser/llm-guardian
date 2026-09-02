# Codex Workflow for the Bounty Track

## Purpose
This repository is developed through short Codex implementation cycles. Each cycle should produce one reviewable vertical slice, not a broad autonomous rewrite.

The human workflow is:

```text
ChatGPT defines next slice and prompt
        -> User gives prompt to Codex
        -> Codex inspects repo and implements slice
        -> Codex returns concise implementation summary
        -> User sends summary back to ChatGPT
        -> ChatGPT reviews result and decides: accept / fix / next slice
```

## Required Codex Behavior
At the start of every task:

```bash
pwd
git remote -v
git branch --show-current
git status --short
```

Then read:
- `AGENTS.md`;
- the roadmap section named in the task;
- the architecture/policy docs relevant to that slice;
- existing code/tests in the affected subsystem.

Do not begin editing until repository and branch checks satisfy `AGENTS.md`.

## One-Slice Rule
A task should implement exactly one roadmap slice unless the prompt explicitly combines slices.

Codex must not:
- pre-build later milestones;
- add scanners/browser automation/network execution while working on M0;
- introduce SaaS infrastructure, billing, or customer UI;
- refactor unrelated legacy modules;
- change public behavior just because a cleaner architecture is possible.

If a later concern affects the current design, add a small extension point or TODO in documentation only when necessary. Do not implement speculative functionality.

## Test-First Rule
For each slice:
1. inspect current tests and conventions;
2. add or update tests that express the acceptance criteria;
3. implement the minimum code needed to pass them;
4. run focused tests;
5. run repository verification.

## Verification
Before reporting completion, Codex must run:

```bash
python scripts/verify.py
./verify.sh
git diff --check
git status --short
```

If `./verify.sh` is unavailable or platform-specific, report that explicitly and run the repository's equivalent verification command rather than silently skipping validation.

Do not report a task as complete if relevant tests fail.

## Git Rules
Follow `AGENTS.md`.

Unless the prompt explicitly requests a commit/push:
- make the changes;
- run verification;
- show the diff/status summary;
- do not push.

When explicitly asked to commit:
- use a concise English commit message;
- inspect `git diff` and `git status` first;
- never commit secrets or generated junk.

When explicitly asked to push:
- push only the current `feature/*` or `fix/*` branch;
- never push directly to `main`;
- never force-push.

## Preferred Implementation Style
- Python type hints for public contracts.
- Small cohesive modules.
- Pure functions for policy/matching logic where practical.
- Explicit enums/value objects instead of free-form strings for security decisions.
- Structured errors instead of silent fallback.
- Dependency injection for clocks, providers, and executors when needed for deterministic tests.
- No network calls in unit tests.
- No model call as an authorization mechanism.

## Security Review Checklist for Every Bounty Slice
Codex should answer these questions before completion:
1. Can any code path bypass the scope guard?
2. Does ambiguous input fail closed?
3. Did this change accidentally enable real network activity earlier than the roadmap allows?
4. Are LLM/tool outputs treated as untrusted data?
5. Is the action/run/policy relationship auditable?
6. Are existing LLM Guardian features still passing verification?

If any answer is uncertain, Codex should report the uncertainty rather than claiming completion.

## Required Final Summary Format
Codex should return a concise summary in this exact structure:

```text
TASK
<roadmap slice and one-line objective>

CHANGES
- <important change 1>
- <important change 2>
- <important change 3>

TESTS
- <command>: PASS/FAIL
- <command>: PASS/FAIL

FILES
- <created/modified file>
- <created/modified file>

SECURITY CHECK
- Scope guard bypass introduced: NO/YES
- Real network activity introduced: NO/YES
- Existing behavior intentionally changed: NO/YES + explanation

GIT
- Branch: <branch>
- Commit: <sha or NOT COMMITTED>
- Push: <pushed/not pushed>

NOTES
- <only blockers, assumptions, or decisions that need review>
```

The summary should be factual and short. Do not paste large diffs unless requested.

## How ChatGPT Will Review the Summary
The expected response after each Codex cycle is intentionally brief:
- `GOOD` when the slice and verification satisfy the acceptance criteria;
- `FIX` followed by the smallest required correction when something is wrong;
- then the next Codex prompt when the slice is accepted.

## Prompt Template
Future Codex prompts should normally contain:

```text
You are implementing <ROADMAP SLICE> in the llm-guardian repository.

Read first:
- AGENTS.md
- <relevant docs>

Objective:
<one concrete objective>

Implement:
- <deliverable>
- <deliverable>

Acceptance criteria:
- <testable criterion>
- <testable criterion>

Do not:
- <explicit non-goal>
- <explicit non-goal>

Tests:
- <required tests>

Before completion run the repository verification commands from AGENTS.md and return the final summary using docs/CODEX_WORKFLOW.md.

Do not push unless this prompt explicitly tells you to push.
```

## Current Task Sequence
The first implementation prompt should target only:

`M0.1 - Scope Domain Model`

After M0.1 is reviewed and accepted, proceed to M0.2. Do not ask Codex to implement the whole roadmap in one task.

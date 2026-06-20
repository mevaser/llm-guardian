# Git Workflow

## Branch Policy
`main` is the stable branch. It should only receive reviewed, verified changes that are ready to keep as the project baseline.

Each implementation slice should use a dedicated `feature/*` branch. Keep branches focused on one vertical slice so review, CI results, and rollbacks stay clear.

Recommended branch names:
- `feature/target-agents`
- `feature/scan-runner`
- `feature/reports-scoring`
- `feature/streamlit-dashboard`
- `feature/deployment`

## Codex Commits
Codex may edit files for the current task and may create local commits only when explicitly instructed.

Before every commit, Codex must run:

```bash
python scripts/verify.py
git diff --check
git status --short
```

Codex must not commit secrets, `.env` files, caches, generated reports, virtual environments, or binary planning documents.

## CI and Review
GitHub Actions validates every push to `main`, every push to `feature/**`, and every pull request targeting `main`.

Merges to `main` are manual. Do not rely on local checks alone; use CI as the shared verification gate before merging.

## Push Rules
Codex must not push to `main`.

Codex may push only to the current `feature/*` branch, and only when explicitly instructed.

Codex must never use `git push --force`.

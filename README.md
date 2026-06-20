# LLM Guardian

LLM Guardian is a controlled AI Red Team evaluation harness for testing local, intentionally vulnerable LLM target agents. The project is designed for spec-first, TDD-style development with deterministic offline tests.

## Current Status
This repository currently contains the initial context package only. Application logic, Streamlit UI, target agents, scan runner, evaluators, scoring, and report generation will be implemented in later vertical slices.

## MVP Goal
- Load predefined attack cases from YAML.
- Execute attacks against local demo target agents.
- Evaluate responses with deterministic rules.
- Produce JSON and Markdown security reports.
- Display results in a local Streamlit dashboard.

## Boundaries
- Only local demo targets are in scope.
- Unit tests must not call real LLM APIs.
- External tools and side effects must be simulated.
- Do not scan real third-party systems.
- Do not commit secrets.

## Planned Verification
Use the repository verification gate before completing future implementation tasks:

```bash
./verify.sh
```

At this initial stage, the script skips code-specific checks until `src/` and `tests/` exist.

## Key Docs
- `docs/PRD.md`
- `docs/ARCHITECTURE.md`
- `docs/IMPLEMENTATION_PLAN.md`
- `docs/TEST_STRATEGY.md`
- `docs/SECURITY_SCOPE.md`
- `docs/DEMO_SCRIPT.md`
- `docs/DEPLOYMENT.md`

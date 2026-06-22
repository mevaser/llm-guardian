# LLM Guardian

LLM Guardian is a controlled AI Red Team evaluation harness for testing local, intentionally vulnerable LLM target agents. The project is designed for spec-first, TDD-style development with deterministic offline tests.

## Current Status
The repository contains a deterministic offline scan engine, local vulnerable demo targets, CLI workflows, and a local Streamlit dashboard for exploring scan results.

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

The verification gate compiles the codebase, runs tests, and validates the attack library.

## Local Usage
Run the verification gate:

```bash
./verify.sh
```

Run the deterministic baseline scan flow:

```bash
python -m llm_guardian.cli scan --target customer_support --offline --output tmp/baseline-report.json
```

Run the separate local-demo-only security-agent orchestration flow:

```bash
python -m llm_guardian.cli agent-scan --target tool_agent --category tool_abuse --output-format json
python -m llm_guardian.cli agent-scan --target rag_agent --category rag_injection --output-format markdown --output-file tmp/agent-report.md
```

`agent-scan` resolves target execution contracts from `data/target_profiles.yaml` by target name. Use `--target-profile path/to/target_profiles.yaml` to run the same local flow with another validated profile file.

Prompt mutation defaults to deterministic mode. To exercise the optional offline LLM-assisted mutator with the fake client:

```bash
python -m llm_guardian.cli agent-scan --target mutation_challenge_tool_agent --category tool_abuse --max-total-attempts 10 --max-attempts-per-attack 2 --max-mutations-per-attack 1 --mutation-strategy-mode llm-assisted --llm-provider fake --output-format markdown
```

The LLM-assisted path validates structured JSON mutation proposals and falls back to deterministic mutation if validation fails. Verdicts remain deterministic. `--llm-provider ollama` is reserved but not implemented in this slice, and no Ollama request is made.

`scan` remains the baseline `ScanRunner` command. `agent-scan` is additive and uses `SecurityAgent` against approved local demo targets only.

Run the Streamlit dashboard locally:

```bash
python -m streamlit run src/llm_guardian/app/streamlit_app.py
```

## Development Workflow
Development work should happen on focused `feature/*` branches, with `main` kept stable. See `docs/GIT_WORKFLOW.md` for branch, commit, push, and merge rules.

Run the verification gate through `scripts/verify.py` before completing work or creating local commits.

## Key Docs
- `docs/PRD.md`
- `docs/ARCHITECTURE.md`
- `docs/IMPLEMENTATION_PLAN.md`
- `docs/TEST_STRATEGY.md`
- `docs/GIT_WORKFLOW.md`
- `docs/SECURITY_SCOPE.md`
- `docs/DEMO_SCRIPT.md`
- `docs/DEPLOYMENT.md`

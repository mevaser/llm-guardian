# LLM Guardian - AI Agent Security Evaluator

## Summary
LLM Guardian is a deterministic MVP for evaluating LLM and agent security behavior against prompt injection, indirect prompt injection, unsafe tool use, and secret-exfiltration scenarios.

The project is intentionally scoped as an offline-first course submission. It focuses on stable, reproducible evaluation behavior rather than production deployment.

## What the agent does
- `SecurityScanAgent` is the explicit evaluator agent for the MVP demo scan.
- Loads attack scenarios from YAML.
- Plans the scan against a demo vulnerable RAG agent.
- Executes scenarios in a deterministic offline loop.
- Observes response, retrieved context, and tool trace.
- Grades behavior using deterministic rules.
- Adapts with follow-up probes when critical findings are observed.
- Writes trajectory JSON evidence.
- Writes a Markdown report.

## Quick demo
Run the MVP demo scan:

```powershell
python -m llm_guardian.cli agent-scan --target demo-vulnerable-rag --output-dir reports/demo_scan
```

Expected stable console summary:

```text
LLM Guardian Scan Complete
Target: demo-vulnerable-rag
Scenarios tested: 8
Adaptive probes: 2
Passed: 6
Failed: 2
Critical: 2
Overall Risk: CRITICAL
```

## Optional LLM-assisted scenario generation
The stable demo scan stays unchanged by default. Optional scenario generation is available as a separate offline-first workflow that produces extra YAML scenarios and then routes them back through the same deterministic grading pipeline.

The included `fake` provider requires no API key, performs no network calls, and is intended for tests and local demos.

Generate optional scenarios:

```powershell
python -m llm_guardian.cli generate-scenarios --target demo-vulnerable-rag --count 2 --output data/generated_attack_scenarios.yaml --provider fake
```

## Groq provider
`fake` remains the default for offline deterministic tests and demos. `groq` is the first real cloud LLM provider for optional scenario generation only; it does not change deterministic execution or grading after scenario generation finishes.

Set the API key for the current PowerShell session:

```powershell
$env:GROQ_API_KEY="..."
```

Generate optional scenarios with Groq:

```powershell
python -m llm_guardian.cli generate-scenarios --target demo-vulnerable-rag --count 4 --output data/generated_attack_scenarios.yaml --provider groq --model llama-3.3-70b-versatile
```

Run the deterministic scan with the generated scenario file:

```powershell
python -m llm_guardian.cli agent-scan --target demo-vulnerable-rag --scenario-file data/generated_attack_scenarios.yaml --output-dir reports/generated_scan
```

## Streamlit UI
Run the Streamlit UI with:

```powershell
streamlit run streamlit_app.py
```

The Streamlit UI uses the same `SecurityScanAgent` workflow as the CLI. It does not
duplicate scan logic; it runs the agent, then displays the generated plan, trace,
findings, adaptive probes, trajectory JSON, and Markdown report. It also includes an
optional Scenario Generator tab backed by the same generation service, with `fake` for offline mode and optional `groq` for cloud-backed scenario generation.

## Output files
The demo command writes:

- `reports/demo_scan/scan_report.md`
- `reports/demo_scan/trajectory.json`

## Sample outputs
Reference artifacts are included in:

- `examples/demo_scan/scan_report.md`
- `examples/demo_scan/trajectory.json`

## Main project components
- `data/attack_scenarios.yaml`
- `demo_targets/vulnerable_rag_agent/`
- `src/llm_guardian/attacks/loader.py`
- `src/llm_guardian/runner/scenario_runner.py`
- `src/llm_guardian/evaluators/deterministic.py`
- `src/llm_guardian/reports/trajectory.py`
- `src/llm_guardian/reports/markdown.py`
- `src/llm_guardian/cli.py`

## Security note
- `send_email` is mock-only.
- `read_secret` returns a fixed fake demo secret.
- No real emails are sent.
- No real secrets are read.
- No LLM or external API call is required for the demo scan.
- Generated scenarios do not decide pass or fail; deterministic grading remains the source of truth.

## Limitations
- This is a deterministic MVP, not a full commercial red-team platform.
- No real MCP or tool integration yet.
- No LLM-as-judge yet.
- No cloud deployment yet.
- No benchmark adapters yet.
- The vulnerable target is intentionally simplified for demonstration.

## Tests
Run the test suite:

```powershell
$runTemp = Join-Path $PWD ".tmp\pytest-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Force $runTemp | Out-Null
python -m pytest --basetemp="$runTemp" -p no:cacheprovider
python scripts/verify.py
```

## Submission checklist
- Demo command works.
- Report generated.
- Trajectory generated.
- Sample artifacts included.
- Tests passing.

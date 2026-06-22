# LLM Guardian - AI Agent Security Evaluator

## Summary
LLM Guardian is a deterministic MVP for evaluating LLM and agent security behavior against prompt injection, indirect prompt injection, unsafe tool use, and secret-exfiltration scenarios.

The project is intentionally scoped as an offline-first course submission. It focuses on stable, reproducible evaluation behavior rather than production deployment.

## What the agent does
- `SecurityScanAgent` is the explicit evaluator agent for the MVP demo scan.
- Loads attack scenarios from YAML.
- Plans and runs scenarios against a demo vulnerable RAG agent.
- Observes response, retrieved context, and tool trace.
- Grades behavior using deterministic rules.
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
Passed: 6
Failed: 2
Critical: 2
Overall Risk: CRITICAL
```

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

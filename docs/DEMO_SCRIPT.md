# LLM Guardian — Course Demo Script

## Opening, 30 seconds
LLM Guardian is a local AI Red Team evaluation project for testing how AI and LLM-based agents behave under security scenarios. The goal is to run structured attacks against a target agent, observe what it does, and turn that behavior into clear security evidence. In this MVP, everything is deterministic and offline, so the demo is stable, repeatable, and does not depend on live external systems.

## Architecture, 60 seconds
The explicit evaluator agent is `SecurityScanAgent`. It loads attack scenarios from YAML in `data/attack_scenarios.yaml`, runs them against an intentionally vulnerable demo RAG agent in `demo_targets/vulnerable_rag_agent/`, observes the model response, retrieved context, and tool trace, then grades each scenario with deterministic rules. The final outputs are written as a trajectory JSON artifact and a Markdown report for review.

## Live Command
Run:

```bash
python -m llm_guardian.cli agent-scan --target demo-vulnerable-rag --output-dir reports/demo_scan
```

## Expected Output
The stable console summary is:

- `LLM Guardian Scan Complete`
- `Target: demo-vulnerable-rag`
- `Scenarios tested: 8`
- `Passed: 6`
- `Failed: 2`
- `Critical: 2`
- `Overall Risk: CRITICAL`

## What to Show in the Demo
- `data/attack_scenarios.yaml`
- `demo_targets/vulnerable_rag_agent/`
- `reports/demo_scan/scan_report.md`
- `reports/demo_scan/trajectory.json`
- `examples/demo_scan/`

## Key Explanation
The failure is intentional. The vulnerable RAG agent treats retrieved content as instructions instead of as untrusted data. The grader detects unsafe tool usage and exfiltration behavior to `attacker@example.com`. The `send_email` tool is mock-only, and `read_secret` returns only a fake demo secret, so the demo stays safe while still showing the security failure clearly.

## Limitations
- Not a production red-team platform.
- No real MCP integration.
- No LLM-as-judge yet.
- No cloud deployment.
- No benchmark adapters yet.

## Closing
This demonstrates an agentic security evaluator because `SecurityScanAgent` plans and runs scenarios, observes behavior, grades outcomes, and writes evidence that a developer can inspect.

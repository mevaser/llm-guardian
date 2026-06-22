# Demo Scan Sample Output

This directory contains deterministic sample output for the local demo scan.

Command used to generate the sample:

```bash
python -m llm_guardian.cli agent-scan --target demo-vulnerable-rag --output-dir reports/demo_scan
```

scan_report.md is the human-readable report.

trajectory.json is the machine-readable evidence log.

The sample artifacts include the `SecurityScanAgent` plan, execution trace, and adaptive probes.

No real emails are sent.

No real secrets are read.

# Demo Scan Sample Output

This directory contains deterministic sample output for the local demo scan.

Command used to generate the sample:

```bash
python -m llm_guardian.cli agent-scan --target demo-vulnerable-rag --output-dir reports/demo_scan
```

scan_report.md is the human-readable report.

trajectory.json is the machine-readable evidence log.

The sample artifacts include the `SecurityScanAgent` plan, execution trace, and adaptive probes.

The default scenario source is recorded as `data/attack_scenarios.yaml`, relative to the
repository root, so demo metadata does not include the local checkout path. Explicitly
supplied scenario file paths are recorded as provided.

No real emails are sent.

No real secrets are read.

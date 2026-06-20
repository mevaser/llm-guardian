# Test Strategy

## Rule
Unit tests must not call real LLM APIs.

## Unit Tests
- Attack library loading and schema validation.
- Target agent behavior.
- Deterministic evaluation.
- Severity-weighted scoring.
- JSON and Markdown report formatting.

## Integration Tests
- Run a full scan against a fake vulnerable target.
- Validate result counts, categories, evidence, and report schema.

## Demo Smoke Test
- Run scan with sample target.
- Generate Markdown report.
- Confirm Streamlit can load sample data.

## Required Commands
```bash
pytest
python -m llm_guardian.cli scan --target customer_support --offline
python -m llm_guardian.cli validate-report tmp_report.json
```

## Deterministic First
LLM-as-judge is optional and must be behind an interface. Tests use FakeLLMProvider.

## Verification Gate
Every task must end with:

```bash
./verify.sh
```

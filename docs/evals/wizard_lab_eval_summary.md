# Wizard Lab Agent Eval Harness Summary

## 1. Goal

This eval harness measures agent behavior over full trajectories, not only final success.

The autonomous agent loop is:

```text
observe → classify → plan → submit prompt → observe response → adapt → retry
```

## 2. System Under Test

The system under test is the autonomous attack agent navigating the Wizard Lab levels. The project evaluates the agent's ability to solve levels autonomously while utilizing hints correctly, mapping observed states, and avoiding duplicate efforts.

## 3. Evaluation Architecture

The eval loop operates as follows:

```text
task dataset → agent run → trajectory capture → grading/scoring → aggregate report
```

The harness is designed to compare strategies such as:

* `scripted`
* `autonomous`

* `scripted` is only a deterministic baseline / benchmark sanity check
* `scripted` must not be presented as an autonomous agent
* `autonomous` is the real planner/controller agent

### Core files

| File | Description |
|------|-------------|
| `eval_agent.py` | The core evaluation runner that executes strategies and captures trajectories. |
| `eval_cases.py` | Defines the golden dataset and structures the evaluation cases. |
| `eval_cases.json` | The serialized golden dataset containing all the test cases. |
| `tests/test_eval_agent.py` | Test suite ensuring the correctness of the evaluation harness logic. |
| `attack_agent.py` | The autonomous agent loop implementing observe → classify → plan → submit prompt → adapt. |
| `planner.py` | The hint-aware controller responsible for strategy selection and hint utilization. |
| `levels.py` | The definitions of target lab levels and their rules, representing the environment. |

## 4. Evaluation Dataset / Golden Set

The golden set consists of 20 eval cases, covering:
* core levels
* hint cases
* regression cases
* robustness cases

## 5. Metrics

The evaluation harness tracks the following metrics:
* solved rate
* average attempts
* duplicate prompt rate
* trajectory score
* Pass@k across repeated runs
* Success@attempt-k inside a run
* hint utilization
* failure taxonomy
* recommendations
* optional LLM judge scaffold, currently off by default

Explain Pass@k briefly:
```text
Pass@k estimates whether the agent can solve a task at least once across k repeated runs, which is useful because agent behavior is non-deterministic.
```

Explain Success@attempt-k briefly:
```text
Success@attempt-k measures whether the agent solves the task within the first k attempts inside a single run.
```

## 6. Baseline Results

The known baseline results are:
```text
scripted solved rate: 100%
autonomous solved rate before tuning: approximately 46%–48%
autonomous hint utilization before tuning: 0%
```

Interpretation:
* the lab is solvable
* the autonomous agent had partial capability
* the major failure was not using emitted hints

## 7. Hint Diagnostics

Improvements in hint diagnostics include:
* improved hint emission diagnostics
* case filtering with `--case-ids`
* emitted-vs-used visibility
* more specific failure taxonomy

## 8. Hint-Aware Controller Improvements

Improvements in the hint-aware controller include:
* hint type normalization
* forced tactic after detected hint
* tactic-to-hint matching
* generic fallback by hint type
* alias two-step flow
* richer decision telemetry

Telemetry fields tracked:
```text
hint_type
normalized_hint_type
forced_tactic
selected_tactic
hint_used
controller_override_used
planner_ignored_hint
alias_plan_active
alias_step
adaptation_reason
```

## 9. Before / After Summary

Before:
- targeted hint utilization: 0%

After:
- targeted hint utilization: 75%
- tool_hint used: YES
- alias_hint used: YES
- policy_hint used: YES
- transformation hint: still less stable

The transformation hint case can still fail when the agent prompt does not trigger the target's hint emission condition.

## 10. Current Limitations

* Groq 429 errors can affect long evals
* observed issue was token-per-minute pressure, not request-per-minute pressure
* full evals should use throttling
* long evals should reduce `max-attempts`, `runs`, and planner token usage
* transformation hint triggering still needs improvement
* LangSmith is not required for this branch; optional hosted tracing can be added later behind a feature flag

## 11. Reproduction Commands

### Full eval example

```powershell
$env:PYTHONPATH="src"
python -m llm_guardian.redteam.local_lab.eval_agent `
  --strategies scripted,autonomous `
  --cases src/llm_guardian/redteam/local_lab/eval_cases.json `
  --runs 3 `
  --max-attempts 8 `
  --delay-ms 0 `
  --export-failure-cases
```

### Targeted hint eval recommended for demo

```powershell
$env:PYTHONPATH="src"
python -m llm_guardian.redteam.local_lab.eval_agent `
  --strategies autonomous `
  --cases src/llm_guardian/redteam/local_lab/eval_cases.json `
  --case-ids hint_transformation,hint_alias_state,hint_tool_diagnostic,hint_policy_restriction `
  --runs 1 `
  --max-attempts 5 `
  --delay-ms 1500 `
  --export-failure-cases
```

### Tests

```powershell
$env:PYTHONPATH="src"
pytest tests/test_eval_agent.py -q
```

If pytest cache permissions fail on Windows, mention this optional command:

```powershell
$env:PYTHONPATH="src"
pytest tests/test_eval_agent.py -q -p no:cacheprovider
```

## 12. Presentation Interpretation

* This is not just a jailbreak demo.
* It is an agent evaluation system.
* It measures capability, consistency, trajectory quality, hint usage, and failure modes.
* The eval harness turns agent behavior into measurable engineering artifacts.
* The project includes local observability and can later integrate hosted tools such as LangSmith, but it does not depend on them.

## 13. Recommended Next Steps

1. Run one controlled targeted eval for final demo metrics.
2. Later: optional LangSmith tracing behind feature flags.
3. Later: reduce Groq rate-limit impact by shrinking planner context and avoiding LLM calls when controller fallback is enough.

## 14. Eval Reports UI

The Wizard Lab includes a local web UI to view these evaluation reports.

### Start the Server

```powershell
$env:PYTHONPATH="src"
python -m llm_guardian.redteam.local_lab.app
```

### Access the UI

Open your browser to:
[http://127.0.0.1:8000/evals](http://127.0.0.1:8000/evals)

This UI provides a read-only view of all eval runs generated using the evaluation commands above. It parses the `reports/redteam/wizard_lab/evals/` directory and shows aggregated metrics, case-level tables, markdown reports, and failure backlogs.

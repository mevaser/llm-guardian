# SecurityAgent Definition Of Done Review

This review checks the current repository state against the SecurityAgent milestone Definition of Done in `docs/SECURITY_AGENT_PLAN.md`.

Status legend:
- `Satisfied`: implemented and covered by current source/tests.
- `Partially satisfied`: present but with a noteworthy limitation.
- `Not satisfied`: missing or contradicted by current implementation.

## Checklist

| Criterion | Status | Evidence |
|---|---|---|
| `SecurityAgent` exists as a higher-level security testing orchestrator | Satisfied | `src/llm_guardian/security_agent/agent.py` defines `SecurityAgent` as the planning, execution, mutation, finding, and reporting coordinator. `tests/test_security_agent_agent.py` exercises the end-to-end orchestration loop. |
| Demo targets remain systems under test, not orchestrators | Satisfied | `src/llm_guardian/targets/customer_support.py`, `src/llm_guardian/targets/tool_agent.py`, `src/llm_guardian/targets/rag_agent.py`, and `src/llm_guardian/targets/memory_agent.py` remain local targets. `src/llm_guardian/security_agent/adapters.py` wraps them through `LocalTargetAdapter`. `tests/test_security_agent_agent.py` includes `test_security_agent_is_not_a_target_agent`. |
| Target profiling drives attack-category selection | Satisfied | `src/llm_guardian/security_agent/planner.py` derives categories from `TargetProfile.target_type`, `capabilities`, `risk_surfaces`, and allow-lists. `src/llm_guardian/cli.py` builds target-specific profiles for `agent-scan`. `tests/test_security_agent_planner.py` validates deterministic category selection for RAG, tool, memory, and generic chatbot profiles. |
| Attack attempts are recorded with history and mutation lineage | Satisfied | `src/llm_guardian/security_agent/models.py` defines `AttackAttempt` and `PromptMutation`. `src/llm_guardian/security_agent/agent.py` records initial attempts and mutated retries. `src/llm_guardian/security_agent/reporting.py` exports `attempt_history` and `prompt_mutations`. `tests/test_security_agent_agent.py` validates attempt indexes, mutation strategy, source prompt, and deterministic replay. |
| Retries are budgeted and bounded | Satisfied | `src/llm_guardian/security_agent/agent.py` enforces `max_total_attempts`, `max_attempts_per_attack`, and `max_mutations_per_attack`. `src/llm_guardian/security_agent/planner.py` carries the budget into `AttackPlan.budget`. `tests/test_security_agent_agent.py` and `tests/test_security_agent_cli.py` verify disabled mutation, bounded retries, and CLI budget plumbing. |
| Evaluation produces structured findings from one or more attempts | Satisfied | `src/llm_guardian/security_agent/executor.py` adapts attack metadata into `AttackCase` and uses `DeterministicEvaluator`. `src/llm_guardian/security_agent/findings.py` aggregates successful attempts into `SecurityFinding` records. `tests/test_security_agent_findings.py` and `tests/test_security_agent_agent.py` validate finding construction and aggregation behavior. |
| Reports include enough evidence to explain why a finding was created | Satisfied | `src/llm_guardian/security_agent/findings.py` builds `evidence_summary`, `successful_attempt_ids`, `mutation_strategies`, `source_prompts`, and `response_excerpt`. `src/llm_guardian/security_agent/reporting.py` includes findings, attempt history, prompt mutations, and summary metrics in JSON/Markdown output. `tests/test_security_agent_reporting.py` validates deterministic report content and required sections. |
| Baseline `ScanRunner` behavior remains available | Satisfied | `src/llm_guardian/runner/scan_runner.py` and `src/llm_guardian/runner/scan_service.py` remain intact. `src/llm_guardian/cli.py` keeps `scan` separate from `agent-scan`. `tests/test_security_agent_cli.py` includes `test_baseline_scan_command_behavior_remains_unchanged`. |
| Deterministic-first behavior remains the default | Satisfied | `src/llm_guardian/security_agent/agent.py`, `planner.py`, `mutator.py`, and `executor.py` use fixed selection and mutation order with no randomness. `src/llm_guardian/cli.py` defaults `agent-scan` to conservative deterministic settings, including `--max-mutations-per-attack 0`. `tests/test_security_agent_agent.py`, `tests/test_security_agent_planner.py`, `tests/test_security_agent_reporting.py`, and `tests/test_security_agent_cli.py` all assert deterministic repeatability. |
| Tests do not require real LLM APIs | Satisfied | `docs/TEST_STRATEGY.md` states that unit tests must not call real LLM APIs. The exercised SecurityAgent tests use local fakes and deterministic targets in `tests/test_security_agent_agent.py`, `tests/test_security_agent_executor.py`, and `tests/test_security_agent_cli.py`. No SecurityAgent path introduces network or provider calls. |
| Verification passes | Satisfied | The requested verification commands pass in the current repository state: `tests/test_security_agent_models.py`, `tests/test_security_agent_planner.py`, `tests/test_security_agent_adapters.py`, `tests/test_security_agent_executor.py`, `tests/test_security_agent_agent.py`, `tests/test_security_agent_mutator.py`, `tests/test_security_agent_findings.py`, `tests/test_security_agent_reporting.py`, `tests/test_security_agent_cli.py`, `python scripts/verify.py`, `./verify.sh`, and `git diff --check`. |

## Gaps Found

No blocking Definition of Done gaps were found in the current implementation.

Minor note:
- The repository does not currently expose a standalone `TargetProfiler` service. Target profiling still exists and drives planning through `TargetProfile` construction plus `AttackPlanner`, so this does not block the milestone Definition of Done.

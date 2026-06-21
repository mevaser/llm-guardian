# Security Agent Plan

## Executive Summary

LLM Guardian currently provides a deterministic baseline scanner that executes predefined attacks against local vulnerable demo targets and produces structured reports. That baseline is useful, but it is not yet an active red-team agent. The missing higher-level component is `SecurityAgent`: an orchestrator that receives a testing objective, profiles the target, selects attack categories, builds an attack plan, executes attempts, evaluates outcomes, mutates prompts after failures, retries within a controlled budget, records attempt history, and produces findings plus a report.

`SecurityAgent` is not a target. It is the active security testing agent for the product. The existing `CustomerSupportAgent`, `ToolAgent`, `RagAgent`, and `MemoryAgent` remain local vulnerable systems under test. `ScanRunner` remains the deterministic baseline scanner. A future `agent-scan` mode should introduce `SecurityAgent` above the current scan and target layers instead of turning it into another `TargetAgent`.

The design goal is to add agentic security testing without violating current project constraints: deterministic-first behavior, offline safety, no real third-party scanning, no autonomous exploitation, no real side effects, and no real LLM API dependency in tests.

## Terminology

### SecurityAgent

The active security tester and orchestrator. It owns planning, attempt execution, adaptation, retry control, and finding production.

### Target

The system being tested. In the current project, this is typically a local vulnerable demo agent or target adapter surface.

### Demo Targets

The local intentionally vulnerable systems under test. Today these include `CustomerSupportAgent`, `ToolAgent`, `RagAgent`, and `MemoryAgent`.

### ScanRunner

The existing deterministic baseline scanner that executes predefined attacks against targets using the current attack library and evaluator flow.

### agent-scan

A future agentic scan mode driven by `SecurityAgent`. This mode should be additive, not a replacement for the deterministic baseline.

### TargetAdapter

A stable integration layer that lets `SecurityAgent` interact with different target types through a common execution boundary without requiring the target itself to become the orchestrator.

### Attempt

One concrete attack execution by `SecurityAgent`, including the selected prompt, context, target response, evaluation outcome, and retry metadata.

### Finding

A structured security result produced from one or more attempts, with evidence, severity, and recommendation fields suitable for reports.

## Current Architecture Gap

The current architecture is centered on deterministic attack replay:

```text
User
  -> Streamlit UI / CLI
      -> ScanRunner
          -> AttackLibrary
          -> TargetAgent
          -> DeterministicEvaluator
          -> ReportGenerator
```

That model is strong for reproducible baseline scans, but it has clear limits:

- attack selection is predefined rather than adaptive
- prompt strategy does not improve based on failed attempts
- there is no explicit target profiling step
- retry behavior is not first-class
- attempt history is not modeled as an evolving search process
- finding generation is tied to deterministic per-case execution rather than a campaign-style orchestrator

This means LLM Guardian can currently answer, "Did these known attacks succeed?" but not yet, "How should an active security testing agent adapt its strategy against this target within safe, local, deterministic constraints?"

## Target Architecture Diagram

The future agentic architecture should be:

```text
User / CLI / UI
  -> SecurityAgent
      -> TargetProfiler
      -> AttackPlanner
      -> AttackExecutor
          -> TargetAdapter
              -> Demo target or other approved local target surface
      -> ResultEvaluator
      -> PromptMutator
      -> AttemptHistory
      -> FindingBuilder
      -> Report
```

Relationship to the existing baseline:

```text
Deterministic baseline:
User / CLI / UI
  -> ScanRunner
      -> AttackLibrary
      -> TargetAgent
      -> DeterministicEvaluator
      -> Report

Future agentic mode:
User / CLI / UI
  -> SecurityAgent
      -> TargetProfiler
      -> AttackPlanner
      -> AttackExecutor
      -> ResultEvaluator
      -> PromptMutator
      -> AttemptHistory
      -> FindingBuilder
      -> Report
```

The architectural rule is simple:

- `ScanRunner` remains the deterministic baseline scanner
- `SecurityAgent` becomes a higher-level orchestrator above baseline target execution
- demo targets remain systems under test
- `SecurityAgent` must not be modeled as another vulnerable target

## Core SecurityAgent Loop

The intended control loop is:

```text
security_test_started
  -> target_profile_created
  -> attack_plan_built
  -> attack_attempt_started
  -> target_invoked_via_adapter
  -> response_observed
  -> attempt_evaluated
  -> prompt_mutated_if_needed
  -> retry_or_stop_decision
  -> finding_created
  -> report_generated
```

Operationally, the loop should work like this:

1. Receive a `SecurityTestObjective` and target input.
2. Build or load a `TargetProfile`.
3. Select relevant attack categories and build an `AttackPlan`.
4. Execute the next `AttackAttempt` through `TargetAdapter`.
5. Observe response text and available trajectory data.
6. Evaluate success, failure, ambiguity, and severity.
7. If the attempt failed and budget remains, create a `PromptMutation`.
8. Retry with controlled limits and recorded history.
9. Aggregate evidence into findings.
10. Produce final structured results and reports.

The loop must remain bounded, inspectable, and deterministic by default.

## Proposed Models

These models are planning contracts for later implementation. They are not code and should not be treated as final schemas.

### TargetProfile

Purpose:
- describe the target being tested so attack planning can be targeted rather than generic

Suggested fields:
- `target_id`
- `target_name`
- `target_type`
- `interface_type`
- `capabilities`
- `known_attack_surfaces`
- `trust_boundaries`
- `available_telemetry`
- `safety_constraints`
- `notes`

Examples of information it may capture:
- whether the target uses tools
- whether the target uses retrieval
- whether the target has memory behavior
- whether the target exposes trajectory traces
- which attack categories are most relevant

### SecurityTestObjective

Purpose:
- represent the user-selected or system-generated testing objective for a scan

Suggested fields:
- `objective_id`
- `target_id`
- `goal_summary`
- `priority_categories`
- `max_attempts`
- `max_attempts_per_category`
- `time_budget`
- `severity_threshold`
- `offline_only`
- `notes`

Examples:
- test for tool misuse against a tool-using target
- test for RAG injection against a retrieval-backed target
- run a broad multi-category local red-team evaluation

### AttackPlan

Purpose:
- capture the current ordered plan that `SecurityAgent` intends to execute

Suggested fields:
- `plan_id`
- `objective_id`
- `target_profile_id`
- `selected_categories`
- `planned_attacks`
- `execution_order`
- `mutation_strategy`
- `stop_conditions`
- `budget_state`

Expected behavior:
- built from target profile plus objective
- updateable as new evidence arrives
- explicit about why specific categories were selected

### AttackAttempt

Purpose:
- record one concrete execution attempt against the target

Suggested fields:
- `attempt_id`
- `plan_id`
- `attack_id`
- `category`
- `prompt`
- `mutation_index`
- `target_input`
- `target_output`
- `trace_evidence`
- `evaluation_result`
- `success`
- `failure_reason`
- `started_at`
- `completed_at`

Expected use:
- become the core unit of attempt history
- preserve both prompt and evaluation context
- support retries without losing evidence lineage

### PromptMutation

Purpose:
- represent how `SecurityAgent` changed an attack prompt after an unsuccessful or ambiguous attempt

Suggested fields:
- `mutation_id`
- `attempt_id`
- `strategy_name`
- `source_prompt`
- `mutated_prompt`
- `rationale_summary`
- `expected_effect`
- `risk_flags`

Examples of mutation intent:
- increase specificity
- reframe as role-play or policy override pressure
- exploit observed target trust assumptions
- pivot from direct ask to multi-step escalation

### SecurityAgentResult

Purpose:
- represent the final output of a `SecurityAgent` campaign for a single target and objective

Suggested fields:
- `result_id`
- `objective_id`
- `target_profile`
- `attack_plan`
- `attempt_history`
- `findings`
- `summary_metrics`
- `report_artifacts`
- `status`
- `completed_at`

Expected use:
- serve as the source for JSON and Markdown reports
- preserve attempt-level evidence, not just final findings
- make agentic scans auditable and reproducible

## Attack Selection Strategy By Target Profile

`SecurityAgent` should not choose attacks uniformly. It should use `TargetProfile` to prioritize the most relevant categories and prompts.

### Tool-Oriented Target Profile

Examples:
- local demo targets with simulated tool actions

Prioritize:
- `tool_abuse`
- `jailbreak`
- `prompt_injection`

Why:
- the highest-value failure is unauthorized or unsafe tool selection

### Retrieval-Oriented Target Profile

Examples:
- local demo targets that consume untrusted retrieved context

Prioritize:
- `rag_injection`
- `prompt_injection`
- `jailbreak`

Why:
- the main risk is trust-boundary failure between retrieved content and higher-priority policy

### Memory-Oriented Target Profile

Examples:
- local demo targets with write/read memory behavior

Prioritize:
- `memory_poisoning`
- `jailbreak`

Why:
- the main risk is storing or recalling poisoned content as trusted state

### Prompt-Only Or Baseline Target Profile

Examples:
- direct prompt-response demo targets without tools or retrieval

Prioritize:
- `prompt_injection`
- `jailbreak`

Why:
- the attack surface is primarily instruction hierarchy and policy override pressure

### Mixed-Capability Target Profile

Examples:
- future targets with tools, retrieval, and memory

Prioritize:
- categories based on declared surfaces and available telemetry
- early attempts that cheaply reveal the dominant weakness
- follow-up attempts that exploit observed weak points

Selection rules should remain deterministic by default. A future optional planner can still produce structured, reviewable category choices.

## Prompt Mutation Strategy

Prompt mutation is the key feature that differentiates `SecurityAgent` from static replay scanning. Mutation should be controlled, explainable, and budgeted.

Mutation goals:

- adapt when a prompt fails cleanly
- exploit weak signals in the target response
- escalate gradually rather than jump immediately to extreme variants
- preserve evidence about what changed between attempts

Suggested mutation strategies:

### Reframing

Adjust the role or context:
- incident response framing
- audit request framing
- internal operator framing

### Specificity Increase

Add concrete target details or ask for a narrower action to reduce refusal generality.

### Authority Pressure

Claim higher urgency or approval signals to probe weak authorization handling.

### Indirect Escalation

Break a blocked request into smaller steps that may individually pass.

### Trust-Boundary Exploitation

Reuse cues from retrieval output, prior responses, or memory-like state to craft stronger follow-up prompts.

Mutation stop rules:

- stop when attempt budget is exhausted
- stop when the same mutation pattern fails repeatedly
- stop when the target already produced sufficient evidence
- stop when a prompt would exceed project safety boundaries

Every mutation must be recorded as structured history, not hidden implicit behavior.

## Relationship To Existing ScanRunner

`SecurityAgent` should extend the product without replacing the current deterministic baseline.

### What Stays True

- `ScanRunner` remains the baseline scanner
- predefined attack-library scans remain valuable for regression and CI
- deterministic evaluation remains the default grading path
- demo targets remain local vulnerable systems under test

### What Changes In Future agent-scan Mode

- attack selection becomes target-aware
- attempts can mutate after failures
- retries become explicit and budgeted
- findings may aggregate evidence across multiple attempts
- reports can include attempt history and mutation lineage

### Integration Options

Option A:
- `SecurityAgent` calls `TargetAdapter` directly and runs a separate orchestration path above existing targets

Option B:
- `SecurityAgent` reuses pieces of `ScanRunner` internally for execution or evaluation where that avoids duplication

Preferred direction:
- reuse stable deterministic components where practical
- avoid forcing `SecurityAgent` into the `TargetAgent` abstraction
- keep baseline scan mode and future agent-scan mode clearly distinct

## Safety Boundaries

`SecurityAgent` must preserve all existing project safety constraints.

Hard boundaries:

- no real third-party target scanning
- no browser automation
- no credential extraction
- no autonomous exploitation
- no real email sending
- no real ticket updates
- no real file export side effects
- no network-dependent unit tests
- no real LLM API dependence in unit tests

Additional agentic boundaries:

- attempt count must be explicitly budgeted
- mutation depth must be bounded
- target adapters must only expose approved local demo surfaces unless ownership and authorization are explicit
- evidence must remain inspectable and attributable to concrete attempts
- errors must be explicit and actionable, never silently suppressed

The system should simulate adversarial persistence, not enable uncontrolled autonomous behavior.

## Implementation Roadmap

Implementation should proceed in small vertical slices.

### Slice 1: Documentation And Terminology Alignment

Purpose:
- define `SecurityAgent` as orchestrator rather than target

Acceptance criteria:
- this plan exists
- terminology is consistent with existing architecture
- no source, test, attack data, or README changes are required

### Slice 2: Core Planning Models

Purpose:
- add the minimal models for objective, profile, plan, attempt, and result state

Acceptance criteria:
- models are deterministic and serializable
- no real LLM or network dependency is introduced

Tests to add:
- model validation tests
- serialization tests

### Slice 3: Target Profiling And Plan Construction

Purpose:
- infer relevant attack categories from target characteristics

Acceptance criteria:
- `TargetProfiler` produces stable `TargetProfile` outputs
- `AttackPlanner` selects categories deterministically

Tests to add:
- profile classification tests
- attack selection tests

### Slice 4: Controlled Attempt Execution

Purpose:
- execute one or more attempts through `TargetAdapter` with bounded budgets

Acceptance criteria:
- attempts are recorded with full history
- target invocation is separated from planning and mutation

Tests to add:
- attempt execution tests
- budget enforcement tests

### Slice 5: Prompt Mutation

Purpose:
- adapt prompts after failed or ambiguous attempts

Acceptance criteria:
- mutations are explicit and recorded
- retry logic respects stop conditions

Tests to add:
- mutation strategy tests
- retry-loop tests

### Slice 6: Finding Aggregation And Reporting

Purpose:
- convert multi-attempt evidence into findings and final reports

Acceptance criteria:
- reports summarize both findings and attempt history
- existing report formats remain stable or evolve additively

Tests to add:
- finding builder tests
- JSON and Markdown report tests

### Slice 7: CLI Or UI Entry For agent-scan

Purpose:
- expose the orchestrator through a new explicit mode without breaking baseline scanning

Acceptance criteria:
- `agent-scan` is clearly separated from baseline scan mode
- deterministic-first behavior remains the default

Tests to add:
- CLI or app integration tests

## Definition Of Done

The `SecurityAgent` milestone is complete only when all of the following are true:

- `SecurityAgent` exists as a higher-level security testing orchestrator
- demo targets remain systems under test, not orchestrators
- target profiling drives attack-category selection
- attack attempts are recorded with history and mutation lineage
- retries are budgeted and bounded
- evaluation produces structured findings from one or more attempts
- reports include enough evidence to explain why a finding was created
- baseline `ScanRunner` behavior remains available
- deterministic-first behavior remains the default
- tests do not require real LLM APIs
- verification passes

## Recommended Next Step

The next implementation slice should stay narrow: add the core planning models for `TargetProfile`, `SecurityTestObjective`, `AttackPlan`, `AttackAttempt`, `PromptMutation`, and `SecurityAgentResult`, without changing demo targets, attack data, or baseline scan behavior. That creates the minimum contract surface needed for future `agent-scan` work while preserving the current product architecture.

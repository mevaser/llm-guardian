# Agent Runtime Implementation Plan

## Executive Summary

LLM Guardian already provides a strong foundation for controlled red-team evaluation: an offline attack library, local deterministic targets, scan orchestration, deterministic evaluation, structured reports, a Streamlit dashboard, and per-finding trace data. The next milestone is to add an explicit local deterministic agent runtime so the project evaluates intentionally vulnerable demo agents as agents, not only as prompt-response functions.

This change turns LLM Guardian from a prompt scanner with target-specific trace fragments into an agent red-team evaluation harness with a shared runtime model. The runtime will make planning, policy decisions, simulated local tool use, simulated retrieval, simulated memory operations, observations, final responses, and trajectory evidence inspectable and repeatable. The first implementation milestone is a local deterministic agent runtime. The architecture must also support a future optional `LLMPlanner` without rewriting the scan runner, reports, or dashboard.

## Current Gap

The current execution model is:

```text
AttackLibrary
  -> ScanRunner
      -> TargetAgent.invoke(prompt)
          -> Evaluator
              -> Report
```

This architecture is useful for deterministic attack execution, but it is still centered on a single target invocation that returns one `TargetResponse`. Existing targets may attach trace events, yet those traces are target-specific artifacts rather than outputs of a shared explicit runtime loop.

This is not enough for an agent-focused project because it still has the following limitations:

- direct prompt-response behavior remains the main execution pattern
- planning visibility is limited and inconsistent across targets
- there is no explicit shared model for tool, retrieval, or memory actions
- policy decisions are not first-class runtime objects
- unsafe trajectories are difficult to evaluate consistently
- trajectory is mostly descriptive today rather than a full security evidence surface

The gap is most visible in the current compatibility boundary: `ScanRunner` calls `TargetAgent.invoke(prompt)`, then the evaluator grades the final text response against fixed indicators. That model can detect many failures, but it cannot yet evaluate agent behavior as a sequence of operational decisions.

## Target Architecture

The future architecture should be:

```text
AttackLibrary
  -> ScanRunner
      -> AgentTarget
          -> AgentRuntime
              -> Planner
              -> PolicyEngine
              -> SimulatedTool / SimulatedRetrieval / SimulatedMemory
              -> Observation
              -> FinalResponse
      -> Evaluator
      -> Report / Streamlit
```

Concise textual diagram:

```text
Attack case
  -> runtime-backed target
      -> planner decision
      -> policy decision
      -> action execution against simulated local surfaces
      -> observation handling
      -> final response
      -> trajectory evidence
  -> evaluator
  -> report and dashboard
```

The design goal is to evolve targets internally while preserving the existing external compatibility boundary during migration:

```text
TargetAgent.invoke(prompt) -> TargetResponse
```

That compatibility rule allows `ScanRunner`, report generation, JSON and Markdown exports, and the Streamlit dashboard to remain stable while targets gain a shared runtime under the hood. The first milestone must deliver a local deterministic agent runtime. A future optional real `LLMPlanner` should plug into the same runtime contracts so the rest of the system does not need a parallel execution path.

## Agent Definition For This Project

For LLM Guardian, an agent is a local deterministic or optionally future real-LLM-backed actor that:

- receives a task or prompt
- creates a structured decision
- optionally calls simulated local tools, retrieval, or memory surfaces
- receives observations from those simulated local surfaces
- produces a final response
- emits operational trace events
- can be intentionally vulnerable in controlled ways for red-team evaluation

An agent in this project is more than a text responder. It is a runtime participant with inspectable operational behavior. The runtime must expose what the agent did at the system level without logging hidden chain-of-thought.

## Runtime Loop

The intended runtime loop is:

```text
agent_started
  -> planner_decision
  -> policy_decision
  -> action_selected
  -> tool_called / retrieval_called / memory_written / memory_read
  -> observation_received
  -> final_response
  -> evaluation_completed
```

The deterministic runtime may execute one or more action-observation steps before producing a final response. The implementation should start simple and testable:

- initial runtime slices may allow a single planner decision plus one action
- later slices may support multiple sequential steps when needed by a target
- every step must remain deterministic by default

Trajectory is not only a log artifact. It is part of the security evidence. Unsafe tool calls, unsafe retrieval trust, unsafe memory writes, and unsafe policy decisions should eventually be evaluable from the trajectory itself in addition to the final response.

## Proposed Models

The following models are conceptual contracts for later implementation. They should be concrete enough to guide coding, but this document does not introduce implementation code.

### AgentDecision

Purpose:
- represent the planner's structured next-step decision

Suggested fields:
- `decision_id`
- `step_index`
- `goal_summary`
- `action_type`
- `action_name`
- `action_arguments`
- `reason_summary`
- `expected_outcome`
- `risk_flags`

Trace and report appearance:
- emitted in `planner_decision`
- summarized as an operational decision, not hidden reasoning
- report should show the selected action and high-level rationale summary when relevant

### ToolCall

Purpose:
- represent an attempted simulated local tool invocation

Suggested fields:
- `tool_name`
- `arguments`
- `authorization_context`
- `allowed_by_policy`
- `step_index`

Trace and report appearance:
- emitted in `action_selected` and `tool_called`
- report should show safe demo-only arguments and whether the call was authorized or unsafe

### ToolResult

Purpose:
- represent the output of a simulated local tool

Suggested fields:
- `tool_name`
- `status`
- `output_summary`
- `artifacts`
- `policy_flags`

Trace and report appearance:
- emitted via `observation_received`
- report should show the simulated result summary and any policy-relevant consequences

### RetrievalResult

Purpose:
- represent retrieved untrusted context used by a runtime-backed target

Suggested fields:
- `source_name`
- `query`
- `content`
- `trust_level`
- `metadata`

Trace and report appearance:
- emitted in `retrieval_called` and `observation_received`
- report should show the retrieved content summary and any trust or override issues

### MemoryOperation

Purpose:
- represent a write or read against simulated local memory

Suggested fields:
- `operation_type`
- `memory_key`
- `memory_value`
- `source`
- `validated`
- `step_index`

Trace and report appearance:
- emitted in `memory_written` or `memory_read`
- report should show what kind of memory action occurred and whether it involved untrusted content

### PolicyDecision

Purpose:
- represent the runtime guardrail decision that permits, blocks, or flags an action

Suggested fields:
- `policy_name`
- `decision`
- `reason_summary`
- `applies_to`
- `severity`
- `metadata`

Trace and report appearance:
- emitted in `policy_decision`
- report should show whether the runtime allowed, blocked, or flagged a risky step

### AgentRunResult

Purpose:
- represent the internal result of a full runtime-backed target execution

Suggested fields:
- `final_response`
- `trace_events`
- `tool_calls`
- `retrieval_results`
- `memory_operations`
- `policy_decisions`
- `task_success`
- `runtime_metadata`

Trace and report appearance:
- adapted into `TargetResponse` during migration
- becomes the internal source for trajectory-aware evaluation and richer reporting

Implementation note:
- the runtime should own `AgentRunResult`
- runtime-backed targets should adapt that internal result to the current external contract `TargetAgent.invoke(prompt) -> TargetResponse`
- this preserves compatibility while the runtime is introduced incrementally

## Planner Strategy

The runtime should support two planner modes.

### A. RuleBasedPlanner

Characteristics:

- deterministic
- default mode
- used for tests, CI, and stable demos
- maps attack prompts to known actions and known vulnerable behaviors
- produces structured `AgentDecision` outputs

Why it is required:

- repeatability is mandatory for grading and CI
- deterministic traces are necessary for stable report and dashboard behavior
- local demos must remain safe and offline-first
- the first runtime milestone should not depend on external providers

### B. Optional LLMPlanner

Characteristics:

- future experimental mode
- disabled by default
- may use Ollama or OpenAI later behind an interface
- must return a structured `AgentDecision`
- must not be used in unit tests
- must not be required for basic project execution

Design constraint:

- `LLMPlanner` support should be an architectural extension point from the start
- it must plug into the same runtime contracts as `RuleBasedPlanner`
- scan runner, reports, and dashboard should not require a rewrite when this planner is added

Deterministic-first is required for repeatability, CI stability, safe demos, and course-aligned grading.

## Simulated Tools And Surfaces

All action surfaces in this milestone must be simulated local surfaces only.

### SimulatedEmailTool

What it simulates:
- an outbound support email action

Example safe fake output:
- `Simulated email prepared for attacker@example.com with demo customer summary.`

Supported attack category:
- `tool_abuse`

Expected trace events:
- `action_selected`
- `policy_decision`
- `tool_called`
- `observation_received`

Must never happen:
- no real email delivery
- no SMTP usage
- no network access

### SimulatedExportTool

What it simulates:
- a support data export action

Example safe fake output:
- `Simulated export completed for demo customer list. No file was written.`

Supported attack category:
- `tool_abuse`

Expected trace events:
- `action_selected`
- `policy_decision`
- `tool_called`
- `observation_received`

Must never happen:
- no real file export
- no writing customer data to disk as a tool side effect
- no external system calls

### SimulatedTicketTool

What it simulates:
- ticket updates, notes, or bulk ticket actions

Example safe fake output:
- `Simulated ticket note accepted in demo mode. No real ticket state changed.`

Supported attack category:
- `tool_abuse`

Expected trace events:
- `action_selected`
- `policy_decision`
- `tool_called`
- `observation_received`

Must never happen:
- no real ticket update
- no real deletion
- no bulk destructive action

### SimulatedKnowledgeBaseTool

What it simulates:
- local retrieval of support notes or knowledge snippets

Example safe fake output:
- `Retrieved demo knowledge snippet marked as untrusted operational context.`

Supported attack category:
- `rag_injection`

Expected trace events:
- `action_selected`
- `retrieval_called`
- `observation_received`
- `policy_decision`

Must never happen:
- no network retrieval
- no external search
- no live document access

### SimulatedMemoryTool

What it simulates:
- local memory write and read behavior for demo agents

Example safe fake output:
- `Stored demo memory item in local deterministic runtime state.`

Supported attack category:
- `memory_poisoning`

Expected trace events:
- `action_selected`
- `memory_written` or `memory_read`
- `observation_received`
- `policy_decision`

Must never happen:
- no external memory service
- no real user data persistence
- no cross-run hidden state outside controlled test scope

Explicit safety rule for all simulated local surfaces:

- no real email
- no real file export
- no real ticket update
- no real deletion
- no network access
- no external system calls

## Agentic Target Mapping

### CustomerSupportAgent

Intended runtime behavior:
- remain the simpler direct prompt-injection baseline
- may stay less agentic than the other targets to preserve a clean baseline comparison

Relevant attack categories:
- `prompt_injection`
- `jailbreak`

Expected successful attacks:
- disclosure-style prompt injection attacks against intentionally vulnerable demo logic

Expected trace events:
- `agent_started`
- `planner_decision`
- `policy_decision`
- `final_response`

### ToolAgent

Intended runtime behavior:
- become a runtime-backed tool-using support agent
- planner selects tool actions
- policy engine permits or flags unsafe simulated local tool use
- runtime records tool result observations before final response

Relevant attack categories:
- `tool_abuse`
- `jailbreak`
- `prompt_injection`

Expected successful attacks:
- unauthorized outbound email
- unauthorized export
- unauthorized ticket write or bulk action

Expected trace events:
- `agent_started`
- `planner_decision`
- `policy_decision`
- `action_selected`
- `tool_called`
- `observation_received`
- `final_response`

### RagAgent

Intended runtime behavior:
- become a runtime-backed retrieval-using support agent
- planner selects retrieval
- runtime records retrieval result as an observation
- policy engine should eventually evaluate whether the agent trusted untrusted retrieval

Relevant attack categories:
- `rag_injection`
- `prompt_injection`
- `jailbreak`

Expected successful attacks:
- unsafe trust of retrieved override instructions
- disclosure based on untrusted retrieval content

Expected trace events:
- `agent_started`
- `planner_decision`
- `action_selected`
- `retrieval_called`
- `observation_received`
- `policy_decision`
- `final_response`

### MemoryAgent

Intended runtime behavior:
- become a runtime-backed memory-using agent with explicit write and read steps
- planner decides whether to store or recall content
- runtime records memory operations as first-class events

Relevant attack categories:
- `memory_poisoning`
- `jailbreak`

Expected successful attacks:
- unvalidated memory writes
- unsafe recall of poisoned memory

Expected trace events:
- `agent_started`
- `planner_decision`
- `action_selected`
- `memory_written`
- `memory_read`
- `observation_received`
- `policy_decision`
- `final_response`

## Attack Category To Agent Surface Mapping

### Prompt Injection

Surface:
- instruction hierarchy
- user input handling

Final response evaluation:
- did the response disclose protected content or obey injected instructions

Trajectory evaluation:
- did the planner or policy layer treat user text as higher priority than trusted instructions

### Jailbreak

Surface:
- policy override
- planner manipulation

Final response evaluation:
- did the response claim safeguards were disabled or behave as if policy was bypassed

Trajectory evaluation:
- did the runtime record unsafe policy decisions or planner decisions that accepted override framing

### Memory Poisoning

Surface:
- memory write and read operations

Final response evaluation:
- did the response repeat poisoned content as if it were trusted

Trajectory evaluation:
- did the runtime accept unsafe memory writes or reuse untrusted memory without validation

### Tool Abuse

Surface:
- unauthorized tool selection and execution

Final response evaluation:
- did the response claim a risky action succeeded

Trajectory evaluation:
- did the runtime select or permit an unauthorized simulated local tool call

### RAG Injection

Surface:
- untrusted retrieval observations

Final response evaluation:
- did the response obey or reflect malicious retrieved content

Trajectory evaluation:
- did the runtime trust untrusted retrieval content or allow it to override higher-priority policy

## Trace Event Taxonomy

All runtime-oriented trace events should use the following required fields:

- `event_type`
- `timestamp`
- `target_name`
- `attack_id`
- `message`
- `metadata`

Expected event types:

- `attack_started`
- `agent_started`
- `planner_decision`
- `policy_decision`
- `action_selected`
- `tool_called`
- `retrieval_called`
- `memory_written`
- `memory_read`
- `observation_received`
- `final_response`
- `target_responded`
- `evaluation_completed`
- `finding_created`

Trace rules:

- no hidden chain-of-thought should be logged
- use operational summaries only
- tool arguments should remain fake, demo-only, and safe
- metadata should be structured enough for future deterministic evaluation
- the same taxonomy should work for JSON reports, Markdown reports, and Streamlit views

## Trajectory Evaluation Plan

Future trajectory-aware metrics should include:

- `unauthorized_tool_call_count`
- `unsafe_policy_decision_count`
- `retrieval_trust_violation_count`
- `memory_poisoning_persistence`
- `tool_call_count`
- `retrieval_call_count`
- `memory_operation_count`
- `trajectory_safety_violation`
- `task_success`
- `final_response_success`

Metrics to implement early:

- `tool_call_count`
- `retrieval_call_count`
- `memory_operation_count`
- `unauthorized_tool_call_count`
- `unsafe_policy_decision_count`
- `trajectory_safety_violation`
- `final_response_success`

Metrics to implement later:

- `retrieval_trust_violation_count`
- `memory_poisoning_persistence`
- richer `task_success` criteria for multi-step flows

The evaluator should continue to grade final responses, but it should gradually become trajectory-aware so operational failures can be scored even when the final text is ambiguous.

## Streamlit And Reporting Implications

Reports and dashboard views should evolve in additive ways:

- show the final response clearly
- preserve evidence sections
- show the full trajectory
- highlight unsafe actions and unsafe policy decisions
- allow category-specific scans to remain intact
- keep JSON and Markdown export stable
- show agent steps in expandable findings in Streamlit

The key reporting change is conceptual: trajectory becomes security evidence, not only a debug artifact. Reports should explain what the agent did operationally, what surfaces it touched, and where unsafe behavior occurred.

## Implementation Roadmap

### Slice 1: Agent Runtime Core Models And Runtime Package

Purpose:
- introduce shared runtime concepts and deterministic execution loop

Files likely to change:
- `src/llm_guardian/models.py`
- new `src/llm_guardian/runtime/` package
- target integration points in `src/llm_guardian/targets/`

Acceptance criteria:
- runtime can execute a simple deterministic step loop
- runtime produces structured trajectory events
- external target contract remains `TargetAgent.invoke(prompt) -> TargetResponse`

Tests to add or update:
- runtime model validation tests
- deterministic runtime loop tests
- compatibility tests for target adaptation

Out of scope:
- real LLM planner integration
- report redesign

### Slice 2: Simulated Tools And Tool Registry

Purpose:
- add shared simulated local tools and registry logic

Files likely to change:
- new `src/llm_guardian/runtime/tools/` package
- target runtime integration points

Acceptance criteria:
- simulated local tool calls are deterministic and safe
- runtime emits tool-related trajectory events consistently

Tests to add or update:
- simulated tool behavior tests
- no-side-effect regression tests

Out of scope:
- retrieval and memory target refactors

### Slice 3: Refactor ToolAgent To Runtime-Backed Tool-Using Support Agent Behavior

Purpose:
- move `ToolAgent` from prompt matching into runtime-backed tool selection

Files likely to change:
- `src/llm_guardian/targets/tool_agent.py`
- runtime planner and tool integration
- tool agent tests and scan tests

Acceptance criteria:
- `ToolAgent` shows explicit planner, policy, tool, observation, and final response trajectory
- tool-abuse attacks remain detectable

Tests to add or update:
- tool agent trajectory tests
- scan runner integration tests for tool abuse

Out of scope:
- retrieval runtime behavior
- memory runtime behavior

### Slice 4: Refactor RagAgent To Runtime-Backed RagSupportAgent Behavior

Purpose:
- model retrieval as an explicit runtime action with observable trust boundaries

Files likely to change:
- `src/llm_guardian/targets/rag_agent.py`
- runtime retrieval surface code
- evaluator tests as needed

Acceptance criteria:
- `RagAgent` emits explicit retrieval and observation steps
- malicious retrieved content is visible in trace evidence

Tests to add or update:
- retrieval trajectory tests
- rag injection scan tests

Out of scope:
- memory poisoning runtime behavior

### Slice 5: Refactor MemoryAgent To Runtime-Backed MemoryAgent Behavior

Purpose:
- make memory writes and reads explicit runtime operations

Files likely to change:
- `src/llm_guardian/targets/memory_agent.py`
- runtime memory surface code
- memory agent tests and scan tests

Acceptance criteria:
- `MemoryAgent` emits explicit write and read trajectory events
- memory poisoning persistence becomes observable

Tests to add or update:
- memory operation tests
- follow-up prompt integration tests

Out of scope:
- optional LLM planner support

### Slice 6: Trajectory-Aware Evaluator And Report Enhancements

Purpose:
- extend evaluation and reporting from final-text evidence to trajectory-aware evidence

Files likely to change:
- `src/llm_guardian/evaluators/deterministic.py`
- `src/llm_guardian/reports/generator.py`
- `src/llm_guardian/app/streamlit_app.py`

Acceptance criteria:
- evaluator can score selected trajectory violations
- reports and dashboard highlight unsafe runtime steps
- existing export formats remain stable

Tests to add or update:
- evaluator metric tests
- JSON and Markdown report tests
- Streamlit rendering tests

Out of scope:
- external provider dependency

### Slice 7: Optional LLM Planner Adapter Behind An Experimental Flag

Purpose:
- add an optional planner that uses a real provider through stable runtime contracts

Files likely to change:
- new planner adapter code in `src/llm_guardian/runtime/`
- provider integration points
- configuration surfaces

Acceptance criteria:
- `LLMPlanner` is explicitly opt-in
- deterministic mode remains default
- unit tests do not depend on real LLM calls

Tests to add or update:
- configuration and interface tests
- provider mocking tests

Out of scope:
- making LLM mode mandatory for demos or CI

### Slice 8: README And Demo Polish

Purpose:
- document the runtime-backed agent model and improve demo clarity

Files likely to change:
- `README.md`
- demo and usage docs

Acceptance criteria:
- user-facing docs explain deterministic and optional experimental modes
- demo flow highlights trajectory evidence

Tests to add or update:
- none unless documentation validation exists

Out of scope:
- runtime architecture changes

## Safety And Scope Constraints

The runtime milestone must preserve the existing project safety boundaries:

- local deterministic default
- no real external side effects
- no real third-party scanning
- no real secrets
- no real customer data
- no real LLM calls by default
- optional `LLMPlanner` only later and behind explicit configuration
- no autonomous exploitation

All intentionally vulnerable demo behavior must remain controlled, local, inspectable, and repeatable.

## Definition Of Done For The Agent Runtime Milestone

The milestone is complete only when all of the following are true:

- `ToolAgent` has explicit planner, tool, observation, and final response trajectory
- `RagAgent` has explicit planner, retrieval, observation, and final response trajectory
- `MemoryAgent` has explicit memory write and read trajectory
- reports include agent trajectory
- Streamlit displays trajectory clearly
- CLI scans still work
- attack library still validates
- `python scripts/verify.py` passes
- no real side effects occur
- deterministic mode remains default
- optional LLM mode is not required for tests

## Risks And Mitigations

### Risk: Overengineering The Runtime Too Early

Mitigation:
- implement in small vertical slices
- start with a minimal deterministic loop and only the required runtime models

### Risk: Confusing Deterministic Agents With Real LLM Agents

Mitigation:
- use precise terminology such as local deterministic agent runtime and intentionally vulnerable demo agents
- document that deterministic mode is the primary test and CI path

### Risk: Unstable LLM-Backed Tests

Mitigation:
- keep `LLMPlanner` optional and disabled by default
- forbid real LLM dependence in unit tests

### Risk: Unsafe Tool Design

Mitigation:
- keep all tools simulated and local
- explicitly prohibit network access, real exports, real email, deletion, and external system calls

### Risk: Too Much Trace Noise

Mitigation:
- log operational summaries only
- standardize event taxonomy and metadata
- treat trajectory as evidence, not as exhaustive internal narration

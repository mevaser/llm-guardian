# Security Scope

## Purpose
LLM Guardian is an evaluation harness for controlled, local security testing of intentionally vulnerable LLM target agents.

## Authorized Targets Only
- Only scan local target agents created inside this repository.
- Do not test real third-party systems.
- Do not include instructions for attacking real third-party systems.
- Any future external target mode must require explicit ownership or written authorization.

## Simulated Data and Tools
- Use fake secrets, fake customers, fake tools, and fake memory only.
- All tool actions must be simulated.
- No real email, file deletion, payment, or external API side effects are allowed in the MVP.

## Prohibited Behavior
- No credential extraction.
- No autonomous exploitation.
- No real destructive tools.
- No browser automation in the MVP.
- No scanning of systems outside this repository.

## Reporting Language
Reports should frame findings as controlled evaluation results, not as proof of compromise.

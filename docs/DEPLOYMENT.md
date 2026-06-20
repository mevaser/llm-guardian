# Deployment

## Deployment Stages
| Stage | Deployment | Reason |
|---|---|---|
| MVP | Local plus Streamlit | Fastest path with the lowest risk. |
| Course demo | Streamlit Cloud | Suitable for a live link with minimal DevOps. |
| Portfolio plus | Docker plus Cloud Run | More production-style while still manageable. |
| Later SaaS | FastAPI, Cloud Run, database, and auth | Only after the course MVP is stable. |

## Initial Repository State
No deployment artifact is included yet. Do not add Docker, Cloud Run, or Streamlit deployment files until the local MVP works and `./verify.sh` passes.

## Deployment Rules
- Do not deploy code that calls real LLM APIs from tests.
- Do not include real secrets in repository files.
- Use environment variables for optional providers.
- Keep external target evaluation disabled unless explicit authorization controls exist.

## Future Environment Variables
See `.env.example` for documented local settings and optional provider placeholders.

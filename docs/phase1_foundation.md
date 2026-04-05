# Phase 1: Project Foundation

This phase delivers the base platform wiring required before feature vertical slices.

## Completed items
- Repository structure in place: `frontend/`, `backend/`, `docs/`, `infra/`.
- Dockerfiles and `infra/docker-compose.yml` for frontend/backend/worker/beat/postgres/redis.
- Backend app skeleton with centralized API router and health endpoints.
- Frontend app skeleton with backend health/readiness checks.
- PostgreSQL and Redis wiring through env-driven configuration.
- Environment configuration template at `.env.example` and compose `env_file` wiring.
- Service health checks in compose for all runtime containers.

## Phase 1 acceptance checks
- Backend responds on `/`, `/health`, `/health/ready`.
- Frontend can call backend health endpoints.
- `docker compose up --build` from `infra/` boots all containers.

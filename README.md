# FortiWeb Configuration and Maturity Assessment Platform

This repository is currently aligned to **Phase 1: Project foundation**.

## Repository structure
- `frontend/` – React + TypeScript skeleton
- `backend/` – FastAPI skeleton and modular backend foundation
- `docs/` – architecture and phase docs
- `infra/` – Dockerfiles and docker-compose

## Phase 1 scope delivered
- Initialize repo structure
- Add Dockerfiles and docker-compose
- Add backend app skeleton
- Add frontend app skeleton
- Add Postgres and Redis wiring
- Add environment configuration
- Add health checks

See `docs/phase1_foundation.md` for checklist and acceptance criteria.

## Quick start
1. Copy env template:
   ```bash
   cp .env.example .env
   ```
2. Start stack:
   ```bash
   cd infra
   docker compose up --build
   ```

## Foundation endpoints
- `GET /`
- `GET /health`
- `GET /health/ready`

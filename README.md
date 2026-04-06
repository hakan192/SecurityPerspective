# Security Perspective

Phase 1 foundation for a containerized security assessment platform:

- **Backend**: FastAPI
- **Frontend**: React (Vite)
- **Database**: PostgreSQL
- **Queue/Scheduler**: Redis + Celery
- **Auth (planned integration)**: LDAP
- **Reporting (foundation placeholders)**: PDF from HTML templates, CSV/Excel exports

## Phase 1 delivered

- Repository structure initialized for backend + frontend.
- Dockerfiles for backend and frontend.
- Docker Compose stack with PostgreSQL, Redis, FastAPI, Celery worker, and React frontend.
- Environment configuration template (`.env.example`).
- Backend skeleton with health endpoints.
- Existing FortiWeb snapshot, parsing, and maturity-scoring APIs retained as starter capability.

## Services

```bash
docker compose up --build
```

- Backend API: http://localhost:8000
- API docs: http://localhost:8000/docs
- Frontend: http://localhost:5173
- PostgreSQL (host access): localhost:5433

## Health checks

- `GET /health/live` — process liveness
- `GET /health/ready` — readiness (database + redis)

## Celery worker

- Worker service runs: `celery -A app.tasks worker --loglevel=info`
- Async collection endpoint queues job: `POST /collect/async`

## Environment

Copy values from `.env.example` and adjust for your environment.

## Notes

- LDAP auth wiring is added as a backend skeleton helper (`ldap_authenticate`) and not yet connected to login/session middleware.
- Reporting helpers (`app/reporting.py`) are placeholders for later PDF and tabular export implementation.

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
cd /path/to/SecurityPerspective
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

## Local admin login (Phase 1)

- Frontend starts with a login screen at `http://localhost:5173`.
- Backend auth endpoint: `POST /auth/login`.
- Default local admin credentials are configured via:
  - `LOCAL_ADMIN_USERNAME` (default `admin`)
  - `LOCAL_ADMIN_PASSWORD` (default `admin123!`)
- For local test safety, login accepts the default pair (`admin` / `admin123!`) even if env values are missing.
- After login, frontend displays seeded test `Server_Policy` data (IP + hostnames).

## Test server policy data

- API endpoint: `GET /server-policies`
- Table name in PostgreSQL: `\"Server_Policy\"`
- Seeded sample rows are created on startup for development/testing.

## Exchange rate test integration

- Source API: `https://open.er-api.com/v6/latest/USD`
- Collect endpoint: `POST /exchange-rates/collect`
- View latest normalized rates: `GET /exchange-rates/latest`
- View raw snapshots: `GET /exchange-rates/snapshots`
- Frontend dashboard shows exchange rates after login and allows collecting latest data.

## Notes

- LDAP auth wiring is added as a backend skeleton helper (`ldap_authenticate`) and not yet connected to login/session middleware.
- Reporting helpers (`app/reporting.py`) are placeholders for later PDF and tabular export implementation.

## Troubleshooting

- If login shows `Failed to fetch`, ensure backend is running and CORS origins include your frontend URL via `CORS_ALLOW_ORIGINS`.
- If frontend is opened via public IP (example `http://100.54.91.32:5173`), API base now auto-resolves to that host (`http://<host>:8000`) and CORS regex can allow dynamic origins via `CORS_ALLOW_ORIGIN_REGEX`.
- If `docker compose ps db` shows `no configuration file provided`, run the command from the project directory or use:
  - `docker compose -f /home/ubuntu/SecurityPerspective/docker-compose.yml ps db`

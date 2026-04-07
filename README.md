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
- Docker Compose stack with PostgreSQL, Redis, FastAPI, Celery worker, React frontend, and Nginx reverse proxy.
- Environment configuration template (`.env.example`).
- Backend skeleton with health endpoints.
- Existing FortiWeb snapshot, parsing, and maturity-scoring APIs retained as starter capability.

## Services

```bash
cd /path/to/SecurityPerspective
docker compose up --build
```

- Nginx gateway (frontend + API): http://localhost
- Backend API via Nginx: http://localhost/api
- API docs via Nginx: http://localhost/api/docs
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

- Frontend starts with a login screen at `http://localhost` (served through Nginx).
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

## FortiWeb server-policy integration

- WAF base URL default: `https://3.236.139.71:8443`
- WAF endpoint: `/api/v2.0/cmdb/server-policy/policy`
- Auth header used for FortiWeb calls: `Authorization: <FORTIWEB_TOKEN>` (raw value, no `Bearer` prefix)
- Collect endpoint: `POST /fortiweb/server-policy/collect`
- View latest collected raw JSON: `GET /fortiweb/server-policy/latest`
- Frontend dashboard includes “Collect from WAF” and renders the raw JSON response after login.

## Frontend layout (Phase 1 refresh)

- Top-left: platform name **SecurityPerspective**
- Top-right: profile card with logged-in user and logout
- Collapsible left sidebar with:
  - `WAF Configuration`
  - `Maturity Level`
  - `⚙ Platform Settings` button at bottom
- When `WAF Configuration` tab is active, the main panel displays the latest WAF API response JSON.
- Dark-blue executive dashboard style for maturity view includes:
  - overview cards
  - maturity trend block
  - recent findings panel
  - configuration source status blocks
- Exact logo file path used by GUI: `frontend/public/branding/securityperspective-logo.png`
- New post-login default view is **Search** page:
  - active search bar with autofocus
  - top-right clickable SecurityPerspective logo to reload/return to Search page
  - search runs against latest loaded WAF response content

## Notes

- LDAP auth wiring is added as a backend skeleton helper (`ldap_authenticate`) and not yet connected to login/session middleware.
- Reporting helpers (`app/reporting.py`) are placeholders for later PDF and tabular export implementation.

## Troubleshooting

- If login shows `Failed to fetch`, ensure the `nginx`, `frontend`, and `backend` services are healthy (`docker compose ps`) and that frontend requests are using `/api` through Nginx.
- If frontend is opened via public IP (example `http://100.54.91.32`), ensure that IP resolves to the Nginx service and that `/api` routes are reachable.
- If `docker compose ps db` shows `no configuration file provided`, run the command from the project directory or use:
  - `docker compose -f /home/ubuntu/SecurityPerspective/docker-compose.yml ps db`

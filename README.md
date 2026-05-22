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
- Docker Compose stack with PostgreSQL, Redis, FastAPI, Celery worker, React frontend, and Nginx gateway.
- Environment variables are optional; sane defaults are built in for local startup.
- Backend skeleton with health endpoints.
- Existing FortiWeb snapshot, parsing, and maturity-scoring APIs retained as starter capability.

## Services

```bash
cd /path/to/SecurityPerspective
docker compose up --build
```

- Nginx entrypoint (frontend + API proxy): http://localhost (redirects to HTTPS)
- Nginx HTTPS entrypoint (frontend + API proxy): https://localhost
- Backend API (direct): http://localhost:8000
- API docs (direct): http://localhost:8000/docs
- API docs via Nginx: http://localhost/api/docs
- PostgreSQL (host access): localhost:5433


## HTTPS with Nginx

Nginx is configured for HTTPS and listens on port `443` in Docker Compose.

Before running `docker compose up --build`, place certificate files in `certs/`:

- `certs/tls.crt` (PEM certificate chain)
- `certs/tls.key` (PEM private key)

These files are baked into the Nginx image during build, so HTTPS is available as soon as the container starts.

## Health checks

- `GET /health/live` — process liveness
- `GET /health/ready` — readiness (database + redis)

## Celery worker

- Worker service runs: `celery -A app.tasks worker --loglevel=info`
- Async collection endpoint queues job: `POST /collect/async`

## Environment

You can run the app without a predefined env file.  
If needed, create a local `.env` to override defaults for your environment.

## Local admin login (Phase 1)

- Frontend starts with a login screen at `http://localhost` (Nginx entrypoint).
- Backend auth endpoint: `POST /auth/login`.
- Default local admin credentials are configured via:
  - `LOCAL_ADMIN_USERNAME` (default `admin`)
  - `LOCAL_ADMIN_PASSWORD` (default `admin123!`)
- For local test safety, login accepts the default pair (`admin` / `admin123!`) even if env values are missing.

## FortiWeb server-policy integration

- WAF base URL default: `https://3.236.139.71:443`
- WAF endpoint: `/api/v2.0/cmdb/server-policy/policy`
- Auth header used for FortiWeb calls: `Authorization: <FORTIWEB_TOKEN>` (raw value, no `Bearer` prefix)
- Collect endpoint: `POST /fortiweb/server-policy/collect`
- View latest collected raw JSON: `GET /fortiweb/server-policy/latest`
- Frontend dashboard includes “Collect from WAF” and renders the raw JSON response after login.
- In Docker Compose, frontend API requests are routed through Nginx at `/api/*` to backend service port `8000`.

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

- If login shows `Failed to fetch`, ensure backend is running and CORS origins include your frontend URL via `CORS_ALLOW_ORIGINS`.
- If frontend is opened via public IP (example `http://100.54.91.32:5173`), API base now auto-resolves to that host (`http://<host>:8000`) and CORS regex can allow dynamic origins via `CORS_ALLOW_ORIGIN_REGEX`.
- If `docker compose ps db` shows `no configuration file provided`, run the command from the project directory or use:
  - `docker compose -f /home/ubuntu/SecurityPerspective/docker-compose.yml ps db`

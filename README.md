# SecurityPerspective

SecurityPerspective is a **containerized, multi-service** application for FortiWeb configuration collection, parsing, maturity scoring, and stakeholder reporting.

## Architecture

The solution is split into five containers:

1. **Frontend container (React + Nginx static hosting)**
   - Dashboard view for snapshots, scorecards, and queue state.
2. **Backend API container (FastAPI)**
   - FortiWeb integration trigger APIs
   - Raw/parsed/assessment retrieval APIs
   - Reporting APIs
3. **Database container (PostgreSQL)**
   - Raw payload snapshots (`raw_snapshots`)
   - Normalized parsed controls (`parsed_controls`)
   - Assessment outputs (`assessments`)
   - Background jobs (`jobs`)
4. **Worker container (Python background processor)**
   - Polls queued jobs
   - Pulls FortiWeb config
   - Parses + scores + persists data
5. **Reverse proxy container (Nginx)**
   - TLS termination
   - Routes `/api/*` to backend and `/` to frontend

## Run with Docker Compose

```bash
# 1) create local certs expected by reverse proxy
mkdir -p data/certs
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout data/certs/tls.key \
  -out data/certs/tls.crt \
  -subj "/CN=localhost"

# 2) start stack
docker compose up --build
```

Access app at:
- https://localhost (frontend through reverse proxy)
- https://localhost/api/health (backend health)

> Note: default users are in `docker-compose.yml` under `APP_USERS_JSON`.

## Core API Endpoints

- `POST /api/collect` — queue a collection job (admin/analyst)
- `GET /api/jobs/{job_id}` — inspect job state
- `GET /api/snapshots` — list snapshots
- `GET /api/snapshots/{snapshot_id}` — raw + normalized controls
- `GET /api/assessments/{snapshot_id}` — maturity result for snapshot
- `GET /api/reports/{snapshot_id}` — downloadable report payload
- `GET /api/dashboard` — summary for scorecards and dashboard widgets

All endpoints use HTTP Basic authentication and role-based authorization.

## Baseline and Scoring

Baseline controls and maturity thresholds are defined in:

- `backend/app/baseline.json`

You can customize controls/categories/weights/maturity bands there.

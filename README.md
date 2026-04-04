# SecurityPerspective

Containerized FortiWeb configuration maturity platform.

## Stack
- Frontend: React + Vite
- Backend: FastAPI
- Database: PostgreSQL
- Queue + workers: Redis + Celery worker + Celery Beat
- Reverse proxy: Nginx
- Authentication source: LDAP/LDAPS (via `ldap3` bind)

## Core capabilities implemented
1. **FortiWeb API integration**
   - `POST /api/v1/fortiweb/snapshots` calls FortiWeb API and stores raw response snapshots.
   - Celery Beat triggers periodic collection (`collect_and_parse_snapshot`).
2. **Historical storage**
   - Every collection is persisted as a timestamped `fortiweb_snapshots` record.
3. **Parsing/extraction**
   - Raw API payload is parsed into normalized `parsed_config_items` records.
4. **Visibility in UI**
   - React UI shows snapshot list and raw JSON view.
5. **Maturity assessment**
   - Parsed data is scored against baseline controls with per-control/category/overall outputs and maturity level.
6. **Analysis/reporting base**
   - Dashboard includes score cards and category pie visualization.
7. **Stakeholder access model**
   - LDAP login endpoint provisions app user with role (`admin` / `analyst` / `stakeholder`) for RBAC extension.

## Run with Docker
```bash
cp .env.example .env
docker compose up --build
```

- App URL: `http://localhost`
- API health: `http://localhost/healthz`

## Important API endpoints
- `POST /api/v1/auth/login`
- `POST /api/v1/fortiweb/snapshots`
- `GET /api/v1/fortiweb/snapshots`
- `GET /api/v1/fortiweb/parsed/{snapshot_id}`
- `POST /api/v1/analysis/assess/{snapshot_id}`
- `GET /api/v1/analysis/assess/{snapshot_id}`

## Notes
- LDAP is configured for bind-auth flow. In production, switch to `ldaps://` and trusted CA.
- Baseline controls are seeded on backend startup and can be moved to migrations/admin UI later.
- Report export/sharing endpoints can be added on top of `maturity_assessments` data.

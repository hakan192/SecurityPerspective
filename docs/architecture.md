# Architecture

## Containers
- `frontend`: React + TypeScript UI.
- `backend`: FastAPI modular monolith with `/health` and `/health/ready`.
- `worker`: Celery worker for collection, parsing, scoring, and reporting jobs.
- `beat`: Celery Beat scheduler for periodic ingestion scheduling.
- `postgres`: system of record.
- `redis`: queue backend + cache.

## Backend module map
- `auth`: local RBAC auth and token issuance; designed for OIDC adapter extension.
- `fortiweb_integration`: API client and retrieval contracts.
- `snapshots`: connector management and snapshot API.
- `parsing`: normalization rules and parsed evidence materialization.
- `baseline`: data-driven controls and expectations.
- `scoring`: weighted control/category/overall maturity scoring using DB thresholds.
- `reporting`: async report jobs and CSV/PDF artifact generation.
- `audit`: immutable audit event stream for critical actions.

## Traceability
`Snapshot -> RawArtifact(JSONB payload+meta) -> ParsedRecord(raw_artifact_id) -> AssessmentControl(parsed_record_id) -> Assessment`.

## Idempotency
- Ingestion computes hourly dedupe key and enforces unique `(connector_id, dedupe_key)`.

## Data-driven maturity
- Baselines and weights: `baseline_controls` table.
- Maturity thresholds: `maturity_thresholds` table (seeded per baseline version).

## Security
- Sensitive operations require backend role checks (`require_roles`), not frontend-only hiding.
- Report jobs enforce ownership/admin access checks on status and download.

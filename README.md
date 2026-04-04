# SecurityPerspective

Containerized starter stack for FortiWeb configuration collection and maturity assessment.

## Architecture

- **Nginx**: entrypoint and reverse proxy
- **React (Vite)**: web frontend
- **FastAPI**: API and orchestration endpoints
- **Celery Worker**: background FortiWeb collection tasks
- **Celery Beat**: scheduled FortiWeb collection tasks
- **PostgreSQL**: data persistence (raw, parsed, scores)
- **Redis**: queue broker/result backend

## Quick start

1. Create env file:

```bash
cp .env.example .env
```

2. Build and start:

```bash
docker compose up --build
```

3. Open app:
- http://localhost

4. Health check:
- `GET http://localhost/api/health`

5. Trigger collection:
- `POST http://localhost/api/fortiweb/collect`

## Notes

- Current worker task is a placeholder used to validate queue wiring.
- Extend `backend/app/tasks.py` with real FortiWeb API calls and database writes.

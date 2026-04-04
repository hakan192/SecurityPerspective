from fastapi import FastAPI

from .tasks import collect_fortiweb_config

app = FastAPI(title="SecurityPerspective API", version="0.1.0")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/fortiweb/collect")
def trigger_collection() -> dict:
    task = collect_fortiweb_config.delay()
    return {"task_id": task.id, "state": "queued"}

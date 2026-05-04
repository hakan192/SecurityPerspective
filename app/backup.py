import logging
import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

from sqlalchemy.engine import make_url

from app.config import settings


BACKUP_DIR = Path("backups")
logger = logging.getLogger(__name__)

def _build_unique_backup_path(database_name: str, timestamp: str) -> Path:
    base_name = f"{database_name}_backup_{timestamp}"
    candidate = BACKUP_DIR / f"{base_name}.sql"
    suffix = 1
    while candidate.exists():
        candidate = BACKUP_DIR / f"{base_name}_{suffix}.sql"
        suffix += 1
    return candidate


def backup_database() -> Path | None:
    """Create a readable SQL backup of the configured PostgreSQL database."""
    url = make_url(settings.database_url)
    if not url.drivername.startswith("postgresql"):
        raise RuntimeError("Database backups are only supported for PostgreSQL")

    timestamp = datetime.utcnow().strftime("%d_%m_%y_%H")
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    backup_path = _build_unique_backup_path(url.database or "postgres", timestamp)

    env = os.environ.copy()
    if url.password:
        env["PGPASSWORD"] = url.password

    cmd = [
        "pg_dump",
        "-h",
        url.host or "localhost",
        "-p",
        str(url.port or 5432),
        "-U",
        url.username or "postgres",
        "-d",
        url.database or "postgres",
        "-F",
        "p",
        "--create",
        "--inserts",
        "--column-inserts",
        "-f",
        str(backup_path),
    ]
    if shutil.which("pg_dump") is None:
        logger.warning("Skipping DB backup: pg_dump is not installed in runtime container")
        return None

    try:
        subprocess.run(cmd, check=True, env=env)
        return backup_path
    except subprocess.CalledProcessError as exc:
        logger.warning("DB backup command failed; continuing collection without blocking: %s", exc)
        return None

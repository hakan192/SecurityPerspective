import os
import subprocess
from datetime import datetime
from pathlib import Path

from sqlalchemy.engine import make_url

from app.config import settings


BACKUP_DIR = Path("backups")


def backup_database() -> Path:
    """Create a readable SQL backup of the configured PostgreSQL database."""
    url = make_url(settings.database_url)
    if not url.drivername.startswith("postgresql"):
        raise RuntimeError("Database backups are only supported for PostgreSQL")

    timestamp = datetime.utcnow().strftime("%d_%m_%y_%H")
    backup_name = f"{url.database}_backup_{timestamp}.sql"
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    backup_path = BACKUP_DIR / backup_name

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
        "-f",
        str(backup_path),
    ]
    subprocess.run(cmd, check=True, env=env)
    return backup_path

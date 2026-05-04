from __future__ import annotations

import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from app.config import settings


def backup_database() -> str:
    backup_dir = Path("backups")
    backup_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%d_%m_%y_%H_%M_%S")
    backup_file = backup_dir / f"security_perspective_backup_{timestamp}.sql"

    parsed = urlparse(settings.database_url.replace("+psycopg2", ""))
    command = [
        "pg_dump",
        "--format=plain",
        "--clean",
        "--if-exists",
        "--no-owner",
        "--no-privileges",
        "--file",
        str(backup_file),
        parsed.geturl(),
    ]

    env = os.environ.copy()
    if parsed.password:
        env["PGPASSWORD"] = parsed.password

    subprocess.run(command, check=True, env=env, capture_output=True, text=True)
    return str(backup_file)

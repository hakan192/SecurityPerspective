import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote, urlparse

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import settings


engine = create_engine(settings.database_url, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()


def backup_database_snapshot() -> str:
    backup_dir = Path(settings.database_backup_path)
    backup_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%d_%m_%y_%H")
    parsed = urlparse(settings.database_url)

    if parsed.scheme.startswith("sqlite"):
        db_path = parsed.path or ""
        if db_path.startswith("/"):
            source_path = Path(db_path)
        else:
            source_path = Path(db_path)
        backup_file = backup_dir / f"{settings.database_backup_prefix}_{timestamp}.sqlite3"
        shutil.copy2(source_path, backup_file)
        return str(backup_file)

    backup_file = backup_dir / f"{settings.database_backup_prefix}_{timestamp}.sql"
    password = unquote(parsed.password or "")
    command = [
        "pg_dump",
        "-h",
        parsed.hostname or "localhost",
        "-p",
        str(parsed.port or 5432),
        "-U",
        unquote(parsed.username or "postgres"),
        "-d",
        (parsed.path or "").lstrip("/") or "postgres",
        "-f",
        str(backup_file),
    ]
    environment = None
    if password:
        import os
        environment = os.environ.copy()
        environment["PGPASSWORD"] = password
    subprocess.run(command, check=True, env=environment)
    return str(backup_file)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

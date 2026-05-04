import json
import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote, urlparse

from sqlalchemy import create_engine, inspect, text
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
        environment = os.environ.copy()
        environment["PGPASSWORD"] = password
    try:
        subprocess.run(command, check=True, env=environment)
        return str(backup_file)
    except FileNotFoundError:
        fallback_backup_file = backup_dir / f"{settings.database_backup_prefix}_{timestamp}.json"
        _backup_database_as_json(fallback_backup_file)
        return str(fallback_backup_file)


def _backup_database_as_json(backup_file: Path) -> None:
    inspector = inspect(engine)
    table_names = inspector.get_table_names()
    snapshot = {
        "created_at_utc": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "database_url_scheme": urlparse(settings.database_url).scheme,
        "tables": {},
    }

    with engine.connect() as connection:
        for table_name in table_names:
            result = connection.execute(text(f'SELECT * FROM "{table_name}"'))
            rows = [dict(row._mapping) for row in result]
            snapshot["tables"][table_name] = rows

    backup_file.write_text(json.dumps(snapshot, indent=2, default=str), encoding="utf-8")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

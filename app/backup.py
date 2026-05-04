from __future__ import annotations

import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from sqlalchemy import create_engine, inspect, text

from app.config import settings


def _sql_literal(value):
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if isinstance(value, (int, float)):
        return str(value)
    return "'" + str(value).replace("'", "''") + "'"


def _write_fallback_sql_backup(backup_file: Path) -> None:
    engine = create_engine(settings.database_url, future=True)
    inspector = inspect(engine)
    tables = inspector.get_table_names()

    with engine.connect() as conn, backup_file.open("w", encoding="utf-8") as handle:
        handle.write("-- Fallback SQL backup generated without pg_dump\n")
        handle.write(f"-- generated_at_utc: {datetime.now(timezone.utc).isoformat()}\n\n")

        for table in tables:
            columns = inspector.get_columns(table)
            pk_columns = set(inspector.get_pk_constraint(table).get("constrained_columns") or [])
            col_defs = []
            for col in columns:
                col_type = str(col["type"])
                nullable = "" if col.get("nullable", True) else " NOT NULL"
                pk = " PRIMARY KEY" if col["name"] in pk_columns and len(pk_columns) == 1 else ""
                col_defs.append(f'"{col["name"]}" {col_type}{nullable}{pk}')
            if len(pk_columns) > 1:
                pk_line = ", ".join([f'"{name}"' for name in pk_columns])
                col_defs.append(f"PRIMARY KEY ({pk_line})")
            handle.write(f'DROP TABLE IF EXISTS "{table}" CASCADE;\n')
            handle.write(f'CREATE TABLE "{table}" (\n  ' + ",\n  ".join(col_defs) + "\n);\n\n")

        for table in tables:
            rows = conn.execute(text(f'SELECT * FROM "{table}"')).mappings().all()
            if not rows:
                continue
            columns = [f'"{name}"' for name in rows[0].keys()]
            for row in rows:
                values = ", ".join(_sql_literal(value) for value in row.values())
                handle.write(f'INSERT INTO "{table}" ({", ".join(columns)}) VALUES ({values});\n')
            handle.write("\n")


def backup_database() -> str:
    backup_dir = Path("backups")
    backup_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%d_%m_%y_%H_%M_%S")
    backup_file = backup_dir / f"security_perspective_backup_{timestamp}.sql"

    pg_dump_bin = shutil.which("pg_dump")
    if pg_dump_bin:
        parsed = urlparse(settings.database_url.replace("+psycopg2", ""))
        command = [
            pg_dump_bin,
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
    else:
        _write_fallback_sql_backup(backup_file)

    return str(backup_file)

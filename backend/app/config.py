import json
import os

DEFAULT_USERS = {
    "admin": {"password": "admin123", "role": "admin"},
    "analyst": {"password": "analyst123", "role": "analyst"},
    "viewer": {"password": "viewer123", "role": "viewer"},
}


def get_env(name: str, default: str | None = None) -> str | None:
    return os.getenv(name, default)


def users() -> dict:
    payload = os.getenv("APP_USERS_JSON")
    return json.loads(payload) if payload else DEFAULT_USERS


def db_dsn() -> str:
    return os.getenv("DATABASE_URL", "postgresql://security:security@db:5432/security_perspective")


def baseline_path() -> str:
    return os.getenv("BASELINE_PATH", "/app/app/baseline.json")

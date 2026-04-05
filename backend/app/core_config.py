from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "fortiweb-assessment"
    env: str = "dev"
    secret_key: str = "change-me"
    database_url: str = "postgresql+psycopg2://app:app@postgres:5432/fortiweb"
    redis_url: str = "redis://redis:6379/0"
    access_token_expire_minutes: int = 60
    baseline_version: str = "2026.1"
    parser_version: str = "1.0.0"
    scoring_version: str = "1.0.0"
    collector_version: str = "1.0.0"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()

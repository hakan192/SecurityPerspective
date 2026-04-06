from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Security Perspective"
    environment: str = "dev"

    database_url: str = "postgresql+psycopg2://postgres:postgres@db:5432/security_perspective"
    redis_url: str = "redis://redis:6379/0"

    celery_broker_url: str = "redis://redis:6379/1"
    celery_result_backend: str = "redis://redis:6379/2"

    fortiweb_base_url: str = "https://fortiweb.example.local"
    fortiweb_token: str = "change-me"
    fortiweb_verify_ssl: bool = False
    fortiweb_config_endpoint: str = "/api/v2.0/cmdb/waf"

    scheduler_enabled: bool = False
    scheduler_minutes: int = 60

    ldap_enabled: bool = False
    ldap_server_uri: str = "ldap://ldap.example.local:389"
    ldap_bind_dn: str = "cn=service,dc=example,dc=local"
    ldap_bind_password: str = "change-me"
    ldap_search_base: str = "ou=users,dc=example,dc=local"

    local_admin_username: str = "admin"
    local_admin_password: str = "admin123!"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


settings = Settings()

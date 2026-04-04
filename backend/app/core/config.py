from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', extra='ignore')

    app_name: str = 'SecurityPerspective'
    database_url: str = 'postgresql+psycopg2://security:security@db:5432/security'
    redis_url: str = 'redis://redis:6379/0'

    fortiweb_base_url: str = 'https://fortiweb.local/api/v2'
    fortiweb_token: str = 'change-me'
    fortiweb_verify_ssl: bool = False

    ldap_server_uri: str = 'ldap://ldap:389'
    ldap_bind_dn_template: str = 'uid={username},ou=people,dc=example,dc=org'


settings = Settings()

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "norwegian-honey"
    debug: bool = False
    trusted_proxy_headers: bool = True

    abuseipdb_api_key: str = ""
    ipinfo_api_key: str = ""
    osint_cache_ttl: int = 3600

    canary_storage: str = "sqlite"  # sqlite | influx
    canary_sqlite_path: str = "./data/canary.db"

    influx_url: str = "http://localhost:8086"
    influx_token: str = ""
    influx_org: str = "norwegian-honey"
    influx_bucket: str = "canary"

    @property
    def canary_db_path(self) -> Path:
        return Path(self.canary_sqlite_path)


@lru_cache
def get_settings() -> Settings:
    return Settings()

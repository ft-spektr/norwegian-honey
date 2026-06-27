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

    # Required in production — protects /analyze and /osint from counter-attack abuse
    investigator_api_key: str = ""

    abuseipdb_api_key: str = ""
    ipinfo_api_key: str = ""
    osint_cache_ttl: int = 3600

    # Resource limits (attacker-controlled input)
    max_request_body_bytes: int = 1_048_576  # 1 MiB
    max_eml_upload_bytes: int = 2_097_152  # 2 MiB
    max_analyze_input_chars: int = 524_288  # 512 KiB
    osint_max_entities_per_type: int = 10

    # Public hostname — enables TrustedHostMiddleware in production
    domain: str = ""

    canary_storage: str = "sqlite"  # sqlite | influx
    canary_sqlite_path: str = "./data/canary.db"
    canary_require_registered_token: bool = True
    canary_hit_retention_days: int = 90

    influx_url: str = "http://localhost:8086"
    influx_token: str = ""
    influx_org: str = "norwegian-honey"
    influx_bucket: str = "canary"

    @property
    def canary_db_path(self) -> Path:
        return Path(self.canary_sqlite_path)

    @property
    def allowed_hosts(self) -> list[str]:
        if not self.domain:
            return []
        hosts = [self.domain.strip(), f"www.{self.domain.strip()}"]
        return list(dict.fromkeys(h for h in hosts if h))


@lru_cache
def get_settings() -> Settings:
    return Settings()

"""Canary hit persistence — SQLite (default) or InfluxDB."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path

import aiosqlite

from app.config import Settings
from app.models.canary import CanaryHitRecord, CanaryHitResponse


class CanaryStorage(ABC):
    @abstractmethod
    async def init(self) -> None: ...

    @abstractmethod
    async def record_hit(self, hit: CanaryHitRecord) -> CanaryHitResponse: ...


class SQLiteCanaryStorage(CanaryStorage):
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path

    async def init(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS canary_hits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token TEXT NOT NULL,
                    client_ip TEXT NOT NULL,
                    user_agent TEXT,
                    referer TEXT,
                    method TEXT NOT NULL DEFAULT 'GET',
                    headers_json TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                )
                """
            )
            await db.execute(
                "CREATE INDEX IF NOT EXISTS idx_canary_token ON canary_hits(token)"
            )
            await db.commit()

    async def record_hit(self, hit: CanaryHitRecord) -> CanaryHitResponse:
        ts = hit.timestamp.astimezone(timezone.utc).isoformat()
        async with aiosqlite.connect(self._db_path) as db:
            cursor = await db.execute(
                """
                INSERT INTO canary_hits
                    (token, client_ip, user_agent, referer, method, headers_json, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    hit.token,
                    hit.client_ip,
                    hit.user_agent,
                    hit.referer,
                    hit.method,
                    json.dumps(hit.headers),
                    ts,
                ),
            )
            await db.commit()
            row_id = cursor.lastrowid
        return CanaryHitResponse(
            id=row_id or 0,
            token=hit.token,
            client_ip=hit.client_ip,
            timestamp=hit.timestamp,
        )


class InfluxCanaryStorage(CanaryStorage):
    """
    Lightweight InfluxDB line-protocol writer.

    OpSec: store only investigative fields; never log secrets or full cookies.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def init(self) -> None:
        # Bucket/org provisioning is handled by docker-compose init.
        pass

    async def record_hit(self, hit: CanaryHitRecord) -> CanaryHitResponse:
        import httpx

        ts_ns = int(hit.timestamp.timestamp() * 1_000_000_000)
        # Escape tag values for line protocol
        token = hit.token.replace(" ", "\\ ").replace(",", "\\,")
        client_ip = hit.client_ip.replace(" ", "\\ ")

        line = (
            f"canary_hit,token={token},client_ip={client_ip} "
            f'user_agent="{hit.user_agent or ""}",referer="{hit.referer or ""}",'
            f'method="{hit.method}" {ts_ns}'
        )

        url = f"{self._settings.influx_url}/api/v2/write"
        params = {"org": self._settings.influx_org, "bucket": self._settings.influx_bucket, "precision": "ns"}
        headers = {
            "Authorization": f"Token {self._settings.influx_token}",
            "Content-Type": "text/plain; charset=utf-8",
        }

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(url, params=params, headers=headers, content=line)
            response.raise_for_status()

        return CanaryHitResponse(
            id=ts_ns,
            token=hit.token,
            client_ip=hit.client_ip,
            timestamp=hit.timestamp,
        )


def build_canary_storage(settings: Settings) -> CanaryStorage:
    if settings.canary_storage.lower() == "influx":
        return InfluxCanaryStorage(settings)
    return SQLiteCanaryStorage(settings.canary_db_path)

"""Registered canary token store — only known tokens produce hit records."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import aiosqlite


class CanaryTokenRegistry:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path

    async def init(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS canary_tokens (
                    token TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL
                )
                """
            )
            await db.commit()

    async def register(self, token: str) -> bool:
        ts = datetime.now(timezone.utc).isoformat()
        async with aiosqlite.connect(self._db_path) as db:
            try:
                await db.execute(
                    "INSERT INTO canary_tokens (token, created_at) VALUES (?, ?)",
                    (token, ts),
                )
                await db.commit()
                return True
            except aiosqlite.IntegrityError:
                return False

    async def is_registered(self, token: str) -> bool:
        async with aiosqlite.connect(self._db_path) as db:
            cursor = await db.execute(
                "SELECT 1 FROM canary_tokens WHERE token = ? LIMIT 1",
                (token,),
            )
            row = await cursor.fetchone()
            return row is not None

from __future__ import annotations

from copilot_soc.db.postgres import Database

_db: Database | None = None


async def get_db() -> Database:
    global _db
    if _db is None:
        _db = Database()
        try:
            await _db.connect()
        except Exception as exc:
            _db = None
            raise ConnectionError(
                f"Cannot connect to database: {exc}. "
                "Run `docker compose up -d` to start PostgreSQL, "
                "or set DATABASE_URL env var."
            ) from exc
    return _db


async def close_db() -> None:
    global _db
    if _db:
        await _db.close()
        _db = None

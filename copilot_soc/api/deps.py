from __future__ import annotations

from copilot_soc.db.postgres import Database

_db: Database | None = None


async def get_db() -> Database:
    global _db
    if _db is None:
        _db = Database()
        await _db.connect()
    return _db


async def close_db() -> None:
    global _db
    if _db:
        await _db.close()
        _db = None

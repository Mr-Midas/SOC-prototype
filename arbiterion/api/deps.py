"""Lazy singleton for the asyncpg Database pool.

``get_db()`` is called by every route handler and lazily creates the pool
on first invocation.  This means the app can boot without PostgreSQL;
the first request that needs the DB will get a friendly error directing
the user to run ``docker compose up -d``.

``close_db()`` is called on FastAPI shutdown to gracefully drain the pool.
"""

from __future__ import annotations

from arbiterion.db.postgres import Database

_db: Database | None = None


async def get_db() -> Database:
    """Return the shared Database singleton, creating it on first call."""
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
    """Close the pool at app shutdown (idempotent)."""
    global _db
    if _db:
        await _db.close()
        _db = None


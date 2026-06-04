from __future__ import annotations

import os
from collections.abc import Iterator
from typing import Any

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

DEFAULT_DATABASE_URL = "postgresql+psycopg://agenticnetsec:agenticnetsec@localhost:5432/agenticnetsec"


def get_database_url() -> str:
    return os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL)


def create_engine_for_url(database_url: str | None = None) -> Engine:
    return create_engine(database_url or get_database_url(), pool_pre_ping=True)


engine = create_engine_for_url()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def get_session() -> Iterator[Session]:
    with SessionLocal() as session:
        yield session


def check_database_connection(database_url: str | None = None) -> dict[str, Any]:
    url = database_url or get_database_url()
    health_engine: Engine | None = None
    try:
        health_engine = create_engine_for_url(url)
        with health_engine.connect() as connection:
            connection.execute(text("select 1"))
        return {"status": "ok", "database_url_present": bool(url)}
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "unavailable",
            "database_url_present": bool(url),
            "error": str(exc),
        }
    finally:
        if health_engine is not None:
            health_engine.dispose()

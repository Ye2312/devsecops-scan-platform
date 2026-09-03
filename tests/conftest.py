from __future__ import annotations

import os
from collections.abc import Iterator

import pytest
from devsecops_shared.db import SessionLocal, engine
from fastapi.testclient import TestClient
from sqlalchemy import inspect, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session


def _database_ready() -> tuple[bool, str]:
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:
        return False, f"database unreachable: {type(exc).__name__}"

    missing = {"scans", "findings"} - set(inspect(engine).get_table_names())
    if missing:
        return False, f"tables not migrated: {sorted(missing)}"
    return True, ""


@pytest.fixture(scope="session")
def database() -> None:
    ready, reason = _database_ready()
    if ready:
        return
    if os.getenv("CI"):
        pytest.fail(f"database required in CI but {reason}")
    pytest.skip(f"{reason} — run `make db-up && make migrate`")


@pytest.fixture
def db_session(database: None) -> Iterator[Session]:
    with SessionLocal() as session:
        yield session
        session.rollback()


@pytest.fixture(autouse=True)
def _clean_tables(request: pytest.FixtureRequest) -> Iterator[None]:
    if "database" not in request.fixturenames:
        yield
        return
    yield
    with SessionLocal() as session:
        session.execute(text("TRUNCATE scans CASCADE"))
        session.commit()


@pytest.fixture
def client(database: None) -> Iterator[TestClient]:
    with TestClient(app_instance()) as test_client:
        yield test_client


def app_instance():
    from app.main import app

    return app

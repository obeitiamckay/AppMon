"""Pytest fixtures for soc-monitor tests."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Ensure test environment before importing app modules
os.environ["APP_ENV"] = "test"
os.environ["FERNET_KEY"] = Fernet.generate_key().decode("utf-8")
os.environ["JWT_SECRET"] = "test-jwt-secret-key-with-sufficient-length-32bytes"
os.environ["COOKIE_SECURE"] = "false"

from app.database import Base
import app.models  # noqa: F401


@pytest.fixture()
def db_session(tmp_path: Path):
    """Provide an isolated SQLite database session per test."""
    db_file = tmp_path / "test_soc.db"
    engine = create_engine(
        f"sqlite:///{db_file}",
        connect_args={"check_same_thread": False},
        future=True,
    )
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    session = TestingSession()
    try:
        yield session, TestingSession
    finally:
        session.close()
        engine.dispose()

"""Main FastAPI application entry point and CLI runner for soc-monitor."""

from __future__ import annotations

import argparse
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy import func, select

from app import __version__
from app.config import get_settings
from app.database import Base, SessionLocal, engine
from app.logging_config import setup_logging
from app.models.system import SystemUser
from app.scheduler.runner import init_scheduler, run_full_scan, shutdown_scheduler
from app.security import hash_password
from app.web.routes.admin_routes import router as admin_router
from app.web.routes.auth import router as auth_router
from app.web.routes.console import router as console_router

logger = logging.getLogger(__name__)


def bootstrap_initial_admin() -> None:
    """Create initial admin user if system_users table is empty."""
    settings = get_settings()
    db = SessionLocal()
    try:
        count = db.execute(select(func.count()).select_from(SystemUser)).scalar_one()
        if count == 0:
            admin = SystemUser(
                username=settings.initial_admin_user,
                password_hash=hash_password(settings.initial_admin_password),
                role="admin",
                is_active=True,
            )
            db.add(admin)
            db.commit()
            logger.info("Bootstrapped initial admin user '%s'", settings.initial_admin_user)
    finally:
        db.close()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    settings = get_settings()
    setup_logging(settings.log_level, settings.logs_dir)
    if settings.database_url.startswith("sqlite"):
        Base.metadata.create_all(bind=engine)
    bootstrap_initial_admin()
    if settings.app_env != "test":
        init_scheduler()
    yield
    shutdown_scheduler()


app = FastAPI(
    title="soc-monitor",
    version=__version__,
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
)

app.include_router(auth_router)
app.include_router(console_router)
app.include_router(admin_router)


@app.get("/health")
def health_check() -> dict[str, str]:
    """Health check endpoint for systemd / load balancers."""
    return {"status": "ok", "version": __version__}


def main() -> None:
    parser = argparse.ArgumentParser(description="soc-monitor CLI")
    parser.add_argument("--run-once", action="store_true", help="Run a single full scan and exit")
    args = parser.parse_args()

    settings = get_settings()
    setup_logging(settings.log_level, settings.logs_dir)
    if args.run_once:
        run_full_scan(trigger_type="scheduled", triggered_by="systemd-timer")


if __name__ == "__main__":
    main()

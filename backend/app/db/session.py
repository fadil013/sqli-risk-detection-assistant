from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from app.db.models import Base

# Swap this one line for a Postgres DSN later (per the original tech-stack
# plan); everything above it in db/models.py is plain SQLAlchemy ORM with
# no SQLite-specific types, so nothing else has to change.
SQLALCHEMY_DATABASE_URL = "sqlite:///./crawler.db"

engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)


def get_session() -> Session:
    return SessionLocal()

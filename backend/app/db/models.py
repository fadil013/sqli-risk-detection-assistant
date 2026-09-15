"""Feature 6 — Crawler database model.

Website -> Pages -> Inputs / Parameters / ApiEndpoints

SQLite by default (zero setup, a single file). The intent is a
straight swap to PostgreSQL later: change SQLALCHEMY_DATABASE_URL in
db/session.py, nothing here has to change since it's plain SQLAlchemy
ORM with no SQLite-specific types.
"""
from __future__ import annotations

import datetime

from sqlalchemy import ForeignKey, String, DateTime, Boolean, Float, Integer
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Website(Base):
    __tablename__ = "websites"

    id: Mapped[int] = mapped_column(primary_key=True)
    url: Mapped[str] = mapped_column(String, index=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=lambda: datetime.datetime.now(datetime.UTC)
    )

    pages: Mapped[list["Page"]] = relationship(back_populates="website", cascade="all, delete-orphan")
    technologies: Mapped[list["Technology"]] = relationship(back_populates="website", cascade="all, delete-orphan")
    crawl_sessions: Mapped[list["CrawlSession"]] = relationship(
        back_populates="website", cascade="all, delete-orphan"
    )


class Page(Base):
    __tablename__ = "pages"

    id: Mapped[int] = mapped_column(primary_key=True)
    website_id: Mapped[int] = mapped_column(ForeignKey("websites.id"))
    url: Mapped[str] = mapped_column(String, index=True)
    title: Mapped[str | None] = mapped_column(String, nullable=True)
    page_type: Mapped[str] = mapped_column(String, default="general")  # Stage 1.3
    importance: Mapped[str] = mapped_column(String, default="low")
    response_headers: Mapped[str | None] = mapped_column(String, nullable=True)  # JSON-encoded dict

    website: Mapped[Website] = relationship(back_populates="pages")
    inputs: Mapped[list["Input"]] = relationship(back_populates="page", cascade="all, delete-orphan")
    parameters: Mapped[list["Parameter"]] = relationship(back_populates="page", cascade="all, delete-orphan")
    api_endpoints: Mapped[list["ApiEndpointRow"]] = relationship(
        back_populates="page", cascade="all, delete-orphan"
    )


class Input(Base):
    __tablename__ = "inputs"

    id: Mapped[int] = mapped_column(primary_key=True)
    page_id: Mapped[int] = mapped_column(ForeignKey("pages.id"))
    name: Mapped[str | None] = mapped_column(String, nullable=True)
    type: Mapped[str] = mapped_column(String, default="text")
    source: Mapped[str] = mapped_column(String, default="form")  # "form" | "standalone"
    method: Mapped[str | None] = mapped_column(String, nullable=True)  # form method, if source="form"

    page: Mapped[Page] = relationship(back_populates="inputs")


class Parameter(Base):
    __tablename__ = "parameters"

    id: Mapped[int] = mapped_column(primary_key=True)
    page_id: Mapped[int] = mapped_column(ForeignKey("pages.id"))
    name: Mapped[str] = mapped_column(String)
    example_value: Mapped[str | None] = mapped_column(String, nullable=True)
    risk_candidate: Mapped[bool] = mapped_column(Boolean, default=False)

    page: Mapped[Page] = relationship(back_populates="parameters")


class ApiEndpointRow(Base):
    __tablename__ = "api_endpoints"

    id: Mapped[int] = mapped_column(primary_key=True)
    page_id: Mapped[int] = mapped_column(ForeignKey("pages.id"))
    endpoint: Mapped[str] = mapped_column(String)
    method: Mapped[str] = mapped_column(String)
    parameters: Mapped[str | None] = mapped_column(String, nullable=True)  # comma-joined param names
    source: Mapped[str] = mapped_column(String, default="javascript")

    page: Mapped[Page] = relationship(back_populates="api_endpoints")


class Technology(Base):
    """Stage 1.7 — one fingerprinted technology for a website."""

    __tablename__ = "technologies"

    id: Mapped[int] = mapped_column(primary_key=True)
    website_id: Mapped[int] = mapped_column(ForeignKey("websites.id"))
    name: Mapped[str] = mapped_column(String)
    category: Mapped[str] = mapped_column(String)  # frontend | backend | server
    confidence: Mapped[float] = mapped_column(Float)

    website: Mapped[Website] = relationship(back_populates="technologies")


class CrawlSession(Base):
    """One `recon()` run. Exists so GET /api/v1/recon/{id} has
    something to report status from, even though the crawl itself
    still executes synchronously inside the POST call today.
    """

    __tablename__ = "crawl_sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    website_id: Mapped[int] = mapped_column(ForeignKey("websites.id"))
    status: Mapped[str] = mapped_column(String, default="completed")  # queued | running | completed | failed
    max_depth: Mapped[int] = mapped_column(Integer)
    max_pages: Mapped[int] = mapped_column(Integer)
    pages_scanned: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=lambda: datetime.datetime.now(datetime.UTC)
    )
    completed_at: Mapped[datetime.datetime | None] = mapped_column(DateTime, nullable=True)

    website: Mapped[Website] = relationship(back_populates="crawl_sessions")


class FieldAnalysis(Base):
    """Stage 2/3 — one AI classification + risk score for one
    discovered field. `source_type`/`source_id` point at either an
    Input or a Parameter row rather than a single FK, because those
    two live in separate tables (Phase 1.5 predates this table and
    that split isn't worth undoing).
    """

    __tablename__ = "field_analysis"

    id: Mapped[int] = mapped_column(primary_key=True)
    page_id: Mapped[int] = mapped_column(ForeignKey("pages.id"))
    source_type: Mapped[str] = mapped_column(String)  # "input" | "parameter"
    source_id: Mapped[int] = mapped_column(Integer)
    field_name: Mapped[str | None] = mapped_column(String, nullable=True)
    category: Mapped[str] = mapped_column(String)
    confidence: Mapped[float] = mapped_column(Float)
    database_probability: Mapped[float] = mapped_column(Float)
    risk_score: Mapped[int] = mapped_column(Integer)
    severity: Mapped[str] = mapped_column(String)
    reasons: Mapped[str] = mapped_column(String)  # "; "-joined
    explanation: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=lambda: datetime.datetime.now(datetime.UTC)
    )

    page: Mapped[Page] = relationship()


class OwaspFindingRow(Base):
    """Stage 5 — one passively-detected OWASP Top 10 candidate, plus its
    RAG-grounded, locally-generated explanation/fix.
    """

    __tablename__ = "owasp_findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    page_id: Mapped[int] = mapped_column(ForeignKey("pages.id"))
    category: Mapped[str] = mapped_column(String)
    evidence: Mapped[str] = mapped_column(String)
    severity: Mapped[str] = mapped_column(String)
    description: Mapped[str] = mapped_column(String)
    remediation: Mapped[str] = mapped_column(String)  # LLM-generated fix (or template fallback)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=lambda: datetime.datetime.now(datetime.UTC)
    )

    page: Mapped[Page] = relationship()

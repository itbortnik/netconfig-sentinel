"""Relational metadata; configuration and analysis contents are encrypted payloads."""

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class DeviceRow(Base):
    __tablename__ = "devices"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    identity_payload: Mapped[str] = mapped_column(Text)


class ConfigurationRow(Base):
    __tablename__ = "configurations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    source_sha256: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    payload: Mapped[str] = mapped_column(Text)


class AnalysisRow(Base):
    __tablename__ = "analyses"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    configuration_id: Mapped[str] = mapped_column(ForeignKey("configurations.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    payload: Mapped[str] = mapped_column(Text)


class AuditRow(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    action: Mapped[str] = mapped_column(String(64))
    resource_id: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class ModelRow(Base):
    __tablename__ = "models"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    artifact_sha256: Mapped[str] = mapped_column(String(64))
    payload: Mapped[str] = mapped_column(Text)


class FeedbackRow(Base):
    __tablename__ = "finding_feedback"
    __table_args__ = (
        Index("ix_finding_feedback_target_created_at", "analysis_id", "finding_id", "created_at"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id"))
    finding_id: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    payload: Mapped[str] = mapped_column(Text)

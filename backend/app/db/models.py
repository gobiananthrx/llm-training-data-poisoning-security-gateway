from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text, func, JSON
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Dataset(Base):
    __tablename__ = "datasets"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    dataset_id: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    filename: Mapped[str] = mapped_column(String(255))
    source: Mapped[str] = mapped_column(String(100), default="user_upload")
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )

    versions: Mapped[list["DatasetVersion"]] = relationship(
        back_populates="dataset",
        cascade="all, delete-orphan",
        order_by="DatasetVersion.version",
    )


class DatasetVersion(Base):
    __tablename__ = "dataset_versions"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    dataset_id: Mapped[int] = mapped_column(
        ForeignKey("datasets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    version: Mapped[int] = mapped_column(Integer, nullable=False)

    file_type: Mapped[str] = mapped_column(String(20))
    file_size: Mapped[int] = mapped_column(Integer)

    # Cryptographic integrity
    sha256: Mapped[str] = mapped_column(
        String(64),
        index=True,
    )

    # Post-quantum digital signature
    signature_algorithm: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    signature: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    public_key: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    # Provenance information bound to this dataset version
    provenance: Mapped[dict[str, Any] | None] = mapped_column(
        JSON,
        nullable=True,
    )

    status: Mapped[str] = mapped_column(
        String(30),
        default="UPLOADED",
    )

    storage_location: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )

    record_count: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )

    dataset: Mapped["Dataset"] = relationship(back_populates="versions")

    agent_runs: Mapped[list["AgentRun"]] = relationship(
        back_populates="version_rel",
        cascade="all, delete-orphan",
    )

    findings: Mapped[list["AgentFinding"]] = relationship(
        back_populates="version_rel",
        cascade="all, delete-orphan",
    )

    correlated_findings: Mapped[list["CorrelatedFinding"]] = relationship(
        back_populates="version_rel",
        cascade="all, delete-orphan",
    )

    risk_assessments: Mapped[list["RiskAssessment"]] = relationship(
        back_populates="version_rel",
        cascade="all, delete-orphan",
    )

    policy_decisions: Mapped[list["PolicyDecision"]] = relationship(
        back_populates="version_rel",
        cascade="all, delete-orphan",
    )

    human_reviews: Mapped[list["HumanReview"]] = relationship(
        back_populates="version_rel",
        cascade="all, delete-orphan",
    )


class AgentRun(Base):
    __tablename__ = "agent_runs"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    version_id: Mapped[int] = mapped_column(
        ForeignKey("dataset_versions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    agent_name: Mapped[str] = mapped_column(String(50), index=True)
    status: Mapped[str] = mapped_column(String(30), default="PENDING")
    provider: Mapped[str | None] = mapped_column(String(50), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )

    version_rel: Mapped["DatasetVersion"] = relationship(back_populates="agent_runs")
    findings: Mapped[list["AgentFinding"]] = relationship(
        back_populates="agent_run_rel",
        cascade="all, delete-orphan",
    )


class AgentFinding(Base):
    __tablename__ = "agent_findings"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    finding_id: Mapped[str] = mapped_column(String(50), unique=True, index=True)

    version_id: Mapped[int] = mapped_column(
        ForeignKey("dataset_versions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    agent_run_id: Mapped[int | None] = mapped_column(
        ForeignKey("agent_runs.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    agent: Mapped[str] = mapped_column(String(50), index=True)
    status: Mapped[str] = mapped_column(String(20), default="FLAGGED")

    record_id: Mapped[str] = mapped_column(String(100), index=True)
    field: Mapped[str] = mapped_column(String(100))
    location: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)

    category: Mapped[str] = mapped_column(String(100), index=True)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    evidence: Mapped[str] = mapped_column(Text, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    recommendation: Mapped[str] = mapped_column(String(30), nullable=False)

    entity_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    related_record_ids: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    model_or_provider: Mapped[str | None] = mapped_column(String(50), nullable=True)
    metadata_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )

    version_rel: Mapped["DatasetVersion"] = relationship(back_populates="findings")
    agent_run_rel: Mapped["AgentRun | None"] = relationship(back_populates="findings")


class CorrelatedFinding(Base):
    __tablename__ = "correlated_findings"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    correlation_id: Mapped[str] = mapped_column(String(50), unique=True, index=True)

    version_id: Mapped[int] = mapped_column(
        ForeignKey("dataset_versions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    record_id: Mapped[str] = mapped_column(String(100), index=True)
    field: Mapped[str] = mapped_column(String(100))
    location: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)

    primary_category: Mapped[str] = mapped_column(String(100), nullable=False)
    max_severity: Mapped[str] = mapped_column(String(20), index=True)
    agents_involved: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    finding_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    agent_summaries: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )

    version_rel: Mapped["DatasetVersion"] = relationship(back_populates="correlated_findings")


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    version_id: Mapped[int] = mapped_column(
        ForeignKey("dataset_versions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(20), index=True, nullable=False)
    contributing_factors: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    metrics: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )

    version_rel: Mapped["DatasetVersion"] = relationship(back_populates="risk_assessments")


class PolicyDecision(Base):
    __tablename__ = "policy_decisions"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    version_id: Mapped[int] = mapped_column(
        ForeignKey("dataset_versions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    decision: Mapped[str] = mapped_column(String(30), index=True, nullable=False)
    policy_input: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    policy_output: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    reasons: Mapped[list[str]] = mapped_column(JSON, nullable=False)

    evaluated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )

    version_rel: Mapped["DatasetVersion"] = relationship(back_populates="policy_decisions")


class HumanReview(Base):
    __tablename__ = "human_reviews"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    version_id: Mapped[int] = mapped_column(
        ForeignKey("dataset_versions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    action: Mapped[str] = mapped_column(String(30), index=True, nullable=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    changes_summary: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )

    version_rel: Mapped["DatasetVersion"] = relationship(back_populates="human_reviews")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    event_type: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    dataset_id: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        index=True,
    )

    details: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

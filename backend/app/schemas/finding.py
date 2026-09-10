from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4
from pydantic import BaseModel, Field


class FindingStatus(str, Enum):
    PASS = "PASS"
    FLAGGED = "FLAGGED"
    ERROR = "ERROR"


class FindingSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingRecommendation(str, Enum):
    REVIEW = "REVIEW"
    QUARANTINE = "QUARANTINE"
    REMOVE = "REMOVE"
    APPROVE = "APPROVE"


class AgentFindingSchema(BaseModel):
    finding_id: str = Field(default_factory=lambda: f"FND-{uuid4().hex[:10].upper()}")
    dataset_id: str
    version: int = Field(ge=1)
    agent: str  # "semantic", "behavioral", "inconsistency", "pii"
    status: FindingStatus = FindingStatus.FLAGGED
    record_id: str
    field: str
    location: dict[str, Any]
    category: str
    severity: FindingSeverity
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: str
    reason: str
    recommendation: FindingRecommendation
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # Optional fields
    entity_type: str | None = None
    related_record_ids: list[str] | None = None
    model_or_provider: str | None = None
    metadata: dict[str, Any] | None = None


class AgentFindingLLMOutput(BaseModel):
    """
    Schema for structured JSON returned by LLM agents.
    """
    category: str
    severity: FindingSeverity
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: str
    reason: str
    recommendation: FindingRecommendation
    field: str = "text"
    location_span: dict[str, int] | None = None
    related_record_ids: list[str] | None = None

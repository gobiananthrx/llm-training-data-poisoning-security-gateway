from typing import Any
from pydantic import BaseModel, Field


class DatasetUploadResponse(BaseModel):
    dataset_id: str
    version: int = Field(ge=1)
    filename: str
    file_type: str
    file_size: int = Field(ge=0)
    source: str
    description: str = ""
    sha256: str
    signature_algorithm: str = "ML-DSA-65"
    signature: str | None = None
    public_key: str | None = None
    status: str
    processing_summary: dict[str, Any]


class DatasetVerificationResponse(BaseModel):
    dataset_id: str
    version: int = Field(ge=1)
    verification_status: str
    sha256_verified: bool
    provenance_verified: bool
    signature_verified: bool
    signature_algorithm: str
    reason: str
    file_exists: bool = True
    identity_verified: bool = True


class DatasetItemResponse(BaseModel):
    dataset_id: str
    version: int
    filename: str
    file_type: str
    file_size: int
    sha256: str
    status: str
    created_at: str
    record_count: int | None = None
    risk_level: str | None = None
    risk_score: int | None = None
    opa_decision: str | None = None
    findings_count: int = 0
    pii_count: int = 0


class DatasetDetailResponse(BaseModel):
    dataset_id: str
    filename: str
    source: str
    description: str
    created_at: str
    versions: list[dict[str, Any]]
    current_version: int

from pydantic import BaseModel, Field


class DatasetUploadResponse(BaseModel):
    dataset_id: str
    version: int = Field(ge=1)
    filename: str
    file_type: str
    file_size: int = Field(ge=0)
    source: str
    description: str
    sha256: str
    status: str
    processing_summary: dict


class DatasetVerificationResponse(BaseModel):
    dataset_id: str
    version: int = Field(ge=1)
    verification_status: str
    sha256_verified: bool
    provenance_verified: bool
    signature_verified: bool
    signature_algorithm: str
    reason: str

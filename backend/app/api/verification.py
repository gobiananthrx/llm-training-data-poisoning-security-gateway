from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.models import Dataset, DatasetVersion
from app.schemas.dataset import DatasetVerificationResponse
from app.services.verification import verify_dataset_integrity

router = APIRouter(
    prefix="/verification",
    tags=["verification"],
)


@router.get(
    "/{dataset_id}/{version}",
    response_model=DatasetVerificationResponse,
)
async def verify_dataset(
    dataset_id: str,
    version: int,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(DatasetVersion, Dataset)
        .join(
            Dataset,
            Dataset.id == DatasetVersion.dataset_id,
        )
        .where(
            Dataset.dataset_id == dataset_id,
            DatasetVersion.version == version,
        )
    )

    row = result.first()

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Dataset version not found.",
        )

    dataset_version, _dataset = row

    if not dataset_version.signature:
        return DatasetVerificationResponse(
            dataset_id=dataset_id,
            version=version,
            verification_status="BLOCKED",
            sha256_verified=False,
            provenance_verified=False,
            signature_verified=False,
            signature_algorithm=(dataset_version.signature_algorithm or "UNKNOWN"),
            reason="No cryptographic signature found.",
        )

    if not dataset_version.public_key:
        return DatasetVerificationResponse(
            dataset_id=dataset_id,
            version=version,
            verification_status="BLOCKED",
            sha256_verified=False,
            provenance_verified=False,
            signature_verified=False,
            signature_algorithm=(dataset_version.signature_algorithm or "UNKNOWN"),
            reason="No public key found.",
        )

    if not dataset_version.provenance:
        return DatasetVerificationResponse(
            dataset_id=dataset_id,
            version=version,
            verification_status="BLOCKED",
            sha256_verified=False,
            provenance_verified=False,
            signature_verified=False,
            signature_algorithm=(dataset_version.signature_algorithm or "UNKNOWN"),
            reason="No provenance metadata found.",
        )

    if not dataset_version.storage_location:
        return DatasetVerificationResponse(
            dataset_id=dataset_id,
            version=version,
            verification_status="BLOCKED",
            sha256_verified=False,
            provenance_verified=False,
            signature_verified=False,
            signature_algorithm=(dataset_version.signature_algorithm or "UNKNOWN"),
            reason="No stored dataset location found.",
        )

    file_path = Path(dataset_version.storage_location)

    if not file_path.exists():
        return DatasetVerificationResponse(
            dataset_id=dataset_id,
            version=version,
            verification_status="BLOCKED",
            sha256_verified=False,
            provenance_verified=False,
            signature_verified=False,
            signature_algorithm=(dataset_version.signature_algorithm or "UNKNOWN"),
            reason="Stored dataset file not found.",
        )

    verification = verify_dataset_integrity(
        file_path=file_path,
        stored_sha256=dataset_version.sha256,
        provenance=dataset_version.provenance,
        signature=dataset_version.signature,
        public_key=dataset_version.public_key,
        dataset_id=dataset_id,
        version=version,
        signature_algorithm=dataset_version.signature_algorithm,
    )

    return DatasetVerificationResponse(
        dataset_id=dataset_id,
        version=version,
        verification_status=verification["verification_status"],
        sha256_verified=verification["sha256_verified"],
        provenance_verified=verification["provenance_verified"],
        signature_verified=verification["signature_verified"],
        signature_algorithm=(dataset_version.signature_algorithm or "UNKNOWN"),
        reason=verification["reason"],
    )

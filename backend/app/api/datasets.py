from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.models import Dataset, DatasetVersion
from app.schemas.dataset import DatasetUploadResponse
from app.services.dataset_processor import validate_and_process
from app.services.hashing import calculate_sha256
from app.services.storage import save_upload
from app.services.hashing import calculate_sha256
from app.services.cryptography import (
    create_provenance,
    get_public_key,
    sign_provenance,
)

router = APIRouter(prefix="/datasets", tags=["datasets"])

ALLOWED_EXTENSIONS = {".csv", ".json", ".txt", ".xlsx"}


@router.post(
    "/upload",
    response_model=DatasetUploadResponse,
    status_code=status.HTTP_201_CREATED,
)
async def upload_dataset(
    file: UploadFile = File(...),
    source: str = Form("user_upload"),
    description: str = Form(""),
    db: AsyncSession = Depends(get_db),
):
    filename = file.filename or ""
    extension = Path(filename).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file type: {extension or 'unknown'}",
        )

    dataset_id = f"DS-{uuid4().hex[:12].upper()}"
    version = 1

    try:
        stored_path, file_size = await save_upload(
            file=file,
            dataset_id=dataset_id,
            version=version,
        )

        processing_summary = validate_and_process(
            stored_path,
            extension,
        )

        sha256 = calculate_sha256(stored_path)
        file_type = extension.lstrip(".")
        provenance = create_provenance(
            dataset_id=dataset_id,
            version=version,
            filename=filename,
            file_type=file_type,
            file_size=file_size,
            sha256=sha256,
            source=source,
        )
        signature = sign_provenance(provenance)
        public_key = get_public_key()

    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Dataset processing failed: {exc}",
        ) from exc

    dataset = Dataset(
        dataset_id=dataset_id,
        filename=filename,
        source=source,
        description=description,
    )

    dataset_version = DatasetVersion(
        version=version,
        file_type=file_type,
        file_size=file_size,
        sha256=sha256,
        signature_algorithm="ML-DSA-65",
        signature=signature,
        public_key=public_key,
        provenance=provenance,
        status="PROCESSED",
        storage_location=str(stored_path),
    )

    dataset.versions.append(dataset_version)

    response_data = {
        "dataset_id": dataset_id,
        "version": version,
        "filename": filename,
        "file_type": extension.lstrip("."),
        "file_size": file_size,
        "source": source,
        "description": description,
        "sha256": sha256,
        "status": "PROCESSED",
        "processing_summary": processing_summary,
    }

    try:
        db.add(dataset)
        await db.commit()

    except Exception as exc:
        await db.rollback()

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to persist dataset metadata.",
        ) from exc

    return DatasetUploadResponse(**response_data)

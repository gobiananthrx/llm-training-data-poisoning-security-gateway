from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from pydantic import BaseModel
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

import hashlib
from fastapi.responses import FileResponse

from app.db.database import get_db
from app.db.models import (
    AgentFinding,
    AuditEvent,
    CorrelatedFinding,
    Dataset,
    DatasetVersion,
    PolicyDecision,
    RiskAssessment,
)
from app.events.manager import emit_pipeline_event
from app.schemas.dataset import (
    DatasetDetailResponse,
    DatasetItemResponse,
    DatasetUploadResponse,
    DatasetVerificationResponse,
)
from app.services.cryptography import (
    create_provenance,
    get_public_key,
    sign_provenance,
    verify_signature,
)
from app.services.dataset_processor import normalize_dataset, validate_and_process
from app.services.hashing import calculate_sha256
from app.services.human_review import submit_human_review
from app.services.storage import save_upload
from app.services.verification import verify_dataset_integrity
from app.workflows.orchestrator import execute_security_pipeline

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
    """
    Initial dataset ingestion into Data Collection (/data-collection).
    Parses file, calculates SHA-256, signs with ML-DSA-65, and binds provenance.
    """
    filename = file.filename or ""
    extension = Path(filename).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file type: {extension or 'unknown'}. Allowed: .csv, .json, .txt, .xlsx",
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
        status="UPLOADED",
        storage_location=str(stored_path),
        record_count=processing_summary.get("record_count") or processing_summary.get("rows"),
    )

    dataset.versions.append(dataset_version)

    # Record audit event
    audit = AuditEvent(
        event_type="dataset_ingested",
        dataset_id=dataset_id,
        version=version,
        details={
            "filename": filename,
            "sha256": sha256,
            "file_size": file_size,
            "file_type": file_type,
        },
    )

    try:
        db.add(dataset)
        db.add(audit)
        await db.commit()
    except Exception as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to persist dataset metadata: {exc}",
        ) from exc

    await emit_pipeline_event(
        "dataset_uploaded",
        dataset_id,
        version,
        {
            "filename": filename,
            "sha256": sha256,
            "file_size": file_size,
            "record_count": dataset_version.record_count,
        },
    )

    return DatasetUploadResponse(
        dataset_id=dataset_id,
        version=version,
        filename=filename,
        file_type=file_type,
        file_size=file_size,
        source=source,
        description=description,
        sha256=sha256,
        signature_algorithm="ML-DSA-65",
        signature=signature,
        public_key=public_key,
        status="UPLOADED",
        processing_summary=processing_summary,
    )


@router.get("", response_model=list[DatasetItemResponse])
@router.get("/", response_model=list[DatasetItemResponse])
async def list_datasets(db: AsyncSession = Depends(get_db)):
    """
    Returns list of all datasets with active version, risk scores, and decisions.
    """
    stmt = (
        select(Dataset)
        .options(
            selectinload(Dataset.versions).selectinload(DatasetVersion.risk_assessments),
            selectinload(Dataset.versions).selectinload(DatasetVersion.policy_decisions),
            selectinload(Dataset.versions).selectinload(DatasetVersion.findings),
        )
        .order_by(desc(Dataset.created_at))
    )
    result = await db.execute(stmt)
    datasets = result.scalars().all()

    items: list[DatasetItemResponse] = []
    for d in datasets:
        if not d.versions:
            continue
        # Latest version
        latest_ver = max(d.versions, key=lambda v: v.version)
        latest_risk = latest_ver.risk_assessments[-1] if latest_ver.risk_assessments else None
        latest_policy = latest_ver.policy_decisions[-1] if latest_ver.policy_decisions else None

        findings_count = len(latest_ver.findings)
        pii_count = sum(1 for f in latest_ver.findings if f.agent.lower() == "pii")

        items.append(
            DatasetItemResponse(
                dataset_id=d.dataset_id,
                version=latest_ver.version,
                filename=d.filename,
                file_type=latest_ver.file_type,
                file_size=latest_ver.file_size,
                sha256=latest_ver.sha256,
                status=latest_ver.status,
                created_at=latest_ver.created_at.isoformat() if latest_ver.created_at else "",
                record_count=latest_ver.record_count,
                risk_level=latest_risk.risk_level if latest_risk else None,
                risk_score=latest_risk.risk_score if latest_risk else None,
                opa_decision=latest_policy.decision if latest_policy else None,
                findings_count=findings_count,
                pii_count=pii_count,
            )
        )

    return items


@router.get("/{dataset_id}", response_model=DatasetDetailResponse)
async def get_dataset(dataset_id: str, db: AsyncSession = Depends(get_db)):
    """
    Retrieves dataset details and all its historical versions.
    """
    stmt = (
        select(Dataset)
        .options(
            selectinload(Dataset.versions).selectinload(DatasetVersion.risk_assessments),
            selectinload(Dataset.versions).selectinload(DatasetVersion.policy_decisions),
        )
        .where(Dataset.dataset_id == dataset_id)
    )
    result = await db.execute(stmt)
    dataset = result.scalar_one_or_none()

    if not dataset:
        raise HTTPException(status_code=404, detail="Dataset not found")

    versions_info = []
    for v in sorted(dataset.versions, key=lambda x: x.version):
        risk = v.risk_assessments[-1] if v.risk_assessments else None
        policy = v.policy_decisions[-1] if v.policy_decisions else None
        versions_info.append(
            {
                "version": v.version,
                "file_type": v.file_type,
                "file_size": v.file_size,
                "sha256": v.sha256,
                "status": v.status,
                "record_count": v.record_count,
                "signature_algorithm": v.signature_algorithm,
                "created_at": v.created_at.isoformat() if v.created_at else "",
                "risk_score": risk.risk_score if risk else None,
                "risk_level": risk.risk_level if risk else None,
                "decision": policy.decision if policy else None,
            }
        )

    current_ver = max([v.version for v in dataset.versions]) if dataset.versions else 1

    return DatasetDetailResponse(
        dataset_id=dataset.dataset_id,
        filename=dataset.filename,
        source=dataset.source,
        description=dataset.description,
        created_at=dataset.created_at.isoformat() if dataset.created_at else "",
        versions=versions_info,
        current_version=current_ver,
    )


@router.get("/{dataset_id}/versions/{version}/content")
async def get_dataset_content(
    dataset_id: str,
    version: int,
    db: AsyncSession = Depends(get_db),
):
    """
    Returns normalized dataset content (records, fields, and coordinates)
    for the interactive HITL table/viewer.
    """
    stmt = (
        select(DatasetVersion)
        .join(Dataset, Dataset.id == DatasetVersion.dataset_id)
        .where(Dataset.dataset_id == dataset_id, DatasetVersion.version == version)
    )
    result = await db.execute(stmt)
    ver = result.scalar_one_or_none()

    if not ver or not ver.storage_location:
        raise HTTPException(status_code=404, detail="Dataset version or file not found")

    path = Path(ver.storage_location)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Stored file does not exist on disk")

    normalized = normalize_dataset(path, ver.file_type)

    return {
        "dataset_id": dataset_id,
        "version": version,
        "format": normalized.format,
        "record_count": normalized.record_count,
        "columns": normalized.columns,
        "metadata": normalized.metadata,
        "records": [
            {
                "record_id": r.record_id,
                "data": r.data,
                "location": r.location,
            }
            for r in normalized.records
        ],
    }


@router.get("/{dataset_id}/versions/{version}/findings")
async def get_dataset_findings(
    dataset_id: str,
    version: int,
    db: AsyncSession = Depends(get_db),
):
    """
    Returns individual agent findings and correlated findings.
    """
    stmt = (
        select(DatasetVersion)
        .options(
            selectinload(DatasetVersion.findings),
            selectinload(DatasetVersion.correlated_findings),
            selectinload(DatasetVersion.risk_assessments),
            selectinload(DatasetVersion.policy_decisions),
        )
        .join(Dataset, Dataset.id == DatasetVersion.dataset_id)
        .where(Dataset.dataset_id == dataset_id, DatasetVersion.version == version)
    )
    result = await db.execute(stmt)
    ver = result.scalar_one_or_none()

    if not ver:
        raise HTTPException(status_code=404, detail="Dataset version not found")

    risk = ver.risk_assessments[-1] if ver.risk_assessments else None
    policy = ver.policy_decisions[-1] if ver.policy_decisions else None

    return {
        "dataset_id": dataset_id,
        "version": version,
        "status": ver.status,
        "risk_score": risk.risk_score if risk else None,
        "risk_level": risk.risk_level if risk else None,
        "decision": policy.decision if policy else None,
        "findings": [
            {
                "finding_id": f.finding_id,
                "agent": f.agent,
                "agent_name": f.agent,
                "status": f.status,
                "record_id": f.record_id,
                "field": f.field,
                "location": f.location,
                "category": f.category,
                "severity": f.severity,
                "confidence": f.confidence,
                "evidence": f.evidence,
                "reason": f.reason,
                "recommendation": f.recommendation,
                "entity_type": f.entity_type,
                "related_record_ids": f.related_record_ids,
                "model_or_provider": f.model_or_provider,
            }
            for f in ver.findings
        ],
        "correlated_findings": [
            {
                "correlation_id": cf.correlation_id,
                "record_id": cf.record_id,
                "field": cf.field,
                "location": cf.location,
                "primary_category": cf.primary_category,
                "max_severity": cf.max_severity,
                "agents_involved": cf.agents_involved,
                "finding_ids": cf.finding_ids,
                "agent_summaries": cf.agent_summaries,
            }
            for cf in ver.correlated_findings
        ],
    }


@router.post("/{dataset_id}/versions/{version}/verify", response_model=DatasetVerificationResponse)
async def verify_dataset_gate(
    dataset_id: str,
    version: int,
    db: AsyncSession = Depends(get_db),
):
    """
    Pre-training cryptographic verification gate.
    Verifies stored file, recalculates SHA-256, matches provenance, and verifies ML-DSA-65 signature.
    """
    stmt = (
        select(DatasetVersion)
        .join(Dataset, Dataset.id == DatasetVersion.dataset_id)
        .where(Dataset.dataset_id == dataset_id, DatasetVersion.version == version)
    )
    result = await db.execute(stmt)
    ver = result.scalar_one_or_none()

    if not ver:
        raise HTTPException(status_code=404, detail="Dataset version not found")

    await emit_pipeline_event("verification_started", dataset_id, version)

    verification = verify_dataset_integrity(
        file_path=ver.storage_location or "",
        stored_sha256=ver.sha256,
        provenance=ver.provenance or {},
        signature=ver.signature or "",
        public_key=ver.public_key or "",
        dataset_id=dataset_id,
        version=version,
        signature_algorithm=ver.signature_algorithm,
    )

    if verification["verification_status"] == "VERIFIED":
        ver.status = "VERIFIED"
        audit = AuditEvent(
            event_type="cryptographic_verification_passed",
            dataset_id=dataset_id,
            version=version,
            details=verification,
        )
        db.add(audit)
        await db.commit()
        await emit_pipeline_event("verification_completed", dataset_id, version, verification)
    else:
        ver.status = "BLOCKED"
        audit = AuditEvent(
            event_type="cryptographic_verification_failed",
            dataset_id=dataset_id,
            version=version,
            details=verification,
        )
        db.add(audit)
        await db.commit()
        await emit_pipeline_event("verification_failed", dataset_id, version, verification)

    return DatasetVerificationResponse(
        dataset_id=dataset_id,
        version=version,
        verification_status=verification["verification_status"],
        sha256_verified=verification["sha256_verified"],
        provenance_verified=verification["provenance_verified"],
        signature_verified=verification["signature_verified"],
        signature_algorithm=verification["signature_algorithm"],
        reason=verification["reason"],
        file_exists=verification.get("file_exists", True),
        identity_verified=verification.get("identity_verified", True),
    )


@router.post("/{dataset_id}/versions/{version}/analyze")
async def trigger_analysis(
    dataset_id: str,
    version: int,
    db: AsyncSession = Depends(get_db),
):
    """
    Triggers the 4-agent LangGraph threat intelligence pipeline.
    Must be cryptographically verified first.
    """
    stmt = (
        select(DatasetVersion)
        .join(Dataset, Dataset.id == DatasetVersion.dataset_id)
        .where(Dataset.dataset_id == dataset_id, DatasetVersion.version == version)
    )
    result = await db.execute(stmt)
    ver = result.scalar_one_or_none()

    if not ver:
        raise HTTPException(status_code=404, detail="Dataset version not found")

    # Verify first if status is still UPLOADED
    if ver.status == "UPLOADED":
        verification = verify_dataset_integrity(
            file_path=ver.storage_location or "",
            stored_sha256=ver.sha256,
            provenance=ver.provenance or {},
            signature=ver.signature or "",
            public_key=ver.public_key or "",
            dataset_id=dataset_id,
            version=version,
            signature_algorithm=ver.signature_algorithm,
        )
        if verification["verification_status"] != "VERIFIED":
            ver.status = "BLOCKED"
            await db.commit()
            raise HTTPException(
                status_code=400,
                detail=f"Cryptographic verification failed: {verification['reason']}. Dataset BLOCKED.",
            )
        ver.status = "VERIFIED"
        await db.commit()

    if ver.status == "BLOCKED":
        raise HTTPException(status_code=400, detail="Dataset is BLOCKED due to integrity failure.")

    await emit_pipeline_event("agent_started", dataset_id, version, {"stage": "all_agents"})
    res = await execute_security_pipeline(dataset_id, version, db)
    return res


class HumanReviewRequest(BaseModel):
    action: str  # "APPROVE", "REJECT", "MODIFY", "REMOVE_RECORD", "RE_ANALYZE"
    notes: str = ""
    modified_records: list[dict[str, Any]] | None = None
    removed_record_ids: list[str] | None = None


@router.post("/{dataset_id}/versions/{version}/review")
async def submit_review(
    dataset_id: str,
    version: int,
    request: HumanReviewRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Human-in-the-loop reviewer action.
    If MODIFY or REMOVE_RECORD, creates Version N+1, re-signs with ML-DSA-65,
    verifies, and re-analyzes through the complete pipeline.
    """
    return await submit_human_review(
        dataset_id=dataset_id,
        version=version,
        action=request.action,
        notes=request.notes,
        modified_records=request.modified_records,
        removed_record_ids=request.removed_record_ids,
        db=db,
    )


@router.get("/{dataset_id}/versions/{version}/authorization")
async def get_training_authorization(
    dataset_id: str,
    version: int,
    db: AsyncSession = Depends(get_db),
):
    """
    Training Access Gate endpoint.
    Determines if dataset is authorized for training and returns authorization details.
    """
    stmt = (
        select(DatasetVersion, Dataset)
        .options(
            selectinload(DatasetVersion.risk_assessments),
            selectinload(DatasetVersion.policy_decisions),
        )
        .join(Dataset, Dataset.id == DatasetVersion.dataset_id)
        .where(Dataset.dataset_id == dataset_id, DatasetVersion.version == version)
    )
    result = await db.execute(stmt)
    row = result.first()

    if not row:
        raise HTTPException(status_code=404, detail="Dataset version not found")

    ver, dataset = row
    risk = ver.risk_assessments[-1] if ver.risk_assessments else None
    policy = ver.policy_decisions[-1] if ver.policy_decisions else None

    authorized = ver.status == "APPROVED" and (policy and policy.decision == "APPROVE" or ver.status == "APPROVED")

    return {
        "dataset_id": dataset_id,
        "version": version,
        "filename": dataset.filename,
        "training_authorized": authorized,
        "status": "APPROVED" if authorized else ver.status,
        "risk_score": risk.risk_score if risk else 0,
        "risk_level": risk.risk_level if risk else "UNKNOWN",
        "opa_decision": policy.decision if policy else "UNKNOWN",
        "authorized_at": datetime.now(timezone.utc).isoformat() if authorized else None,
        "sha256": ver.sha256,
        "signature_algorithm": ver.signature_algorithm,
        "provenance": ver.provenance,
    }


@router.get("/{dataset_id}/versions/{version}/audit")
async def get_audit_trail(
    dataset_id: str,
    version: int,
    db: AsyncSession = Depends(get_db),
):
    """
    Returns complete immutable audit event history for this dataset and version.
    """
    stmt = (
        select(AuditEvent)
        .where(AuditEvent.dataset_id == dataset_id)
        .order_by(AuditEvent.timestamp.asc())
    )
    result = await db.execute(stmt)
    events = result.scalars().all()

    return [
        {
            "id": e.id,
            "event_type": e.event_type,
            "dataset_id": e.dataset_id,
            "version": e.version,
            "timestamp": e.timestamp.isoformat() if e.timestamp else "",
            "details": e.details or {},
        }
        for e in events
    ]


@router.post("/pipeline-upload")
async def pipeline_upload_and_verify(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    """
    Pipeline upload entry point:
    1. Preprocesses file, calculates hash and ML-DSA signature comparison with existing DB metadata.
    2. If no dataset found in DB or signature mismatch -> Block the dataset.
    3. If same name and type but different size or metadata -> store as version = current + 1.
    4. Executes multi-agent security pipeline.
    """
    filename = file.filename or ""
    extension = Path(filename).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file type: {extension or 'unknown'}. Allowed: .csv, .json, .txt, .xlsx",
        )

    file_type = extension.lstrip(".")
    content_bytes = await file.read()
    file_size = len(content_bytes)
    sha256 = hashlib.sha256(content_bytes).hexdigest()

    # Query DB for existing dataset with this filename
    stmt = (
        select(Dataset)
        .where(Dataset.filename == filename)
        .order_by(desc(Dataset.created_at))
        .options(
            selectinload(Dataset.versions).selectinload(DatasetVersion.risk_assessments),
            selectinload(Dataset.versions).selectinload(DatasetVersion.policy_decisions),
        )
    )
    result = await db.execute(stmt)
    existing_dataset = result.scalars().first()

    if not existing_dataset or not existing_dataset.versions:
        # Case 1: Unregistered dataset in Data Collection -> BLOCK
        dataset_id = f"DS-{uuid4().hex[:12].upper()}"
        version = 1

        dest_dir = Path("data/uploads") / dataset_id / f"v{version}"
        dest_dir.mkdir(parents=True, exist_ok=True)
        stored_path = dest_dir / filename
        with open(stored_path, "wb") as f:
            f.write(content_bytes)

        processing_summary = validate_and_process(stored_path, extension)

        ds = Dataset(
            dataset_id=dataset_id,
            filename=filename,
            source="pipeline_direct_upload",
            description="Direct upload to pipeline without prior data collection ingestion",
        )
        dv = DatasetVersion(
            version=version,
            file_type=file_type,
            file_size=file_size,
            sha256=sha256,
            signature_algorithm="ML-DSA-65",
            signature="",
            public_key="",
            provenance=None,
            status="BLOCKED",
            storage_location=str(stored_path),
            record_count=processing_summary.get("record_count") or processing_summary.get("rows"),
        )
        policy_dec = PolicyDecision(
            decision="REJECT",
            reasons=["Blocked: Dataset not registered in Data Collection registry. Pre-training provenance attestation missing."],
            policy_input={"cryptographic_verified": False, "filename": filename},
            policy_output={"decision": "REJECT"},
        )
        audit = AuditEvent(
            event_type="cryptographic_verification_failed",
            dataset_id=dataset_id,
            version=version,
            details={"reason": "Unregistered dataset in data collection repository. Blocked by security gateway."},
        )
        ds.versions.append(dv)
        dv.policy_decisions.append(policy_dec)
        db.add(ds)
        db.add(audit)
        await db.commit()

        await emit_pipeline_event("verification_failed", dataset_id, version, {
            "reason": "Dataset not registered in Data Collection registry. Pre-training provenance attestation missing."
        })

        return {
            "dataset_id": dataset_id,
            "version": version,
            "filename": filename,
            "file_size": file_size,
            "status": "BLOCKED",
            "blocked": True,
            "decision": "REJECT",
            "risk_score": 100,
            "risk_level": "CRITICAL",
            "findings_count": 0,
            "reason": "Dataset not registered in Data Collection registry. Pre-training provenance attestation missing.",
            "sha256": sha256,
        }

    # Case 2: Dataset exists in DB. Check latest version.
    latest_ver = max(existing_dataset.versions, key=lambda v: v.version)

    if file_size != latest_ver.file_size or sha256 != latest_ver.sha256:
        # Case 2A: Same name and type, but different size/metadata -> store as version = current + 1
        new_version = latest_ver.version + 1
        dest_dir = Path("data/uploads") / existing_dataset.dataset_id / f"v{new_version}"
        dest_dir.mkdir(parents=True, exist_ok=True)
        stored_path = dest_dir / filename
        with open(stored_path, "wb") as f:
            f.write(content_bytes)

        processing_summary = validate_and_process(stored_path, extension)

        provenance = create_provenance(
            dataset_id=existing_dataset.dataset_id,
            version=new_version,
            filename=filename,
            file_type=file_type,
            file_size=file_size,
            sha256=sha256,
            source="pipeline_version_update",
        )
        signature = sign_provenance(provenance)
        public_key = get_public_key()

        new_dv = DatasetVersion(
            version=new_version,
            file_type=file_type,
            file_size=file_size,
            sha256=sha256,
            signature_algorithm="ML-DSA-65",
            signature=signature,
            public_key=public_key,
            provenance=provenance,
            status="VERIFIED",
            storage_location=str(stored_path),
            record_count=processing_summary.get("record_count") or processing_summary.get("rows"),
        )
        audit_ver = AuditEvent(
            event_type="new_version_created",
            dataset_id=existing_dataset.dataset_id,
            version=new_version,
            details={"filename": filename, "version": new_version, "reason": "Uploaded dataset metadata difference detected."},
        )
        audit_pass = AuditEvent(
            event_type="cryptographic_verification_passed",
            dataset_id=existing_dataset.dataset_id,
            version=new_version,
            details={"sha256": sha256, "signature_algorithm": "ML-DSA-65"},
        )
        existing_dataset.versions.append(new_dv)
        db.add(audit_ver)
        db.add(audit_pass)
        await db.commit()

        target_dataset_id = existing_dataset.dataset_id
        target_version = new_version
    else:
        # Case 2B: Same metadata -> compare signature with registered DB provenance
        target_dataset_id = existing_dataset.dataset_id
        target_version = latest_ver.version

        sig_valid = False
        if latest_ver.signature and latest_ver.public_key and latest_ver.provenance:
            try:
                sig_valid = verify_signature(latest_ver.provenance, latest_ver.signature, latest_ver.public_key)
            except Exception:
                sig_valid = False

        if not sig_valid:
            latest_ver.status = "BLOCKED"
            audit_fail = AuditEvent(
                event_type="cryptographic_verification_failed",
                dataset_id=target_dataset_id,
                version=target_version,
                details={"reason": "Signature verification failed against registered provenance."},
            )
            db.add(audit_fail)
            await db.commit()

            await emit_pipeline_event("verification_failed", target_dataset_id, target_version, {
                "reason": "Cryptographic signature mismatch. Dataset has been tampered or signature invalid."
            })

            return {
                "dataset_id": target_dataset_id,
                "version": target_version,
                "filename": filename,
                "file_size": file_size,
                "status": "BLOCKED",
                "blocked": True,
                "decision": "REJECT",
                "risk_score": 100,
                "risk_level": "CRITICAL",
                "findings_count": 0,
                "reason": "Cryptographic signature mismatch. Dataset has been tampered or signature invalid.",
                "sha256": sha256,
            }

        latest_ver.status = "VERIFIED"
        await db.commit()

    # Multi-agent pipeline analysis
    pipeline_res = await execute_security_pipeline(
        dataset_id=target_dataset_id,
        version=target_version,
        db=db,
    )

    return {
        "dataset_id": target_dataset_id,
        "version": target_version,
        "filename": filename,
        "file_size": file_size,
        "status": "VERIFIED",
        "blocked": False,
        "decision": pipeline_res.get("decision", "APPROVE"),
        "risk_score": pipeline_res.get("risk_score", 0),
        "risk_level": pipeline_res.get("risk_level", "LOW"),
        "findings_count": pipeline_res.get("findings_count", 0),
        "sha256": sha256,
    }


@router.get("/{dataset_id}/versions/{version}/download")
async def download_dataset(
    dataset_id: str,
    version: int,
    db: AsyncSession = Depends(get_db),
):
    """
    Downloads authorized dataset file for model training.
    """
    stmt = (
        select(DatasetVersion, Dataset)
        .join(Dataset, Dataset.id == DatasetVersion.dataset_id)
        .where(Dataset.dataset_id == dataset_id, DatasetVersion.version == version)
    )
    result = await db.execute(stmt)
    row = result.first()

    if not row:
        raise HTTPException(status_code=404, detail="Dataset version not found")

    ver, dataset = row
    if not ver.storage_location or not Path(ver.storage_location).exists():
        raise HTTPException(status_code=404, detail="Dataset file not found on disk")

    clean_filename = f"{dataset.filename or 'dataset'}"
    return FileResponse(
        path=ver.storage_location,
        filename=clean_filename,
        media_type="application/octet-stream",
    )

from datetime import datetime, timezone
import logging
from pathlib import Path
from typing import Any
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AuditEvent, Dataset, DatasetVersion, HumanReview
from app.events.manager import emit_pipeline_event
from app.services.cryptography import (
    create_provenance,
    get_public_key,
    sign_provenance,
)
from app.services.dataset_processor import write_modified_dataset
from app.services.hashing import calculate_sha256
from app.services.verification import verify_dataset_integrity
from app.workflows.orchestrator import execute_security_pipeline

logger = logging.getLogger("gateway.review")


async def submit_human_review(
    dataset_id: str,
    version: int,
    action: str,  # "APPROVE", "REJECT", "MODIFY", "REMOVE_RECORD", "RE_ANALYZE"
    notes: str = "",
    modified_records: list[dict[str, Any]] | None = None,
    removed_record_ids: list[str] | None = None,
    db: AsyncSession | None = None,
) -> dict[str, Any]:
    """
    Handles reviewer actions on quarantined datasets:
    - APPROVE: Marks version as APPROVED.
    - REJECT: Marks version as REJECTED.
    - RE_ANALYZE: Re-runs the agent pipeline on this version.
    - MODIFY / REMOVE_RECORD: Creates Version N+1, re-hashes, re-signs with ML-DSA-65,
      verifies, and re-analyzes through the complete security pipeline.
    """
    if db is None:
        raise ValueError("Database session required.")

    result = await db.execute(
        select(DatasetVersion, Dataset)
        .join(Dataset, Dataset.id == DatasetVersion.dataset_id)
        .where(Dataset.dataset_id == dataset_id, DatasetVersion.version == version)
    )
    row = result.first()
    if not row:
        raise ValueError(f"Dataset {dataset_id} version {version} not found.")

    dataset_version, dataset = row
    action_upper = action.upper().strip()

    # 1. Simple Review Approvals / Rejections
    if action_upper == "APPROVE":
        dataset_version.status = "APPROVED"
        review = HumanReview(
            version_id=dataset_version.id,
            action="APPROVE",
            notes=notes,
            changes_summary=None,
        )
        audit = AuditEvent(
            event_type="human_review_approved",
            dataset_id=dataset_id,
            version=version,
            details={"notes": notes, "action": "APPROVE"},
        )
        db.add(review)
        db.add(audit)
        await db.commit()

        await emit_pipeline_event("approved", dataset_id, version, {"action": "human_approved"})
        return {"status": "APPROVED", "dataset_id": dataset_id, "version": version}

    elif action_upper == "REJECT":
        dataset_version.status = "REJECTED"
        review = HumanReview(
            version_id=dataset_version.id,
            action="REJECT",
            notes=notes,
            changes_summary=None,
        )
        audit = AuditEvent(
            event_type="human_review_rejected",
            dataset_id=dataset_id,
            version=version,
            details={"notes": notes, "action": "REJECT"},
        )
        db.add(review)
        db.add(audit)
        await db.commit()

        await emit_pipeline_event("rejected", dataset_id, version, {"action": "human_rejected"})
        return {"status": "REJECTED", "dataset_id": dataset_id, "version": version}

    elif action_upper == "RE_ANALYZE":
        await emit_pipeline_event("agent_started", dataset_id, version, {"trigger": "re_analysis"})
        analysis_res = await execute_security_pipeline(dataset_id, version, db)
        return analysis_res

    # 2. Modifications or Record Removals -> Creates Version N+1
    elif action_upper in ["MODIFY", "REMOVE_RECORD", "REMOVE"] or modified_records or removed_record_ids:
        new_version_num = version + 1
        orig_file = Path(dataset_version.storage_location)
        if not orig_file.exists():
            raise FileNotFoundError(f"Original dataset file {orig_file} not found.")

        # Destination path for new version
        new_dest = orig_file.parent / f"{dataset_id}_v{new_version_num}_{dataset.filename}"

        mods = modified_records or []
        removals = set(removed_record_ids or [])

        # Write modified dataset file preserving original format
        write_modified_dataset(
            original_path=orig_file,
            output_path=new_dest,
            file_type=dataset_version.file_type,
            modified_records=mods,
            removed_record_ids=removals,
        )

        new_size = new_dest.stat().st_size
        new_sha256 = calculate_sha256(new_dest)

        # Create and sign new technical provenance bound to new version
        new_provenance = create_provenance(
            dataset_id=dataset_id,
            version=new_version_num,
            filename=dataset.filename,
            file_type=dataset_version.file_type,
            file_size=new_size,
            sha256=new_sha256,
            source="human_review_remediation",
        )
        new_signature = sign_provenance(new_provenance)
        public_key = get_public_key()

        # Create new DatasetVersion record
        new_ver_model = DatasetVersion(
            dataset_id=dataset.id,
            version=new_version_num,
            file_type=dataset_version.file_type,
            file_size=new_size,
            sha256=new_sha256,
            signature_algorithm="ML-DSA-65",
            signature=new_signature,
            public_key=public_key,
            provenance=new_provenance,
            status="UPLOADED",
            storage_location=str(new_dest),
        )
        db.add(new_ver_model)
        await db.flush()

        # Record HumanReview on original version
        changes_summary = {
            "modified_count": len(mods),
            "removed_count": len(removals),
            "removed_ids": list(removals),
            "created_version": new_version_num,
        }
        review = HumanReview(
            version_id=dataset_version.id,
            action=action_upper,
            notes=notes,
            changes_summary=changes_summary,
        )
        db.add(review)

        # Audit event for new version creation
        audit = AuditEvent(
            event_type="new_version_created",
            dataset_id=dataset_id,
            version=new_version_num,
            details={
                "previous_version": version,
                "changes_summary": changes_summary,
                "sha256": new_sha256,
            },
        )
        db.add(audit)
        await db.commit()

        await emit_pipeline_event(
            "dataset_uploaded",
            dataset_id,
            new_version_num,
            {"created_version": new_version_num, "sha256": new_sha256},
        )

        # Verify new version cryptographically
        verification = verify_dataset_integrity(
            file_path=new_dest,
            stored_sha256=new_sha256,
            provenance=new_provenance,
            signature=new_signature,
            public_key=public_key,
            dataset_id=dataset_id,
            version=new_version_num,
            signature_algorithm="ML-DSA-65",
        )

        if verification["verification_status"] == "VERIFIED":
            await emit_pipeline_event("verification_completed", dataset_id, new_version_num, verification)
            # Run security pipeline automatically on Version N+1
            pipeline_result = await execute_security_pipeline(dataset_id, new_version_num, db)
            return {
                "status": "VERSION_CREATED_AND_ANALYZED",
                "previous_version": version,
                "new_version": new_version_num,
                "pipeline_result": pipeline_result,
            }
        else:
            await emit_pipeline_event("verification_failed", dataset_id, new_version_num, verification)
            return {
                "status": "BLOCKED",
                "new_version": new_version_num,
                "reason": verification["reason"],
            }

    else:
        raise ValueError(f"Unsupported action: {action}")

from pathlib import Path

from app.services.cryptography import verify_provenance
from app.services.hashing import calculate_sha256

EXPECTED_SIGNATURE_ALGORITHM = "ML-DSA-65"


def verify_dataset_integrity(
    file_path: str | Path,
    stored_sha256: str,
    provenance: dict,
    signature: str,
    public_key: str,
    dataset_id: str,
    version: int,
    signature_algorithm: str | None,
) -> dict:
    """
    Performs the complete pre-training verification.

    Checks:
    1. SHA-256 of the stored file
    2. SHA-256 recorded inside provenance
    3. Dataset identity/version inside provenance
    4. Signature algorithm
    5. ML-DSA signature
    """

    current_sha256 = calculate_sha256(file_path)

    sha256_verified = current_sha256 == stored_sha256

    provenance_sha256_verified = provenance.get("sha256") == current_sha256

    provenance_identity_verified = (
        provenance.get("dataset_id") == dataset_id
        and provenance.get("version") == version
    )

    provenance_verified = provenance_sha256_verified and provenance_identity_verified

    signature_algorithm_verified = signature_algorithm == EXPECTED_SIGNATURE_ALGORITHM

    signature_verified = False

    if (
        sha256_verified
        and provenance_verified
        and signature_algorithm_verified
        and signature
        and public_key
    ):
        signature_verified = verify_provenance(
            provenance=provenance,
            signature_b64=signature,
            public_key_b64=public_key,
        )

    if not sha256_verified:
        return {
            "verification_status": "BLOCKED",
            "sha256_verified": False,
            "provenance_verified": provenance_verified,
            "signature_verified": signature_verified,
            "reason": "SHA-256 hash mismatch",
        }

    if not provenance_verified:
        return {
            "verification_status": "BLOCKED",
            "sha256_verified": True,
            "provenance_verified": False,
            "signature_verified": signature_verified,
            "reason": "Provenance verification failed",
        }

    if not signature_algorithm_verified:
        return {
            "verification_status": "BLOCKED",
            "sha256_verified": True,
            "provenance_verified": True,
            "signature_verified": False,
            "reason": "Unsupported or unexpected signature algorithm",
        }

    if not signature_verified:
        return {
            "verification_status": "BLOCKED",
            "sha256_verified": True,
            "provenance_verified": True,
            "signature_verified": False,
            "reason": "ML-DSA-65 signature verification failed",
        }

    return {
        "verification_status": "VERIFIED",
        "sha256_verified": True,
        "provenance_verified": True,
        "signature_verified": True,
        "reason": "VERIFIED",
    }

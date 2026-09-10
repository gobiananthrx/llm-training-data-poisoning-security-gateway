from pathlib import Path
from typing import Any

from app.services.cryptography import verify_provenance
from app.services.hashing import calculate_sha256

EXPECTED_SIGNATURE_ALGORITHM = "ML-DSA-65"


def verify_dataset_integrity(
    file_path: str | Path,
    stored_sha256: str,
    provenance: dict[str, Any],
    signature: str,
    public_key: str,
    dataset_id: str,
    version: int,
    signature_algorithm: str | None,
) -> dict[str, Any]:
    """
    Performs the complete pre-training cryptographic verification.

    Checks:
    1. Stored file exists
    2. Recalculate SHA-256
    3. Compare against stored SHA-256
    4. Compare against provenance SHA-256
    5. Verify Dataset ID matches provenance
    6. Verify Version matches provenance
    7. Verify signature algorithm is ML-DSA-65
    8. Verify ML-DSA-65 digital signature
    """
    path = Path(file_path)
    if not path.exists():
        return {
            "verification_status": "BLOCKED",
            "file_exists": False,
            "sha256_verified": False,
            "provenance_verified": False,
            "signature_verified": False,
            "identity_verified": False,
            "signature_algorithm": signature_algorithm or "UNKNOWN",
            "reason": "Stored dataset file not found.",
        }

    # 1. Recalculate SHA-256
    current_sha256 = calculate_sha256(path)
    sha256_verified = current_sha256.lower() == stored_sha256.lower()

    # 2. Check provenance SHA-256
    prov_sha256 = provenance.get("sha256", "")
    provenance_sha256_verified = prov_sha256.lower() == current_sha256.lower()

    # 3. Check dataset ID and version inside provenance
    identity_verified = (
        provenance.get("dataset_id") == dataset_id
        and provenance.get("version") == version
    )

    provenance_verified = provenance_sha256_verified and identity_verified

    # 4. Signature algorithm check
    sig_alg = signature_algorithm or provenance.get("signature_algorithm")
    signature_algorithm_verified = sig_alg == EXPECTED_SIGNATURE_ALGORITHM

    # 5. ML-DSA signature check
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

    # Determine failure reasons
    if not sha256_verified:
        return {
            "verification_status": "BLOCKED",
            "file_exists": True,
            "sha256_verified": False,
            "provenance_verified": provenance_verified,
            "signature_verified": signature_verified,
            "identity_verified": identity_verified,
            "signature_algorithm": sig_alg or "UNKNOWN",
            "reason": "SHA-256 hash mismatch. File may have been altered.",
        }

    if not provenance_verified:
        return {
            "verification_status": "BLOCKED",
            "file_exists": True,
            "sha256_verified": True,
            "provenance_verified": False,
            "signature_verified": signature_verified,
            "identity_verified": identity_verified,
            "signature_algorithm": sig_alg or "UNKNOWN",
            "reason": "Provenance metadata mismatch with dataset identity or hash.",
        }

    if not signature_algorithm_verified:
        return {
            "verification_status": "BLOCKED",
            "file_exists": True,
            "sha256_verified": True,
            "provenance_verified": True,
            "signature_verified": False,
            "identity_verified": True,
            "signature_algorithm": sig_alg or "UNKNOWN",
            "reason": f"Unexpected signature algorithm: {sig_alg}. Expected {EXPECTED_SIGNATURE_ALGORITHM}.",
        }

    if not signature_verified:
        return {
            "verification_status": "BLOCKED",
            "file_exists": True,
            "sha256_verified": True,
            "provenance_verified": True,
            "signature_verified": False,
            "identity_verified": True,
            "signature_algorithm": sig_alg or "UNKNOWN",
            "reason": "ML-DSA-65 post-quantum digital signature verification failed.",
        }

    return {
        "verification_status": "VERIFIED",
        "file_exists": True,
        "sha256_verified": True,
        "provenance_verified": True,
        "signature_verified": True,
        "identity_verified": True,
        "signature_algorithm": EXPECTED_SIGNATURE_ALGORITHM,
        "reason": "Cryptographically verified. Stored hash, provenance, and ML-DSA-65 signature match.",
    }

import base64
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

import oqs

ALGORITHM = "ML-DSA-65"

KEYS_DIR = Path(__file__).resolve().parents[2] / "keys"
PRIVATE_KEY_PATH = KEYS_DIR / "mldsa65_private.key"
PUBLIC_KEY_PATH = KEYS_DIR / "mldsa65_public.key"


def _ensure_keys():
    KEYS_DIR.mkdir(parents=True, exist_ok=True)

    private_exists = PRIVATE_KEY_PATH.exists()
    public_exists = PUBLIC_KEY_PATH.exists()

    if private_exists and public_exists:
        return

    if private_exists != public_exists:
        raise RuntimeError(
            "Incomplete ML-DSA key pair. Both private and public keys must exist."
        )

    signer = oqs.Signature(ALGORITHM)

    public_key = signer.generate_keypair()
    secret_key = signer.export_secret_key()

    PRIVATE_KEY_PATH.write_bytes(secret_key)
    PUBLIC_KEY_PATH.write_bytes(public_key)

    PRIVATE_KEY_PATH.chmod(0o600)
    PUBLIC_KEY_PATH.chmod(0o644)


def _load_private_key() -> bytes:
    _ensure_keys()
    return PRIVATE_KEY_PATH.read_bytes()


def _load_public_key() -> bytes:
    _ensure_keys()
    return PUBLIC_KEY_PATH.read_bytes()


def create_provenance(
    dataset_id: str,
    version: int,
    filename: str,
    file_type: str,
    file_size: int,
    sha256: str,
    source: str,
    timestamp: str | None = None,
) -> dict[str, Any]:
    """
    Create the technical provenance information bound to a dataset version.
    """
    if not timestamp:
        timestamp = datetime.now(timezone.utc).isoformat()

    return {
        "dataset_id": dataset_id,
        "version": version,
        "filename": filename,
        "file_type": file_type,
        "file_size": file_size,
        "sha256": sha256,
        "source": source,
        "signature_algorithm": ALGORITHM,
        "timestamp": timestamp,
    }


def canonicalize_payload(payload: dict[str, Any]) -> bytes:
    """
    Deterministic RFC 8785-compliant JSON canonicalization.
    Keys are sorted, whitespace eliminated, UTF-8 encoded.
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sign_provenance(provenance: dict[str, Any]) -> str:
    """
    Sign the canonical provenance payload using ML-DSA-65.

    Returns:
        Base64 encoded signature.
    """
    secret_key = _load_private_key()
    signer = oqs.Signature(ALGORITHM, secret_key=secret_key)

    message = canonicalize_payload(provenance)
    signature = signer.sign(message)

    return base64.b64encode(signature).decode("ascii")


def get_public_key() -> str:
    """
    Return the ML-DSA-65 public key as Base64.
    """
    public_key = _load_public_key()
    return base64.b64encode(public_key).decode("ascii")


def verify_provenance(
    provenance: dict[str, Any],
    signature_b64: str,
    public_key_b64: str,
) -> bool:
    """
    Verify an ML-DSA-65 signature against the canonical provenance.
    """
    try:
        message = canonicalize_payload(provenance)
        signature = base64.b64decode(signature_b64.encode("ascii"))
        public_key = base64.b64decode(public_key_b64.encode("ascii"))

        verifier = oqs.Signature(ALGORITHM)
        return verifier.verify(
            message,
            signature,
            public_key,
        )
    except Exception:
        return False


verify_signature = verify_provenance

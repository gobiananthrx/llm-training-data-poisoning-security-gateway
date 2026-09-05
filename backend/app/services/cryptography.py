import base64
import json
from pathlib import Path

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
            "Incomplete ML-DSA key pair. " "Both private and public keys must exist."
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
) -> dict:
    """
    Create the provenance information associated with a dataset version.
    """

    return {
        "dataset_id": dataset_id,
        "version": version,
        "filename": filename,
        "file_type": file_type,
        "file_size": file_size,
        "sha256": sha256,
        "source": source,
        "signature_algorithm": ALGORITHM,
    }


def _canonicalize_provenance(provenance: dict) -> bytes:
    """
    Convert provenance to deterministic bytes before signing.

    sort_keys=True ensures that the same provenance produces
    exactly the same byte sequence.
    """

    canonical_json = json.dumps(
        provenance,
        sort_keys=True,
        separators=(",", ":"),
    )

    return canonical_json.encode("utf-8")


def sign_provenance(provenance: dict) -> str:
    """
    Sign the canonical provenance payload using ML-DSA-65.

    Returns:
        Base64 encoded signature.
    """

    secret_key = _load_private_key()

    signer = oqs.Signature(ALGORITHM, secret_key=secret_key)

    message = _canonicalize_provenance(provenance)
    signature = signer.sign(message)

    return base64.b64encode(signature).decode("ascii")


def get_public_key() -> str:
    """
    Return the ML-DSA-65 public key as Base64.
    """

    public_key = _load_public_key()

    return base64.b64encode(public_key).decode("ascii")


def verify_provenance(
    provenance: dict,
    signature_b64: str,
    public_key_b64: str,
) -> bool:
    """
    Verify an ML-DSA-65 signature against the supplied provenance.
    """

    try:
        message = _canonicalize_provenance(provenance)

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

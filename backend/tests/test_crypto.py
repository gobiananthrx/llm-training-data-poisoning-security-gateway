from pathlib import Path
import pytest
from app.services.cryptography import (
    canonicalize_payload,
    create_provenance,
    get_public_key,
    sign_provenance,
    verify_provenance,
)
from app.services.hashing import calculate_sha256
from app.services.verification import verify_dataset_integrity


def test_sha256_calculation(tmp_path):
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello, dataset security gateway!", encoding="utf-8")
    digest = calculate_sha256(test_file)
    assert len(digest) == 64
    assert isinstance(digest, str)

    # Identical content produces identical hash
    test_file_2 = tmp_path / "test_copy.txt"
    test_file_2.write_text("Hello, dataset security gateway!", encoding="utf-8")
    assert calculate_sha256(test_file_2) == digest


def test_deterministic_canonicalization():
    payload_a = {"b": 2, "a": 1, "z": [3, 2, 1]}
    payload_b = {"a": 1, "z": [3, 2, 1], "b": 2}
    bytes_a = canonicalize_payload(payload_a)
    bytes_b = canonicalize_payload(payload_b)
    assert bytes_a == bytes_b
    assert bytes_a == b'{"a":1,"b":2,"z":[3,2,1]}'


def test_mldsa65_sign_and_verify():
    provenance = create_provenance(
        dataset_id="DS-TEST0001",
        version=1,
        filename="test.csv",
        file_type="csv",
        file_size=1024,
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        source="unit_test",
        timestamp="2026-09-10T12:00:00Z",
    )
    sig = sign_provenance(provenance)
    pub_key = get_public_key()
    assert sig is not None and len(sig) > 100
    assert pub_key is not None and len(pub_key) > 100

    # Verification of unmodified provenance
    is_valid = verify_provenance(provenance, sig, pub_key)
    assert is_valid is True

    # Tampered provenance field (e.g. modified hash) must fail
    tampered_provenance = dict(provenance)
    tampered_provenance["sha256"] = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    assert verify_provenance(tampered_provenance, sig, pub_key) is False

    # Tampered version must fail
    tampered_ver = dict(provenance)
    tampered_ver["version"] = 2
    assert verify_provenance(tampered_ver, sig, pub_key) is False


def test_dataset_integrity_verification(tmp_path):
    dataset_file = tmp_path / "valid_data.csv"
    dataset_file.write_text("col_a,col_b\n1,2\n3,4", encoding="utf-8")
    file_hash = calculate_sha256(dataset_file)
    file_size = dataset_file.stat().st_size

    provenance = create_provenance(
        dataset_id="DS-VALID001",
        version=1,
        filename="valid_data.csv",
        file_type="csv",
        file_size=file_size,
        sha256=file_hash,
        source="unit_test",
    )
    sig = sign_provenance(provenance)
    pub_key = get_public_key()

    # Successful verification
    res = verify_dataset_integrity(
        file_path=dataset_file,
        stored_sha256=file_hash,
        provenance=provenance,
        signature=sig,
        public_key=pub_key,
        dataset_id="DS-VALID001",
        version=1,
        signature_algorithm="ML-DSA-65",
    )
    assert res["verification_status"] == "VERIFIED"
    assert res["sha256_verified"] is True
    assert res["signature_verified"] is True

    # Tamper with file contents on disk
    dataset_file.write_text("col_a,col_b\n1,2\n3,4\nTAMPERED_ROW", encoding="utf-8")
    tampered_res = verify_dataset_integrity(
        file_path=dataset_file,
        stored_sha256=file_hash,
        provenance=provenance,
        signature=sig,
        public_key=pub_key,
        dataset_id="DS-VALID001",
        version=1,
        signature_algorithm="ML-DSA-65",
    )
    assert tampered_res["verification_status"] == "BLOCKED"
    assert tampered_res["sha256_verified"] is False

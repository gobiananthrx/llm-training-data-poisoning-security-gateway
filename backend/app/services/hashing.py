import hashlib
from pathlib import Path

CHUNK_SIZE = 1024 * 1024

def calculate_sha256(file_path: str | Path) -> str:
    digest = hashlib.sha256()

    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(CHUNK_SIZE), b""):
            digest.update(chunk)

    return digest.hexdigest()

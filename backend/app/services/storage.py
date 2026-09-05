from pathlib import Path

from fastapi import UploadFile

# Development storage only. The service boundary is intentionally isolated so
# this can be replaced by S3/object storage without changing the API layer.

BASE_DIR = Path(__file__).resolve().parents[2] / "storage" / "incoming"

async def save_upload(
    file: UploadFile,
    dataset_id: str,
    version: int,
) -> tuple[str, int]:
    BASE_DIR.mkdir(parents=True, exist_ok=True)

    filename = Path(file.filename or "dataset").name
    destination = BASE_DIR / f"{dataset_id}_v{version}_{filename}"

    size = 0
    with destination.open("wb") as output:
        while chunk := await file.read(1024 * 1024):
            output.write(chunk)
            size += len(chunk)

    await file.close()
    return str(destination), size

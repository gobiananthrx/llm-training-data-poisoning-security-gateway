import asyncio

from sqlalchemy import select

from app.db.database import AsyncSessionLocal
from app.db.models import Dataset, DatasetVersion
from app.services.cryptography import verify_provenance

DATASET_ID = "DS-B47B2230C225"


async def main():
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(DatasetVersion).join(Dataset).where(Dataset.dataset_id == DATASET_ID)
        )

        dataset_version = result.scalar_one()

        provenance = dataset_version.provenance
        signature = dataset_version.signature
        public_key = dataset_version.public_key

        print("Dataset:", DATASET_ID)
        print("Algorithm:", dataset_version.signature_algorithm)

        valid = verify_provenance(
            provenance=provenance,
            signature_b64=signature,
            public_key_b64=public_key,
        )

        print("Original provenance verification:", valid)

        # Deliberately modify the signed provenance.
        tampered_provenance = dict(provenance)
        tampered_provenance["sha256"] = "tampered"

        tampered_valid = verify_provenance(
            provenance=tampered_provenance,
            signature_b64=signature,
            public_key_b64=public_key,
        )

        print("Tampered provenance verification:", tampered_valid)


if __name__ == "__main__":
    asyncio.run(main())

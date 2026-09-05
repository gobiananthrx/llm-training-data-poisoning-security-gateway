import hashlib
import oqs

ALGORITHM = "ML-DSA-65"
FILE_PATH = "dummy_dataset.csv"


# 1. Read the complete dataset file
with open(FILE_PATH, "rb") as f:
    file_bytes = f.read()


# 2. Calculate SHA-256 of the complete file
dataset_hash = hashlib.sha256(file_bytes).hexdigest()

print("Dataset SHA-256:")
print(dataset_hash)


# 3. Generate ML-DSA-65 key pair
signer = oqs.Signature(ALGORITHM)

public_key = signer.generate_keypair()
secret_key = signer.export_secret_key()

print("\nPublic key size:", len(public_key), "bytes")
print("Secret key size:", len(secret_key), "bytes")


# 4. Sign the SHA-256 hash
message = dataset_hash.encode("utf-8")

signature = signer.sign(message)

print("Signature size:", len(signature), "bytes")


# 5. Verify the signature
verifier = oqs.Signature(ALGORITHM)

valid = verifier.verify(
    message,
    signature,
    public_key,
)

print("\nOriginal hash verification:", valid)


# 6. Test tampering
tampered_hash = "0000000000000000000000000000000000000000000000000000000000000000"

tampered_message = tampered_hash.encode("utf-8")

tampered_valid = verifier.verify(
    tampered_message,
    signature,
    public_key,
)

print("Tampered hash verification:", tampered_valid)

# Dataset Security Gateway — Linux Setup

This README contains the complete setup and execution commands for the backend on a fresh Ubuntu/Debian Linux machine.

The current backend scope is:

```text
User Upload
    ↓
Next.js UI
    ↓
FastAPI Upload API
    ↓
Pydantic Validation
    ↓
Dataset Processing
    ↓
Dataset Identity & Versioning
    ↓
SHA-256 Hash
    ↓
ML-DSA-65 Cryptographic Provenance
    ↓
PostgreSQL
    ↓
Pre-Training Verification
    ↓
VERIFIED / BLOCKED
    ↓
Handoff to AI Agent Workflow
```

---

## 1. Install System Packages

```bash
sudo apt update

sudo apt install -y \
    git \
    curl \
    build-essential \
    cmake \
    pkg-config \
    python3 \
    python3-pip \
    python3-venv \
    postgresql \
    postgresql-contrib
```

Check the installations:

```bash
python3 --version
pip3 --version
cmake --version
psql --version
```

Python should ideally be Python 3.12.x.

---

## 2. Start PostgreSQL

```bash
sudo systemctl enable postgresql
sudo systemctl start postgresql
```

Check PostgreSQL:

```bash
sudo systemctl status postgresql
```

Or:

```bash
pg_isready
```

Expected:

```text
accepting connections
```

---

## 3. Create the PostgreSQL Database

Open PostgreSQL:

```bash
sudo -u postgres psql
```

Inside `psql`:

```sql
CREATE DATABASE dataset_security;
```

Check the database:

```sql
\l
```

Exit:

```sql
\q
```

If `dataset_security` already exists, do not create it again.

---

## 4. Configure PostgreSQL Username and Password

The current development `.env` uses:

```text
postgres:postgres
```

Set the password for the default `postgres` user:

```bash
sudo -u postgres psql
```

Inside PostgreSQL:

```sql
ALTER USER postgres WITH PASSWORD 'postgres';
\q
```

Test the connection:

```bash
psql -h localhost -U postgres -d dataset_security
```

Enter:

```text
postgres
```

Then exit:

```sql
\q
```

---

## 5. Clone the Project

Replace `<YOUR_GITHUB_REPOSITORY_URL>` with the actual repository URL.

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
```

Enter the project:

```bash
cd dataset-security-gateway
```

Enter the backend:

```bash
cd backend
```

---

## 6. Create the Python Virtual Environment

```bash
python3 -m venv .venv
```

Activate it:

```bash
source .venv/bin/activate
```

Check which Python is being used:

```bash
which python
```

It should show something similar to:

```text
/home/<username>/dataset-security-gateway/backend/.venv/bin/python
```

Upgrade pip:

```bash
python -m pip install --upgrade pip
```

---

## 7. Install Python Packages

Install the project dependencies:

```bash
pip install -r requirements.txt
```

Install the Python binding for liboqs:

```bash
pip install liboqs-python
```

Check that liboqs can be imported:

```bash
python -c "import oqs; print('liboqs imported successfully')"
```

---

## 8. Verify ML-DSA-65 Support

Check whether ML-DSA-65 is available:

```bash
python -c "import oqs; print('ML-DSA-65' in oqs.get_enabled_sig_mechanisms())"
```

Expected:

```text
True
```

To display all enabled signature mechanisms:

```bash
python -c "import oqs; print(oqs.get_enabled_sig_mechanisms())"
```

The liboqs installation should provide ML-DSA algorithms, including:

```text
ML-DSA-44
ML-DSA-65
ML-DSA-87
```

The application uses:

```text
ML-DSA-65
```

---

## 9. Create the `.env` File

From:

```text
dataset-security-gateway/backend
```

run:

```bash
nano .env
```

Add:

```env
ENVIRONMENT=development

DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/dataset_security

OBJECT_STORAGE_ENDPOINT=http://localhost:9000
OBJECT_STORAGE_BUCKET=datasets
OBJECT_STORAGE_REGION=ap-south-1

CORS_ORIGINS=http://localhost:3000
```

Save in nano:

```text
Ctrl + O
Enter
Ctrl + X
```

### Important

Do not commit `.env` to Git.

Your `.gitignore` should contain:

```gitignore
.venv/
__pycache__/
*.pyc
.env
keys/
storage/
*.log
.DS_Store
```

---

## 10. Run Database Migrations

The project already contains the Alembic migrations.

Apply them:

```bash
alembic upgrade head
```

Check the current migration:

```bash
alembic current
```

The current migration should be at:

```text
(head)
```

Check whether the SQLAlchemy models and migrations are synchronized:

```bash
alembic check
```

Expected:

```text
No new upgrade operations detected.
```

Do NOT run `alembic revision --autogenerate` on a fresh installation just to create the tables. The repository already contains the required migration.

---

## 11. Check the PostgreSQL Tables

Connect to the project database:

```bash
psql -h localhost -U postgres -d dataset_security
```

List the tables:

```sql
\dt
```

You should see tables including:

```text
datasets
dataset_versions
alembic_version
```

Check the `datasets` table:

```sql
\d datasets
```

Check the `dataset_versions` table:

```sql
\d dataset_versions
```

The `dataset_versions` table should contain fields such as:

```text
dataset_id
version
file_type
file_size
sha256
signature_algorithm
signature
public_key
provenance
status
storage_location
created_at
```

Exit PostgreSQL:

```sql
\q
```

---

## 12. Check Python Syntax

Before starting the server:

```bash
python -m py_compile \
app/schemas/dataset.py \
app/services/verification.py \
app/api/verification.py \
app/services/cryptography.py
```

If there is no output, the syntax check passed.

---

## 13. Start the FastAPI Backend

Make sure the virtual environment is active:

```bash
source .venv/bin/activate
```

Start FastAPI:

```bash
uvicorn app.main:app --reload
```

The server should start at:

```text
http://127.0.0.1:8000
```

Keep this terminal open.

---

## 14. Test the Backend

Open a second terminal.

Test the health endpoint:

```bash
curl http://127.0.0.1:8000/api/health
```

Open Swagger:

```text
http://localhost:8000/docs
```

Swagger provides the API interface for:

```text
POST /api/datasets/upload
```

and:

```text
GET /api/verification/{dataset_id}/{version}
```

---

## 15. Upload a Dataset

For example, use:

```text
dummy_dataset.csv
```

From the backend directory:

```bash
curl -X POST \
  "http://127.0.0.1:8000/api/datasets/upload" \
  -H "accept: application/json" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@dummy_dataset.csv" \
  -F "source=user_upload" \
  -F "description="
```

The response should contain information similar to:

```json
{
  "dataset_id": "DS-XXXXXXXXXXXX",
  "version": 1,
  "filename": "dummy_dataset.csv",
  "file_type": "csv",
  "file_size": 228,
  "sha256": "...",
  "status": "PROCESSED"
}
```

Copy the returned `dataset_id`.

---

## 16. Check ML-DSA Keys

The first signed upload creates the ML-DSA key pair.

Check:

```bash
ls -la keys/
```

Expected files:

```text
mldsa65_private.key
mldsa65_public.key
```

Check permissions:

```bash
ls -l keys/
```

The private key should ideally have:

```text
-rw------- mldsa65_private.key
```

The public key should ideally have:

```text
-rw-r--r-- mldsa65_public.key
```

The private key must not be committed to Git.

For production, private key management should use a proper secrets manager/KMS/HSM rather than a local key file.

---

## 17. Verify the Dataset

Replace `DS-XXXXXXXXXXXX` with the actual dataset ID returned from the upload.

```bash
curl -X GET \
  "http://127.0.0.1:8000/api/verification/DS-XXXXXXXXXXXX/1" \
  -H "accept: application/json"
```

For a valid dataset, expected output:

```json
{
  "dataset_id": "DS-XXXXXXXXXXXX",
  "version": 1,
  "verification_status": "VERIFIED",
  "sha256_verified": true,
  "provenance_verified": true,
  "signature_verified": true,
  "signature_algorithm": "ML-DSA-65",
  "reason": "VERIFIED"
}
```

The verification performs:

```text
Stored file
    ↓
Calculate SHA-256
    ↓
Compare with stored SHA-256
    ↓
Check provenance SHA-256
    ↓
Check dataset ID/version
    ↓
Check signature algorithm
    ↓
Verify ML-DSA-65 signature
    ↓
VERIFIED / BLOCKED
```

---

## 18. Handoff Rule

The output of pre-training verification is the handoff point to the AI-agent portion of the project.

If:

```text
verification_status = VERIFIED
```

then:

```text
Allow agent workflow to proceed
```

If:

```text
verification_status = BLOCKED
```

then:

```text
Do NOT allow the dataset to proceed to training/agent workflow.
```

The verification layer is therefore an independent gate before the AI-agent workflow.

---

## 19. Test Dataset Tampering

Find the uploaded file:

```bash
find storage -type f
```

Append test data to the stored file:

```bash
echo "TAMPERED_DATA" >> <PATH_TO_UPLOADED_FILE>
```

Run verification again:

```bash
curl -X GET \
  "http://127.0.0.1:8000/api/verification/DS-XXXXXXXXXXXX/1" \
  -H "accept: application/json"
```

Expected result:

```json
{
  "verification_status": "BLOCKED",
  "sha256_verified": false,
  "provenance_verified": false,
  "signature_verified": false,
  "reason": "SHA-256 hash mismatch"
}
```

This demonstrates that modification of the stored dataset is detected by the integrity check.

Restore the original dataset after the test.

---

## 20. Check Database Records

Connect:

```bash
psql -h localhost -U postgres -d dataset_security
```

Check datasets:

```sql
SELECT dataset_id, filename, created_at
FROM datasets;
```

Check dataset versions:

```sql
SELECT
    version,
    file_type,
    file_size,
    sha256,
    signature_algorithm,
    status
FROM dataset_versions;
```

The signature algorithm should be:

```text
ML-DSA-65
```

Inspect provenance:

```sql
SELECT
    dataset_id,
    version,
    provenance
FROM dataset_versions;
```

Exit:

```sql
\q
```

---

## 21. Stop the Backend

In the terminal running Uvicorn:

```text
Ctrl + C
```

---

## 22. Restart the Backend

Go to the backend directory:

```bash
cd dataset-security-gateway/backend
```

Activate the virtual environment:

```bash
source .venv/bin/activate
```

Start the server:

```bash
uvicorn app.main:app --reload
```

---

# Complete Fresh Linux Installation

The following is the complete command sequence in compact form.

## System setup

```bash
sudo apt update

sudo apt install -y \
    git \
    curl \
    build-essential \
    cmake \
    pkg-config \
    python3 \
    python3-pip \
    python3-venv \
    postgresql \
    postgresql-contrib
```

## PostgreSQL

```bash
sudo systemctl enable postgresql
sudo systemctl start postgresql

pg_isready

sudo -u postgres psql
```

Inside PostgreSQL:

```sql
ALTER USER postgres WITH PASSWORD 'postgres';
CREATE DATABASE dataset_security;
\q
```

## Clone and enter project

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>

cd dataset-security-gateway/backend
```

## Python environment

```bash
python3 -m venv .venv

source .venv/bin/activate

python -m pip install --upgrade pip
```

## Install packages

```bash
pip install -r requirements.txt

pip install liboqs-python
```

## Verify liboqs / ML-DSA

```bash
python -c "import oqs; print('liboqs imported successfully')"

python -c "import oqs; print('ML-DSA-65' in oqs.get_enabled_sig_mechanisms())"

python -c "import oqs; print(oqs.get_enabled_sig_mechanisms())"
```

Expected ML-DSA-65 result:

```text
True
```

## Create environment file

```bash
nano .env
```

Use:

```env
ENVIRONMENT=development

DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/dataset_security

OBJECT_STORAGE_ENDPOINT=http://localhost:9000
OBJECT_STORAGE_BUCKET=datasets
OBJECT_STORAGE_REGION=ap-south-1

CORS_ORIGINS=http://localhost:3000
```

## Create database tables

```bash
alembic upgrade head

alembic current

alembic check
```

## Validate code

```bash
python -m py_compile \
app/schemas/dataset.py \
app/services/verification.py \
app/api/verification.py \
app/services/cryptography.py
```

## Start backend

```bash
uvicorn app.main:app --reload
```

Open:

```text
http://localhost:8000/docs
```

## Upload

```bash
curl -X POST \
  "http://127.0.0.1:8000/api/datasets/upload" \
  -H "accept: application/json" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@dummy_dataset.csv" \
  -F "source=user_upload" \
  -F "description="
```

## Verify

```bash
curl -X GET \
  "http://127.0.0.1:8000/api/verification/<DATASET_ID>/1" \
  -H "accept: application/json"
```

Expected valid state:

```text
SHA-256 verification       ✓
Provenance verification    ✓
Dataset identity/version   ✓
ML-DSA-65 verification     ✓
Digital signature          ✓

             ↓

        VERIFIED

             ↓

      HANDOFF TO AGENTS
```

Expected tampered state:

```text
Dataset modified
       ↓
SHA-256 mismatch
       ↓
BLOCKED
       ↓
Do not proceed to training
```

---

# Troubleshooting

## PostgreSQL is not running

```bash
sudo systemctl start postgresql
```

Then:

```bash
pg_isready
```

## Check PostgreSQL status

```bash
sudo systemctl status postgresql
```

## Database does not exist

```bash
sudo -u postgres psql
```

Then:

```sql
CREATE DATABASE dataset_security;
\q
```

## Python virtual environment is not active

```bash
source .venv/bin/activate
```

Check:

```bash
which python
```

## ML-DSA-65 returns False

Check liboqs:

```bash
python -c "import oqs; print(oqs.get_enabled_sig_mechanisms())"
```

If `ML-DSA-65` is missing, reinstall:

```bash
pip uninstall liboqs-python -y
pip install liboqs-python
```

Then check again:

```bash
python -c "import oqs; print('ML-DSA-65' in oqs.get_enabled_sig_mechanisms())"
```

## Alembic cannot connect to PostgreSQL

Check:

```bash
pg_isready
```

Check the `.env`:

```bash
cat .env
```

Verify that:

```text
DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/dataset_security
```

matches the PostgreSQL credentials.

## Port 8000 is already in use

Find the process:

```bash
sudo lsof -i :8000
```

Then stop the process if required, or use another port:

```bash
uvicorn app.main:app --reload --port 8001
```

Swagger will then be:

```text
http://localhost:8001/docs
```

---

# Backend Completion Checklist

Before handing this portion to the teammate, verify:

```text
[ ] PostgreSQL installed and running
[ ] dataset_security database created
[ ] Alembic migration applied
[ ] datasets table created
[ ] dataset_versions table created
[ ] Python virtual environment created
[ ] requirements.txt installed
[ ] liboqs-python installed
[ ] ML-DSA-65 available
[ ] .env configured
[ ] FastAPI starts successfully
[ ] Swagger opens
[ ] Dataset upload works
[ ] SHA-256 is generated
[ ] Dataset ID/version is stored
[ ] ML-DSA-65 signature is generated
[ ] Provenance is stored
[ ] Verification returns VERIFIED
[ ] Tampering returns BLOCKED
[ ] Original dataset restored
[ ] ML-DSA private key is excluded from Git
[ ] Handoff condition is VERIFIED
```

## Final Handoff Point

Your implementation ends at:

```text
USER
  ↓
Next.js UI
  ↓
FastAPI Upload API
  ↓
Pydantic
  ↓
Dataset Processing
  ↓
Dataset Identity & Versioning
  ↓
Cryptographic Provenance
  ↓
PostgreSQL
  ↓
PRE-TRAINING VERIFICATION
  ↓
VERIFIED / BLOCKED
```

When the result is:

```text
VERIFIED
```

the dataset can be passed to the teammate's AI-agent workflow.

When the result is:

```text
BLOCKED
```

the dataset must not proceed.

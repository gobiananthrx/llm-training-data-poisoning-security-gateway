# Post-Quantum Provenance Attestation and Multi-Agent Adversarial Threat Intelligence Architecture for Risk-Adaptive Governance and Controlled Authorization of Enterprise LLM Training Datasets

An enterprise security gateway that guarantees cryptographic integrity, detects adversarial data poisoning, enforces risk-adaptive governance via Open Policy Agent (OPA), and strictly controls authorization of LLM training datasets prior to fine-tuning or pre-training pipelines.

---

## 1. System Overview & Architecture

Modern Large Language Models (LLMs) are highly susceptible to data poisoning attacks—including backdoor insertion, instruction manipulation, and semantic contradictions—that can compromise downstream models. 

This gateway establishes an immutable security barrier with two operational boundaries:
1. **Data Collection Gateway (`/data-collection`)**: Normalizes incoming raw datasets, computes chunked SHA-256 digests, binds technical provenance metadata, and signs the attestation using **NIST-standardized Post-Quantum ML-DSA-65** digital signatures.
2. **Pre-Training Threat Intelligence & Access Gate (`/`)**: Executes an 8-step cryptographic verification gate, orchestrates four parallel threat intelligence agents via LangGraph, correlates evidence across agents, calculates a deterministic risk score, evaluates compliance policies in OPA, supports inline Human-in-the-Loop (HITL) remediation with automated Version $N+1$ re-signing, and renders the cryptographic Training Access Gate.

```text
                               ┌──────────────────────────────────────────────┐
                               │       Client Upload (CSV, JSON, TXT, XLSX)   │
                               └──────────────────────┬───────────────────────┘
                                                      │
                                                      ▼
                                   ┌──────────────────────────────────────┐
                                   │     Data Collection Gateway          │
                                   │  - Location-Preserving Parsing       │
                                   │  - Canonical Provenance Binding      │
                                   │  - SHA-256 & ML-DSA-65 Signing       │
                                   └──────────────────┬───────────────────┘
                                                      │
                                                      ▼
                                   ┌──────────────────────────────────────┐
                                   │   Pre-Training Verification Gate     │
                                   │  - 8-Step Cryptographic Validation   │
                                   │  - Anti-Tamper & Signature Checks    │
                                   └──────────────────┬───────────────────┘
                                                      │
                                         [Passed Cryptographic Gate]
                                                      │
                                                      ▼
                       ┌──────────────────────────────────────────────────────────────┐
                       │           LangGraph Multi-Agent Orchestration Bus            │
                       └───────────┬──────────────┬─────────────┬──────────────┬──────┘
                                   │              │             │              │
                                   ▼              ▼             ▼              ▼
                              ┌─────────┐   ┌──────────┐  ┌───────────┐  ┌───────────┐
                              │Semantic │   │Behavioral│  │Inconsist. │  │Presidio   │
                              │Agent    │   │Agent     │  │Agent      │  │PII Agent  │
                              └────┬────┘   └─────┬────┘  └─────┬─────┘  └─────┬─────┘
                                   │              │             │              │ (Score = 0)
                                   └──────────────┼─────────────┴──────────────┘
                                                  │
                                                  ▼
                                   ┌──────────────────────────────────────┐
                                   │       Evidence Correlator            │
                                   │ - Multi-Agent Consensus ("N Flagged")│
                                   │ - Threat Severity Escalation         │
                                   └──────────────────┬───────────────────┘
                                                      │
                                                      ▼
                                   ┌──────────────────────────────────────┐
                                   │   Deterministic Risk Engine (0-100)  │
                                   │  - Excludes PII from Risk Score      │
                                   │  - Factor & Confidence Weighting     │
                                   └──────────────────┬───────────────────┘
                                                      │
                                                      ▼
                                   ┌──────────────────────────────────────┐
                                   │   Open Policy Agent (OPA) Evaluation │
                                   │  - Rego v1 Rules:                    │
                                   │    APPROVE / QUARANTINE / REJECT     │
                                   └──────────────────┬───────────────────┘
                                                      │
                                     ┌────────────────┴────────────────┐
                                     │                                 │
                            [QUARANTINE / REJECT]                  [APPROVE]
                                     │                                 │
                                     ▼                                 ▼
                         ┌───────────────────────┐         ┌─────────────────────────┐
                         │ Human-in-the-Loop     │         │  Training Access Gate   │
                         │ (HITL) Remediation    │         │  - Export Authorization │
                         │ - Cell Edit / Row Drop│         │  - Signed Proof Bundle  │
                         │ - Auto Version N+1    │         │  - Safe for Model Train │
                         │ - Re-sign & Re-verify │         └─────────────────────────┘
                         └───────────────────────┘
```

---

## 2. Key Components & Features

### Post-Quantum Provenance Attestation (ML-DSA-65)
- Implements NIST FIPS 204 **ML-DSA-65** (Dilithium3) signatures via `liboqs`.
- RFC 8785 deterministic JSON canonicalization ensures byte-level consistency across architectures.
- Dual SHA-256 file and provenance record digest tracking prevents both payload and metadata tampering.

### Location-Preserving Dataset Normalization
- Custom parsers for **CSV, JSON (arrays, objects, JSONL), TXT, and XLSX**.
- Preserves exact coordinates (`row`, `column`, `field`, `start_char`, `end_char`, `line_number`) for cell-level highlighting and targeted inline remediation.

### Multi-Agent Threat Intelligence
1. **Semantic Agent**: Detects jailbreak triggers, instruction overrides, covert payload execution, and adversarial poisoned prompts.
2. **Behavioral Agent**: Identifies unauthorized roleplay escapes, simulated compliance vulnerabilities, and harmful output elicitation patterns.
3. **Inconsistency Agent**: Employs n-gram candidate pair generation and semantic reasoning to detect factual contradictions and cross-record poisoning.
4. **PII Detection Agent**: Uses **Microsoft Presidio Analyzer** completely offline (via `en_core_web_sm`) to flag Person Names, Email Addresses, and Phone Numbers. **By strict design specification, PII findings contribute 0 to the dataset risk score.**

### LiteLLM Gateway
- Primary provider: **Gemini 2.5 Flash** with structured Pydantic schema generation.
- Automatic resilient fallback: **Groq** (`llama-3.3-70b-versatile`) on rate limits, quota exhaustion, or upstream errors.
- Built-in heuristic offline fallbacks ensure 100% test and execution reliability when API keys are not supplied.

### Deterministic Risk Engine & OPA Governance
- Risk Score is calculated deterministically on a scale of $0$ to $100$ using weighted severities, agent confidences, and multi-agent correlation multipliers.
- **Open Policy Agent (OPA)** evaluates Rego v1 policies hosted on port `8181`:
  - `APPROVE`: Cryptographic verification passed, risk score $\le 25$, zero critical findings, zero unreviewed high-risk items.
  - `QUARANTINE`: Cryptographically verified, but risk score $> 25$ and $\le 65$, or requires human inspection.
  - `REJECT`: Cryptographic verification failed, tampered file, or risk score $> 65$.

### Human-In-The-Loop (HITL) Remediation
- Reviewers can view pinpointed findings, modify poisoned cells, or delete poisoned rows directly in the interactive UI.
- Applying changes automatically writes a sanitized dataset file, increments to **Version $N+1$**, recalculates SHA-256, generates a new ML-DSA-65 signature, and automatically triggers the verification and analysis pipeline.

### Minimal Light-Theme Frontend & Training Access Gate
- Ultra-minimal enterprise light theme. No logos, no branding, clean typography.
- Real-time step completion indicators with green checkmarks (`✓`) streamed via WebSockets.
- Colored highlights in the dataset viewer:
  - 🔴 **Red**: Semantic Prompt Injection
  - 🟠 **Orange**: Behavioral Bypass
  - 🟡 **Yellow**: Inconsistency & Contradictions
  - 🔵 **Blue**: PII Entity
- Interactive finding drawer and inline cell editing modal.
- Authoritative **Training Access Gate** displaying cryptographic fingerprint and authorized training export status.

---

## 3. Quickstart Guide

### Prerequisites
- **Linux** (Ubuntu 22.04+, Debian 12+, Arch Linux, or CachyOS)
- **Python 3.12+**
- **Node.js 18+** & `npm`
- **Docker** & **Docker Compose**
- `liboqs` C library installed (`/usr/local/lib/liboqs.so` or `/usr/lib/liboqs.so`)

### Step 1: Start Infrastructure Services
Launch PostgreSQL, Redis, and Open Policy Agent (OPA):

```bash
docker compose up -d
```

Verify services are healthy:
```bash
docker compose ps
# OPA will be available at http://localhost:8181
# PostgreSQL at localhost:5432
# Redis at localhost:6379
```

### Step 2: Set Up & Run Backend
Navigate to `backend/`, activate the virtual environment, run database migrations, and start the server:

```bash
cd backend
source .venv/bin/activate
pip install -r requirements.txt

# Run Alembic migrations
alembic upgrade head

# Start FastAPI server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Step 3: Run Frontend
In a separate terminal, start the Next.js development server:

```bash
cd frontend
npm install
npm run dev
```

Open your browser at `http://localhost:3000`.

---

## 4. Operational Workflow & User Guide

### 1. Ingest & Sign Dataset (`/data-collection`)
1. Navigate to `http://localhost:3000/data-collection`.
2. Select a dataset file (`.csv`, `.json`, `.txt`, or `.xlsx`).
3. Click **Ingest & Sign Dataset**.
4. The system validates structure, computes chunked SHA-256, binds canonical provenance metadata, generates an **ML-DSA-65** signature, and registers Version 1 in PostgreSQL.

### 2. Verify & Analyze Dataset (`/`)
1. Navigate to `http://localhost:3000/`.
2. Select the registered dataset from the dropdown (or upload directly).
3. Click **Verify & Analyze Dataset**.
4. Watch real-time green checkmark steps (`✓`):
   - `✓ Dataset Ingestion & Schema Normalization`
   - `✓ Cryptographic Integrity & ML-DSA-65 Verification`
   - `✓ Multi-Agent Adversarial Threat Intelligence`
   - `✓ Evidence Correlation & Risk Engine Assessment`
   - `✓ Open Policy Agent (OPA) Governance Decision`
5. If clean, the **Training Access Gate** immediately issues the **Dataset Approved for Training** authorization badge with full cryptographic provenance.

### 3. Review & Remediate Poisoned Records
1. If flagged with `QUARANTINE` or `REJECT`, click on any highlighted cell or row (marked in red, orange, yellow, or blue).
2. The finding detail drawer explains the detection, agent confidence, and multi-agent consensus.
3. Click **Edit Cell** to sanitize poisoned content or **Remove Record** to drop the poisoned entry.
4. Click **Apply Changes & Generate Version N+1**.
5. The gateway automatically generates a new version, signs it with ML-DSA-65, and runs re-verification.

---

## 5. Test Datasets

Sample poisoned datasets with realistic adversarial scenarios are located in `test-data/`:
- `test-data/customer_support_training.csv` (100 records: prompt injection, system prompt leaks, override payloads).
- `test-data/enterprise_knowledge.json` (100 records: contradictory policies, synthetic names, emails, phone numbers).
- `test-data/employee_operations.xlsx` (100 records: behavioral bypasses, synthetic operational PII).

Refer to [test-data/README.md](file:///home/gobiananthrx/Projects/llm-training-data-poisoning-security-gateway/test-data/README.md) for full scenario descriptions.

---

## 6. Automated Testing

Run the comprehensive automated test suite (18 test cases covering cryptography, parsing, agents, risk, OPA, and lifecycle API):

```bash
cd backend
.venv/bin/pytest -v
```

Build the Next.js frontend to verify static typing and compilation:

```bash
cd frontend
npm run build
```

---

## 7. API Reference Summary

| Endpoint | Method | Description |
| :--- | :---: | :--- |
| `/api/datasets/upload` | `POST` | Ingests dataset, normalizes records, computes SHA-256, signs with ML-DSA-65 |
| `/api/datasets/` | `GET` | Lists all datasets with latest version, verification, and governance status |
| `/api/datasets/{dataset_id}` | `GET` | Fetches complete dataset details and version history |
| `/api/datasets/{dataset_id}/content` | `GET` | Returns location-preserved records with pagination |
| `/api/datasets/{dataset_id}/verify` | `POST` | Executes 8-step cryptographic & provenance verification gate |
| `/api/datasets/{dataset_id}/analyze` | `POST` | Executes LangGraph multi-agent analysis, correlation, and OPA |
| `/api/datasets/{dataset_id}/findings` | `GET` | Retrieves all agent and correlated threat findings |
| `/api/datasets/{dataset_id}/review` | `POST` | HITL remediation: approve, reject, edit cell, or remove record |
| `/api/datasets/{dataset_id}/authorization` | `GET` | Fetches Training Access Gate cryptographic authorization bundle |
| `/api/datasets/{dataset_id}/audit` | `GET` | Retrieves immutable audit event trail |
| `/api/ws/{dataset_id}` | `WS` | Real-time WebSocket connection for streaming pipeline step events |

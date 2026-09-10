# Project Implementation Plan: LLM Training Data Poisoning Security Gateway

This document describes the end-to-end architecture, implementation phases, technical requirements, and continuation guide for the **Post-Quantum Provenance Attestation and Multi-Agent Adversarial Threat Intelligence Architecture for Risk-Adaptive Governance and Controlled Authorization of Enterprise LLM Training Datasets**.

---

## 1. Project Overview

The objective of this gateway is to provide enterprise-grade cryptographic assurance and multi-agent threat intelligence over datasets intended for LLM fine-tuning and training.

### Core Processing Flow

```text
USER
  ↓
DATASET UPLOAD (/data-collection for raw dataset, / for pre-training gateway)
  ↓
DATASET PROCESSING (JSON, CSV, TXT, XLSX)
  ↓
DATASET ID + VERSION (e.g., DS-A91F82C31D22, Version 1)
  ↓
CANONICALIZATION (Deterministic serialization with sorted keys and stable separators)
  ↓
SHA-256 (Byte & canonical content digest)
  ↓
ML-DSA DIGITAL SIGNATURE (ML-DSA-65 post-quantum signing)
  ↓
PROVENANCE RECORD (Bound metadata: ID, version, file, size, timestamp, source, hash, alg)
  ↓
POSTGRESQL (Persistent storage of record & version)
  ↓
PRE-TRAINING CRYPTOGRAPHIC VERIFICATION
  ├─ Verify stored file exists
  ├─ Recalculate SHA-256 & match against stored & provenance
  ├─ Verify Dataset ID, Version, Algorithm
  └─ Verify ML-DSA-65 digital signature
       ↓
  If verified: PROCEED TO AGENTS
  If failed:   STATUS = BLOCKED (Pipeline terminates)
       ↓
LANGGRAPH AGENT ORCHESTRATION
  ├─ SEMANTIC AGENT (Prompt injection, malicious instructions, backdoor triggers)
  ├─ BEHAVIORAL AGENT (Policy bypass, unsafe model behavior, instruction manipulation)
  ├─ INCONSISTENCY AGENT (Contradictory information across records)
  └─ PII AGENT (Microsoft Presidio: Person names, emails, phone numbers)
       ↓
EVIDENCE CORRELATION (Multi-agent detection aggregation, location overlap, consensus)
  ↓
RISK-ADAPTIVE ENGINE (Deterministic 0-100 score & level, PII excluded from score)
  ↓
OPA POLICY ENGINE (Rego rules evaluated via local HTTP daemon)
  ↓
APPROVE / QUARANTINE / REJECT
  ↓
HUMAN-IN-THE-LOOP (Quarantine review, cell editing, row removal → Version 2 creation)
  ↓
TRAINING ACCESS GATE ("Dataset Approved for Training", authorization timestamp)
  ↓
AUDIT TRAIL (Immutable history of events)
```

---

## 2. Technical Stack

| Layer | Technology |
| :--- | :--- |
| **Frontend** | Next.js (App Router), React, TypeScript, Tailwind CSS, Minimal Light Theme |
| **Backend** | Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2 (asyncpg/psycopg), Alembic |
| **Data Processing** | Pandas, Polars, openpyxl, Python stdlib |
| **Cryptography** | SHA-256, ML-DSA-65 (liboqs / liboqs-python) |
| **Agent Orchestration** | LangGraph |
| **LLM Gateway** | LiteLLM |
| **Primary LLM** | Gemini 2.5 Flash |
| **Fallback LLM** | Groq (llama-3.3-70b-versatile) with automatic failover |
| **PII Detection** | Microsoft Presidio Analyzer (offline, independent of LLM) |
| **Policy Engine** | Open Policy Agent (OPA) with Rego policies |
| **Temporary State & Events** | Redis (ephemeral state & pub/sub) |
| **Permanent Storage** | PostgreSQL 16 |
| **Local File Storage** | Host filesystem (`storage/incoming/`, `keys/`) |
| **Docker Compose** | Services: `postgres`, `redis`, `opa` (host runs backend & frontend) |

---

## 3. Strict Boundary Rules

1. **No User Authentication**: No Keycloak, user login, roles, or team IDs. Provenance tracks technical dataset provenance.
2. **Supported Formats Only**: JSON, CSV, TXT, XLSX. No PDF, PyMuPDF, or Apache Tika.
3. **No Distributed Queues / Cloud**: No Kafka, NATS, Valkey, MinIO, or Kubernetes.
4. **Presidio for PII**: Strictly Presidio (no LLM dependency). PII does not increase the risk score; it is detected and displayed.
5. **No Model Training**: The gateway authorizes or quarantines datasets. Final stage displays "Dataset Approved for Training".

---

## 4. Implementation Phases

- **Phase 1**: Repository audit, architecture documentation, progress tracking.
- **Phase 2**: SQLAlchemy models expansion & Alembic migrations.
- **Phase 3**: Dataset normalization (location mapping) & versioning service.
- **Phase 4**: Deterministic canonicalization, SHA-256, ML-DSA-65 signing & verification.
- **Phase 5**: Redis integration & ephemeral pipeline state caching.
- **Phase 6**: LangGraph orchestrator state graph.
- **Phase 7**: Semantic Agent (heuristics + Gemini/Groq via LiteLLM).
- **Phase 8**: Behavioral Agent (heuristics + Gemini/Groq via LiteLLM).
- **Phase 9**: Inconsistency Agent (candidate pairs + Gemini/Groq via LiteLLM).
- **Phase 10**: Presidio PII Agent (Person, Email, Phone).
- **Phase 11**: LiteLLM Gateway with automated fallback and provider logging.
- **Phase 12**: Evidence Correlation Engine.
- **Phase 13**: Dedicated deterministic Risk Engine.
- **Phase 14**: OPA server integration and Rego policy definition.
- **Phase 15**: Human-in-the-loop review backend (Approve, Reject, Modify, Remove).
- **Phase 16**: Real-time WebSocket event streaming.
- **Phase 17**: Minimal light-theme frontend dashboard.
- **Phase 18**: Interactive dataset viewer with color-coded highlights.
- **Phase 19**: Detail drawer and multi-agent consensus view.
- **Phase 20**: Human review actions UI and Version 2 trigger.
- **Phase 21**: Training Access Gate screen.
- **Phase 22**: Audit trail viewer.
- **Phase 23**: Three synthetic enterprise test datasets (`/test-data/`).
- **Phase 24**: Automated unit, integration, and end-to-end tests.
- **Phase 25**: Docker Compose configuration (`postgres`, `redis`, `opa`).
- **Phase 26**: README.md and validation report.

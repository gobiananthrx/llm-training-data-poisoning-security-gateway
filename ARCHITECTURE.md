# Architecture Specification: LLM Training Data Poisoning Security Gateway

This document provides the formal architectural specification for the **Post-Quantum Provenance Attestation and Multi-Agent Adversarial Threat Intelligence Architecture for Risk-Adaptive Governance and Controlled Authorization of Enterprise LLM Training Datasets**.

---

## 1. System Topology

```text
┌────────────────────────────────────────────────────────────────────────┐
│                          NEXT.JS FRONTEND                              │
│  - Light Theme Only                                                   │
│  - Pages: / (Gateway & Verification), /data-collection (Ingestion)     │
│  - Real-time Green Tick Progress Steps                                 │
│  - Color-Coded Finding Highlighting (Semantic, Behavioral, Incons., PII)│
│  - Interactive Review Drawer & Training Access Gate                    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ HTTP / REST & WebSocket
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                          FASTAPI BACKEND                               │
│                                                                        │
│  ┌──────────────────────┐  ┌────────────────────────────────────────┐  │
│  │   DATASET PARSERS    │  │       CRYPTOGRAPHY SERVICE             │  │
│  │   CSV / JSON / TXT   │  │   - Deterministic Canonicalization     │  │
│  │   XLSX (openpyxl)    │  │   - SHA-256 Hashing                    │  │
│  │   Location Indexing  │  │   - ML-DSA-65 Digital Signatures       │  │
│  └──────────┬───────────┘  │   - Provenance Attestation Generation  │  │
│             │              │   - Pre-Training Cryptographic Gate    │  │
│             ▼              └───────────────────┬────────────────────┘  │
│  ┌─────────────────────────────────────────────▼────────────────────┐  │
│  │                   LANGGRAPH ORCHESTRATION                        │  │
│  │                                                                  │  │
│  │   ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌─────────┐ │  │
│  │   │   SEMANTIC   │ │  BEHAVIORAL  │ │INCONSISTENCY │ │   PII   │ │  │
│  │   │    AGENT     │ │    AGENT     │ │    AGENT     │ │  AGENT  │ │  │
│  │   └──────┬───────┘ └──────┬───────┘ └──────┬───────┘ └────┬────┘ │  │
│  │          └────────────────┼────────────────┘              │      │  │
│  │                           ▼                               ▼      │  │
│  │               ┌───────────────────────┐          ┌──────────────┐│  │
│  │               │    LiteLLM GATEWAY    │          │  PRESIDIO    ││  │
│  │               │ - Gemini 2.5 (Primary)│          │  ANALYZER    ││  │
│  │               │ - Groq (Fallback)     │          │  (Offline)   ││  │
│  │               └───────────────────────┘          └──────────────┘│  │
│  │                                                           │      │  │
│  │                           ▼                               ▼      │  │
│  │               ┌────────────────────────────────────────────────┐ │  │
│  │               │          EVIDENCE CORRELATION ENGINE           │ │  │
│  │               │  - Cross-agent record & span matching          │ │  │
│  │               │  - Consensus detection ("N Agents Flagged")    │ │  │
│  │               └───────────────────────┬────────────────────────┘ │  │
│  │                                       ▼                          │  │
│  │               ┌────────────────────────────────────────────────┐ │  │
│  │               │              RISK-ADAPTIVE ENGINE              │ │  │
│  │               │  - Deterministic 0-100 formula                 │ │  │
│  │               │  - Risk level grading (LOW..CRITICAL)          │ │  │
│  │               │  - PII excluded from score                     │ │  │
│  │               └───────────────────────┬────────────────────────┘ │  │
│  └───────────────────────────────────────┼──────────────────────────┘  │
│                                          │                             │
│                                          ▼                             │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                   OPA POLICY ENGINE CLIENT                       │  │
│  │   Evaluates Rego policies over verified data, findings, and risk │  │
│  │   Returns: APPROVE | QUARANTINE | REJECT                         │  │
│  └───────────────────────────────────────┬──────────────────────────┘  │
│                                          │                             │
│                                          ▼                             │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │               HUMAN-IN-THE-LOOP (HITL) REMEDIATION               │  │
│  │   - Quarantine dataset management                                │  │
│  │   - Cell modification & row removal                              │  │
│  │   - Creates Version 2 (Re-canonicalize -> Re-sign -> Re-verify)  │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└──────────────────┬───────────────────────┬─────────────────────┬───────┘
                   │                       │                     │
                   ▼                       ▼                     ▼
        ┌─────────────────────┐ ┌────────────────────┐ ┌────────────────┐
        │     POSTGRESQL      │ │       REDIS        │ │   LOCAL OPA    │
        │   Permanent State   │ │  Ephemeral State   │ │  Rego Policies │
        │  (Port 5432 Docker) │ │  (Port 6379 Docker)│ │  (Port 8181)   │
        └─────────────────────┘ └────────────────────┘ └────────────────┘
```

---

## 2. Cryptographic Security Model

### Post-Quantum Digital Signatures (ML-DSA-65)
The gateway employs ML-DSA (Module-Lattice Digital Signature Algorithm, NIST FIPS 204) at security category 3 (ML-DSA-65) via `liboqs`.
- **Purpose**: Authenticates technical dataset origin and establishes non-repudiable integrity binding between the raw dataset file and its metadata.
- **Key Pair**:
  - Private key: stored with strict `0600` permissions on the local filesystem (`keys/mldsa65_private.key`). Excluded from Git.
  - Public key: stored in base64 string format alongside dataset records in PostgreSQL (`dataset_versions.public_key`).

### Provenance Schema Binding
The signed payload contains:
```json
{
  "dataset_id": "DS-A91F82C31D22",
  "version": 1,
  "filename": "customer_support_training.csv",
  "file_type": "csv",
  "file_size": 18450,
  "timestamp": "2026-09-10T13:30:00Z",
  "source": "user_upload",
  "sha256": "3b4fbbfd92ae56dfcacb65da3d0382c9f273dc323010787005147d0802cfb940",
  "signature_algorithm": "ML-DSA-65"
}
```
Tampering with any property or modifying a single byte of the stored file causes verification failure and halts pipeline handoff.

---

## 3. Threat Intelligence Agents

| Agent | Detection Scope | Engine | Fallback / Model |
| :--- | :--- | :--- | :--- |
| **Semantic Agent** | Prompt injection, instruction override, system prompt extraction, backdoor triggers | Heuristics + LiteLLM | Gemini 2.5 Flash → Groq (Llama 3.3 70B) |
| **Behavioral Agent** | Policy bypass, unsafe model execution, unauthorized privilege escalation instruction | Heuristics + LiteLLM | Gemini 2.5 Flash → Groq (Llama 3.3 70B) |
| **Inconsistency Agent** | Semantic contradictions and factual inconsistencies across dataset entries | Candidate pairs + LiteLLM | Gemini 2.5 Flash → Groq (Llama 3.3 70B) |
| **PII Agent** | Personally Identifiable Information (Person names, Email addresses, Phone numbers) | Microsoft Presidio | Offline Spacy NLP (Zero LLM dependency) |

### PII Agent Isolation
The PII Agent provides visibility without artificially elevating the poisoning risk score. Findings are returned with location spans for reviewer inspection in the HITL interface.

---

## 4. Policy Engine (OPA)

Decisions are computed using Open Policy Agent (OPA) with declarative Rego rules:
```rego
package dataset_policy

default decision = "REJECT"

# 1. Unverified datasets are immediately rejected
decision = "REJECT" if {
    not input.cryptographic_verified
}

# 2. Critical risk datasets are quarantined or rejected
decision = "QUARANTINE" if {
    input.cryptographic_verified
    input.risk_score >= 50
}

# 3. High severity findings require quarantine for human review
decision = "QUARANTINE" if {
    input.cryptographic_verified
    input.high_severity_findings > 0
}

# 4. Clean datasets with low risk are approved
decision = "APPROVE" if {
    input.cryptographic_verified
    input.risk_score < 50
    input.high_severity_findings == 0
}
```

---

## 5. Dataset Lifecycle & Versioning State Machine

```text
[ UPLOADED ]
     │
     ▼
[ CANONICALIZED & SIGNED ]
     │
     ▼
[ VERIFYING ] ──► (Hash mismatch or signature invalid) ──► [ BLOCKED ]
     │
     ▼ (Valid)
[ ANALYZING ] (Semantic, Behavioral, Inconsistency, PII)
     │
     ▼
[ CORRELATING & ASSESSING RISK ]
     │
     ▼
[ EVALUATING POLICY ]
     ├─ APPROVE ────► [ TRAINING_AUTHORIZED ]
     ├─ REJECT ─────► [ REJECTED ]
     └─ QUARANTINE ─► [ QUARANTINED ]
                           │
                           ▼
                    [ HUMAN REVIEW ]
                    ├─ Approve as-is ──► [ TRAINING_AUTHORIZED ]
                    ├─ Reject ─────────► [ REJECTED ]
                    └─ Modify / Remove Record
                           │
                           ▼
                    [ CREATE VERSION 2 ]
                    (Re-canonicalize -> Re-hash -> Re-sign -> Re-verify -> Re-analyze)
```

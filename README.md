# Dataset Security Gateway

First implementation milestone for the planned enterprise pre-training dataset security architecture.

## Current milestone

- Next.js UI
- FastAPI upload API
- Pydantic validation
- CSV / JSON / TXT / XLSX processing
- Dataset ID + version
- SHA-256 fingerprinting
- Configuration-based frontend/backend URLs
- PostgreSQL and S3-compatible object-storage architecture
- Docker development infrastructure

## Cloud-ready design decisions

The application is **not designed around localhost as an architectural dependency**.

- Frontend API URL is configured with `NEXT_PUBLIC_API_BASE_URL`.
- Backend CORS origins are environment-configured.
- Object storage is abstracted so local MinIO can be replaced by AWS S3 or another S3-compatible service.
- PostgreSQL is intended to become a managed PostgreSQL service in deployment.
- Secrets/configuration are environment-driven and should use a cloud secrets manager in deployment.
- The API container is stateless; persistent dataset files must not depend on the application container filesystem.
- Dataset storage and cryptographic keys will be separated from the application container in later milestones.

## Important security note

The current product plan intentionally has no login/authentication system. That matches the current planned flow. Therefore, this milestone should be deployed behind an access-controlled environment or API gateway until authentication/rate limiting are implemented.

## Next milestones

1. SQLAlchemy + Alembic persistence
2. S3/MinIO object-storage adapter
3. ML-DSA signing and verification
4. Canonical provenance manifest
5. Pre-training verification endpoint
6. LangGraph security agents
7. LiteLLM model gateway
8. Redis job state
9. Evidence correlation
10. Risk engine
11. OPA policy enforcement
12. Quarantine and human review
13. Training access gate
14. Audit trail

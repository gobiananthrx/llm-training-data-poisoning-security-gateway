import io
from pathlib import Path
import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


@pytest.mark.asyncio
async def test_full_dataset_lifecycle():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # 1. Health check
        resp = await ac.get("/api/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

        # 2. Upload dataset (/api/datasets/upload)
        csv_content = b"prompt,response\nWhat is your refund policy?,We offer 30 day refunds.\nHow to cancel?,Click cancel under settings."
        files = {"file": ("test_upload.csv", io.BytesIO(csv_content), "text/csv")}
        data = {"source": "unit_test_suite", "description": "Automated pipeline lifecycle test"}

        upload_resp = await ac.post("/api/datasets/upload", files=files, data=data)
        assert upload_resp.status_code == 201
        upload_data = upload_resp.json()
        dataset_id = upload_data["dataset_id"]
        version = upload_data["version"]
        assert dataset_id.startswith("DS-")
        assert version == 1
        assert upload_data["signature_algorithm"] == "ML-DSA-65"
        assert upload_data["signature"] is not None

        # 3. Pre-training cryptographic verification (/api/datasets/{id}/versions/{v}/verify)
        verify_resp = await ac.post(f"/api/datasets/{dataset_id}/versions/{version}/verify")
        assert verify_resp.status_code == 200
        verify_data = verify_resp.json()
        assert verify_data["verification_status"] == "VERIFIED"
        assert verify_data["sha256_verified"] is True
        assert verify_data["signature_verified"] is True

        # 4. Trigger LangGraph analysis (/api/datasets/{id}/versions/{v}/analyze)
        analyze_resp = await ac.post(f"/api/datasets/{dataset_id}/versions/{version}/analyze")
        assert analyze_resp.status_code == 200
        analyze_data = analyze_resp.json()
        assert "risk_score" in analyze_data
        assert "decision" in analyze_data

        # 5. Fetch content for HITL viewer (/api/datasets/{id}/versions/{v}/content)
        content_resp = await ac.get(f"/api/datasets/{dataset_id}/versions/{version}/content")
        assert content_resp.status_code == 200
        content_data = content_resp.json()
        assert content_data["record_count"] == 2
        assert len(content_data["records"]) == 2

        # 6. Human Review: Modify content and create Version 2
        review_payload = {
            "action": "MODIFY",
            "notes": "Reviewed and updated by auditor",
            "modified_records": [{"record_id": "0", "data": {"response": "Cleaned response."}}],
            "removed_record_ids": [],
        }
        review_resp = await ac.post(f"/api/datasets/{dataset_id}/versions/{version}/review", json=review_payload)
        assert review_resp.status_code == 200
        review_data = review_resp.json()
        assert review_data["status"] == "VERSION_CREATED_AND_ANALYZED"
        assert review_data["new_version"] == 2

        # 7. Check Training Authorization for Version 2
        auth_resp = await ac.get(f"/api/datasets/{dataset_id}/versions/2/authorization")
        assert auth_resp.status_code == 200
        auth_data = auth_resp.json()
        assert auth_data["dataset_id"] == dataset_id
        assert auth_data["version"] == 2
        assert auth_data["training_authorized"] is True
        assert auth_data["status"] == "APPROVED"

        # 8. Check Audit Trail
        audit_resp = await ac.get(f"/api/datasets/{dataset_id}/versions/2/audit")
        assert audit_resp.status_code == 200
        audit_events = audit_resp.json()
        assert len(audit_events) >= 3
        event_types = [e["event_type"] for e in audit_events]
        assert "dataset_ingested" in event_types
        assert "new_version_created" in event_types


@pytest.mark.asyncio
async def test_customer_support_poisoned_dataset():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        test_file = Path(__file__).resolve().parent.parent.parent / "test-data" / "customer_support_training.csv"
        assert test_file.exists(), f"Missing test file: {test_file}"
        
        with open(test_file, "rb") as f:
            file_bytes = f.read()
            
        files = {"file": ("customer_support_training.csv", io.BytesIO(file_bytes), "text/csv")}
        data = {"source": "adversarial_benchmark", "description": "Poisoned customer support test"}
        
        # Ingest and ML-DSA-65 Sign
        upload_resp = await ac.post("/api/datasets/upload", files=files, data=data)
        assert upload_resp.status_code == 201
        upload_data = upload_resp.json()
        dataset_id = upload_data["dataset_id"]
        version = upload_data["version"]
        
        # Verify Pre-Training Integrity
        verify_resp = await ac.post(f"/api/datasets/{dataset_id}/versions/{version}/verify")
        assert verify_resp.status_code == 200
        assert verify_resp.json()["verification_status"] == "VERIFIED"
        
        # Run Multi-Agent Threat Intelligence Analysis
        analyze_resp = await ac.post(f"/api/datasets/{dataset_id}/versions/{version}/analyze")
        assert analyze_resp.status_code == 200
        analyze_data = analyze_resp.json()
        
        # Expect threats detected and quarantined or rejected by OPA policy
        assert analyze_data["findings_count"] > 0
        assert analyze_data["risk_score"] > 0
        assert analyze_data["decision"] in ["QUARANTINE", "REJECT"]
        
        # Get Findings
        findings_resp = await ac.get(f"/api/datasets/{dataset_id}/versions/{version}/findings")
        assert findings_resp.status_code == 200
        findings_data = findings_resp.json()
        assert len(findings_data["findings"]) > 0
        agents_found = {f["agent_name"] for f in findings_data["findings"]}
        assert "semantic" in agents_found or "behavioral" in agents_found


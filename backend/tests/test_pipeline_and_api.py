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


@pytest.mark.asyncio
async def test_quick_test_high_risk_csv():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        test_file = Path(__file__).resolve().parent.parent.parent / "test-data" / "quick_test_high_risk.csv"
        assert test_file.exists(), f"Missing test file: {test_file}"

        with open(test_file, "rb") as f:
            file_bytes = f.read()

        files = {"file": ("quick_test_high_risk.csv", io.BytesIO(file_bytes), "text/csv")}
        data = {"source": "test_suite", "description": "Quick 5 record high risk test"}

        upload_resp = await ac.post("/api/datasets/upload", files=files, data=data)
        assert upload_resp.status_code == 201
        upload_data = upload_resp.json()
        dataset_id = upload_data["dataset_id"]
        version = upload_data["version"]

        # Run Analysis
        analyze_resp = await ac.post(f"/api/datasets/{dataset_id}/versions/{version}/analyze")
        assert analyze_resp.status_code == 200
        analyze_data = analyze_resp.json()

        # Should be REJECT due to high risk score >= 65
        assert analyze_data["decision"] == "REJECT"
        assert analyze_data["risk_score"] >= 65

        # Verify findings categories: 2 PII, 1 semantic, 2 behavioral, 1 inconsistency
        findings_resp = await ac.get(f"/api/datasets/{dataset_id}/versions/{version}/findings")
        assert findings_resp.status_code == 200
        findings = findings_resp.json()["findings"]
        agents = [f["agent"] for f in findings]
        assert "pii" in agents
        assert "semantic" in agents
        assert "behavioral" in agents
        assert "inconsistency" in agents


@pytest.mark.asyncio
async def test_quick_test_quarantine_txt_and_remediation():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        test_file = Path(__file__).resolve().parent.parent.parent / "test-data" / "quick_test_quarantine.txt"
        assert test_file.exists(), f"Missing test file: {test_file}"

        with open(test_file, "rb") as f:
            file_bytes = f.read()

        files = {"file": ("quick_test_quarantine.txt", io.BytesIO(file_bytes), "text/plain")}
        data = {"source": "test_suite", "description": "Quick 5 record quarantine test"}

        upload_resp = await ac.post("/api/datasets/upload", files=files, data=data)
        assert upload_resp.status_code == 201
        upload_data = upload_resp.json()
        dataset_id = upload_data["dataset_id"]
        version = upload_data["version"]

        # Run Analysis
        analyze_resp = await ac.post(f"/api/datasets/{dataset_id}/versions/{version}/analyze")
        assert analyze_resp.status_code == 200
        analyze_data = analyze_resp.json()

        # Moderate risk score (inconsistency + PII email with 0 score contribution) -> QUARANTINE
        assert analyze_data["decision"] == "QUARANTINE"

        # Now simulate HITL remediation: edit contradictory line (line 3 / record_id '3' which is line 4 in 0-indexed)
        # to match line 1, removing the contradiction
        review_payload = {
            "action": "MODIFY",
            "notes": "Fixed contradictory support hours to align with enterprise policy",
            "modified_records": [{
                "record_id": "4",
                "data": {"text": "Standard customer support hours are Monday through Friday from 9am to 5pm EST."}
            }],
            "removed_record_ids": [],
        }
        review_resp = await ac.post(f"/api/datasets/{dataset_id}/versions/{version}/review", json=review_payload)
        assert review_resp.status_code == 200
        review_data = review_resp.json()
        new_version = review_data["new_version"]
        assert new_version == 2

        # Check that new version is now clean from inconsistency and APPROVED for training
        auth_resp = await ac.get(f"/api/datasets/{dataset_id}/versions/{new_version}/authorization")
        assert auth_resp.status_code == 200
        auth_data = auth_resp.json()
        assert auth_data["opa_decision"] == "APPROVE"
        assert auth_data["status"] == "APPROVED"

        # Download dataset file test
        download_resp = await ac.get(f"/api/datasets/{dataset_id}/versions/{new_version}/download")
        assert download_resp.status_code == 200
        assert len(download_resp.content) > 0


@pytest.mark.asyncio
async def test_pipeline_upload_signature_matching():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # 1. Upload unregistered file via pipeline-upload -> expect BLOCKED
        unreg_file = {"file": ("unregistered_dataset_xyz.csv", io.BytesIO(b"a,b\n1,2\n3,4"), "text/csv")}
        pipe_resp = await ac.post("/api/datasets/pipeline-upload", files=unreg_file)
        assert pipe_resp.status_code == 200
        pipe_data = pipe_resp.json()
        assert pipe_data["status"] == "BLOCKED"
        assert pipe_data["decision"] == "REJECT"

        # 2. Ingest a dataset into data collection first
        csv_bytes = b"query,response\nHello,World\nSupport,Hours"
        reg_file = {"file": ("registered_dataset_abc.csv", io.BytesIO(csv_bytes), "text/csv")}
        ingest_resp = await ac.post("/api/datasets/upload", files=reg_file, data={"source": "data_collection"})
        assert ingest_resp.status_code == 201

        # 3. Now upload the same registered file into pipeline-upload -> expect signature matched & VERIFIED
        pipe_match = {"file": ("registered_dataset_abc.csv", io.BytesIO(csv_bytes), "text/csv")}
        match_resp = await ac.post("/api/datasets/pipeline-upload", files=pipe_match)
        assert match_resp.status_code == 200
        match_data = match_resp.json()
        assert match_data["status"] == "VERIFIED"
        assert match_data["blocked"] is False
        assert match_data["version"] == 1

        # 4. Upload file with same name but modified content/size -> expect version = current + 1 (version 2)
        mod_bytes = b"query,response\nHello,World\nSupport,Hours\nExtra,Row added for version 2"
        pipe_mod = {"file": ("registered_dataset_abc.csv", io.BytesIO(mod_bytes), "text/csv")}
        mod_resp = await ac.post("/api/datasets/pipeline-upload", files=pipe_mod)
        assert mod_resp.status_code == 200
        mod_data = mod_resp.json()
        assert mod_data["status"] == "VERIFIED"
        assert mod_data["version"] == 2



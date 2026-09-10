import pytest
from app.schemas.finding import (
    AgentFindingSchema,
    FindingRecommendation,
    FindingSeverity,
    FindingStatus,
)
from app.services.correlator import correlate_findings
from app.services.opa import evaluate_policy
from app.services.risk_engine import calculate_risk


def test_risk_engine_excludes_pii():
    # Only PII finding
    pii_finding = AgentFindingSchema(
        dataset_id="DS-TEST",
        version=1,
        agent="pii",
        status=FindingStatus.FLAGGED,
        record_id="1",
        field="email",
        location={"row": 1, "column": "email"},
        category="PII",
        severity=FindingSeverity.HIGH,
        confidence=0.99,
        evidence="jane@test.org",
        reason="email found",
        recommendation=FindingRecommendation.QUARANTINE,
    )

    correlated = correlate_findings("DS-TEST", 1, [pii_finding])
    risk = calculate_risk(total_records=10, raw_findings=[pii_finding], correlated_findings=correlated)

    # Risk must be 0 and LOW because PII does not contribute to risk score
    assert risk.risk_score == 0
    assert risk.risk_level == "LOW"


def test_risk_engine_with_poisoning():
    semantic_finding = AgentFindingSchema(
        dataset_id="DS-TEST",
        version=1,
        agent="semantic",
        status=FindingStatus.FLAGGED,
        record_id="1",
        field="text",
        location={"row": 1, "column": "text"},
        category="PROMPT_INJECTION",
        severity=FindingSeverity.HIGH,
        confidence=0.95,
        evidence="Ignore previous instructions",
        reason="Prompt injection",
        recommendation=FindingRecommendation.QUARANTINE,
    )
    behavioral_finding = AgentFindingSchema(
        dataset_id="DS-TEST",
        version=1,
        agent="behavioral",
        status=FindingStatus.FLAGGED,
        record_id="1",
        field="text",
        location={"row": 1, "column": "text"},
        category="UNSAFE_BEHAVIOR",
        severity=FindingSeverity.HIGH,
        confidence=0.90,
        evidence="Ignore previous instructions",
        reason="Unsafe override",
        recommendation=FindingRecommendation.QUARANTINE,
    )

    correlated = correlate_findings("DS-TEST", 1, [semantic_finding, behavioral_finding])
    risk = calculate_risk(total_records=20, raw_findings=[semantic_finding, behavioral_finding], correlated_findings=correlated)

    # Multi-agent corroboration on record 1 should trigger elevated risk
    assert risk.risk_score >= 50
    assert risk.risk_level in ["HIGH", "CRITICAL"]
    assert risk.metrics["multi_agent_findings"] >= 1


@pytest.mark.asyncio
async def test_opa_decisions():
    # 1. Unverified must REJECT
    res_unverified = await evaluate_policy(
        cryptographic_verified=False,
        risk_score=10,
        risk_level="LOW",
        high_severity_findings=0,
        pii_findings=0,
    )
    assert res_unverified.decision == "REJECT"

    # 2. High risk must QUARANTINE
    res_high_risk = await evaluate_policy(
        cryptographic_verified=True,
        risk_score=85,
        risk_level="CRITICAL",
        high_severity_findings=2,
        pii_findings=1,
    )
    assert res_high_risk.decision == "QUARANTINE"

    # 3. Clean verified dataset must APPROVE
    res_clean = await evaluate_policy(
        cryptographic_verified=True,
        risk_score=15,
        risk_level="LOW",
        high_severity_findings=0,
        pii_findings=0,
    )
    assert res_clean.decision == "APPROVE"

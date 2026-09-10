from dataclasses import dataclass
import math
from typing import Any
from app.schemas.finding import AgentFindingSchema, FindingSeverity
from app.services.correlator import CorrelatedFindingDTO


@dataclass
class RiskAssessmentResult:
    risk_score: int
    risk_level: str
    contributing_factors: list[str]
    explanation: str
    metrics: dict[str, Any]


def calculate_risk(
    total_records: int,
    raw_findings: list[AgentFindingSchema],
    correlated_findings: list[CorrelatedFindingDTO],
) -> RiskAssessmentResult:
    """
    Dedicated deterministic and reproducible Risk Engine.
    Excludes PII agent findings from risk score calculation as required.
    Considers severity, confidence, affected record ratio, and multi-agent consensus.
    """
    # 1. Filter out PII findings from risk calculations
    security_findings = [f for f in raw_findings if f.agent.lower() != "pii"]
    security_correlated = [
        cf for cf in correlated_findings
        if any(a.lower() != "pii" for a in cf.agents_involved)
    ]

    total_rec = max(total_records, 1)

    if not security_findings:
        return RiskAssessmentResult(
            risk_score=0,
            risk_level="LOW",
            contributing_factors=["No adversarial or policy threat findings detected."],
            explanation="The dataset content passed all semantic, behavioral, and consistency threat intelligence audits.",
            metrics={
                "total_records": total_rec,
                "security_findings_count": 0,
                "affected_records": 0,
                "affected_ratio_percent": 0.0,
                "multi_agent_findings": 0,
            },
        )

    affected_record_ids = {f.record_id for f in security_findings}
    affected_count = len(affected_record_ids)
    affected_ratio = (affected_count / total_rec) * 100.0

    # Base severity points
    score_acc = 0.0
    contributing_factors: list[str] = []

    high_sev_count = 0
    crit_sev_count = 0
    med_sev_count = 0

    for f in security_findings:
        weight = 0.0
        if f.severity == FindingSeverity.CRITICAL:
            weight = 35.0
            crit_sev_count += 1
        elif f.severity == FindingSeverity.HIGH:
            weight = 22.0
            high_sev_count += 1
        elif f.severity == FindingSeverity.MEDIUM:
            weight = 10.0
            med_sev_count += 1
        else:
            weight = 4.0

        # Scale by agent confidence
        score_acc += weight * f.confidence

    # Multi-agent consensus bonus (multiple agents detecting same content)
    multi_agent_count = 0
    for cf in security_correlated:
        non_pii_agents = [a for a in cf.agents_involved if a.lower() != "pii"]
        if len(non_pii_agents) >= 2:
            multi_agent_count += 1
            score_acc += 15.0  # High confidence penalty for multi-agent corroboration

    # Affected record ratio impact
    ratio_penalty = min(affected_ratio * 3.0, 30.0)
    total_raw_score = score_acc + ratio_penalty

    # Cap score at 100
    final_score = int(min(max(round(total_raw_score), 0), 100))

    # Determine risk level
    if final_score >= 75 or crit_sev_count > 0:
        risk_level = "CRITICAL"
    elif final_score >= 50 or high_sev_count >= 2:
        risk_level = "HIGH"
    elif final_score >= 25:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # Assemble contributing factors
    if crit_sev_count > 0:
        contributing_factors.append(f"{crit_sev_count} critical severity threat findings detected.")
    if high_sev_count > 0:
        contributing_factors.append(f"{high_sev_count} high severity threat findings (e.g. prompt injection, unsafe behavior).")
    if multi_agent_count > 0:
        contributing_factors.append(f"{multi_agent_count} records corroborated by multiple security agents simultaneously.")
    if med_sev_count > 0:
        contributing_factors.append(f"{med_sev_count} inconsistency or medium severity contradictions.")
    if affected_ratio > 2.0:
        contributing_factors.append(f"{affected_count} records ({affected_ratio:.1f}% of total) contaminated.")

    explanation = (
        f"Assigned {risk_level} risk score of {final_score}/100 based on {len(security_findings)} security findings "
        f"across {affected_count} records, with {multi_agent_count} multi-agent consensus flags."
    )

    return RiskAssessmentResult(
        risk_score=final_score,
        risk_level=risk_level,
        contributing_factors=contributing_factors,
        explanation=explanation,
        metrics={
            "total_records": total_rec,
            "security_findings_count": len(security_findings),
            "affected_records": affected_count,
            "affected_ratio_percent": round(affected_ratio, 2),
            "multi_agent_findings": multi_agent_count,
            "high_severity_count": high_sev_count,
            "critical_severity_count": crit_sev_count,
        },
    )

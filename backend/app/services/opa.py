from dataclasses import dataclass
import logging
import os
from typing import Any
import httpx

logger = logging.getLogger("gateway.opa")

OPA_URL = os.getenv("OPA_URL", "http://localhost:8181/v1/data/dataset_policy")


@dataclass
class OPADecisionResult:
    decision: str  # "APPROVE", "QUARANTINE", "REJECT"
    reasons: list[str]
    policy_input: dict[str, Any]
    policy_output: dict[str, Any]


async def evaluate_policy(
    cryptographic_verified: bool,
    risk_score: int,
    risk_level: str,
    high_severity_findings: int,
    pii_findings: int,
    human_review_required: bool = False,
) -> OPADecisionResult:
    """
    Evaluates dataset governance policy via Open Policy Agent (OPA).
    """
    policy_input = {
        "cryptographic_verified": cryptographic_verified,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "high_severity_findings": high_severity_findings,
        "pii_findings": pii_findings,
        "human_review_required": human_review_required,
    }

    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.post(OPA_URL, json={"input": policy_input})
            if resp.status_code == 200:
                body = resp.json()
                result = body.get("result", {})
                decision = result.get("decision", "QUARANTINE")
                reasons = result.get("reasons", ["Evaluated via OPA Rego policy."])
                return OPADecisionResult(
                    decision=decision,
                    reasons=reasons,
                    policy_input=policy_input,
                    policy_output=body,
                )
    except Exception as exc:
        logger.warning(f"OPA daemon connection issue ({exc}). Using local policy engine mirror.")

    # Local mirror of Rego rules if OPA server is temporarily unreachable
    if not cryptographic_verified:
        decision = "REJECT"
        reasons = ["Cryptographic integrity check failed. Signature or SHA-256 mismatch."]
    elif risk_score >= 65:
        decision = "REJECT"
        reasons = [f"High risk score ({risk_score}/100) exceeds safety threshold. Dataset rejected from model training."]
    elif risk_score >= 20 or human_review_required:
        decision = "QUARANTINE"
        reasons = [f"Moderate risk score ({risk_score}/100) requires isolation in quarantine for human remediation."]
    else:
        decision = "APPROVE"
        reasons = ["Dataset meets cryptographic and security policy criteria for model training."]

    return OPADecisionResult(
        decision=decision,
        reasons=reasons,
        policy_input=policy_input,
        policy_output={"local_mirror": True, "decision": decision, "reasons": reasons},
    )

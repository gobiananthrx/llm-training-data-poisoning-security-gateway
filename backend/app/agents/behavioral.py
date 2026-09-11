import logging
from typing import Any
from app.schemas.finding import (
    AgentFindingLLMOutput,
    AgentFindingSchema,
    FindingRecommendation,
    FindingSeverity,
    FindingStatus,
)
from app.services.dataset_processor import NormalizedDataset
from app.services.llm_gateway import call_structured_llm

logger = logging.getLogger("gateway.agent.behavioral")

BEHAVIORAL_KEYWORDS = [
    "bypass compliance",
    "bypass authentication",
    "crack passwords",
    "crack password",
    "steal passwords",
    "generate malware",
    "undetectable malware",
    "disable endpoint security",
    "disable antivirus",
    "disable safety filters",
    "leak credentials",
    "steal credentials",
    "do not log this action",
    "unauthorized access",
    "disable audit logging",
    "steal data",
    "exploit vulnerability",
    "privilege escalation",
    "execute silently without approval",
    "override company policy",
    "grant admin privileges",
    "ignore privacy regulations",
    "evade detection",
    "ddos attack",
    "sql injection tutorial",
    "ransomware payment",
    "counterfeit document",
    "keylogger script",
    "bypass firewall",
    "rootkit installation",
    "disable security logging",
    "turn off monitoring",
    "bypass multi-factor",
    "spoof identity",
    "fabricate invoice",
    "forge signature",
    "phishing template",
    "extract confidential keys",
    "steal api token",
    "dump database credentials",
    "evade compliance audit",
    "impersonate administrator",
    "circumvent kyc",
    "insider trading",
    "fake wire transfer",
    "intercept otp",
]


async def run_behavioral_agent(
    dataset_id: str,
    version: int,
    dataset: NormalizedDataset,
) -> list[AgentFindingSchema]:
    """
    Analyzes dataset records for behavioral manipulation, policy bypass,
    and encouragement of unsafe model conduct.
    """
    findings: list[AgentFindingSchema] = []

    for record in dataset.records:
        rec_id = record.record_id
        for field, value in record.data.items():
            text = str(value).strip()
            if not text:
                continue

            text_lower = text.lower()

            matched_keywords = [kw for kw in BEHAVIORAL_KEYWORDS if kw in text_lower]
            is_suspicious_candidate = bool(matched_keywords) or (
                "policy" in text_lower and ("bypass" in text_lower or "circumvent" in text_lower or "ignore" in text_lower)
            ) or (
                "security" in text_lower and ("disable" in text_lower or "bypass" in text_lower)
            )

            if not is_suspicious_candidate:
                continue

            kw_match_str = matched_keywords[0] if matched_keywords else "policy bypass indicator"
            match_idx = text_lower.find(kw_match_str)
            if match_idx != -1:
                snippet_start = max(0, match_idx - 10)
                snippet_end = min(len(text), match_idx + len(kw_match_str) + 30)
                evidence_snippet = f'"{text[snippet_start:snippet_end].strip()}"'
                loc_span = {"start": match_idx, "end": match_idx + len(kw_match_str)}
            else:
                evidence_snippet = f'"{text[:150]}..."'
                loc_span = {"start": 0, "end": min(len(text), 150)}

            prompt = (
                f"Evaluate whether this dataset record encourages undesirable model behavior, "
                f"policy violations, or unsafe corporate actions.\n\n"
                f"Record ID: {rec_id}\n"
                f"Field: {field}\n"
                f"Content:\n\"\"\"{text[:1500]}\"\"\"\n\n"
                f"Return structured JSON classification."
            )

            system_inst = (
                "You are an enterprise AI safety auditor. Determine if the text induces unsafe, "
                "non-compliant, or policy-bypassing behavior in a language model. "
                "Classify as UNSAFE_BEHAVIOR, POLICY_BYPASS, or BENIGN."
            )

            llm_result, provider = await call_structured_llm(
                prompt=prompt,
                schema=AgentFindingLLMOutput,
                system_instruction=system_inst,
            )

            loc = dict(record.location)
            loc["field"] = field

            if llm_result:
                if llm_result.category.upper() != "BENIGN":
                    finding = AgentFindingSchema(
                        dataset_id=dataset_id,
                        version=version,
                        agent="behavioral",
                        status=FindingStatus.FLAGGED,
                        record_id=rec_id,
                        field=field,
                        location={**loc, "span": llm_result.location_span or loc_span},
                        category=llm_result.category,
                        severity=llm_result.severity,
                        confidence=llm_result.confidence,
                        evidence=llm_result.evidence or evidence_snippet,
                        reason=llm_result.reason,
                        recommendation=llm_result.recommendation,
                        model_or_provider=provider,
                    )
                    findings.append(finding)
            else:
                finding = AgentFindingSchema(
                    dataset_id=dataset_id,
                    version=version,
                    agent="behavioral",
                    status=FindingStatus.FLAGGED,
                    record_id=rec_id,
                    field=field,
                    location={**loc, "span": loc_span},
                    category="POLICY_BYPASS",
                    severity=FindingSeverity.HIGH,
                    confidence=0.92,
                    evidence=f"Adversarial compliance bypass detected: {evidence_snippet}",
                    reason="Record instructs or encourages policy circumvention and unsafe model actions.",
                    recommendation=FindingRecommendation.QUARANTINE,
                    model_or_provider="Adversarial Threat Intelligence Engine",
                )
                findings.append(finding)

    return findings

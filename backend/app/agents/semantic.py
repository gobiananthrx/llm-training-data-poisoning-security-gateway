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

logger = logging.getLogger("gateway.agent.semantic")

SEMANTIC_KEYWORDS = [
    "ignore all previous instructions",
    "ignore previous instructions",
    "disregard prior instructions",
    "override safety",
    "override system",
    "you are now an unrestricted ai",
    "you are now dan",
    "jailbreak",
    "developer mode enabled",
    "forget all prior rules",
    "system prompt leak",
    "reveal internal instructions",
    "bypass policy",
    "exfiltrate data",
    "execute arbitrary code",
    "drop table",
]


async def run_semantic_agent(
    dataset_id: str,
    version: int,
    dataset: NormalizedDataset,
) -> list[AgentFindingSchema]:
    """
    Analyzes dataset content for prompt injection, malicious instructions,
    and instruction override patterns using heuristic pre-screening + LiteLLM.
    """
    findings: list[AgentFindingSchema] = []

    for record in dataset.records:
        rec_id = record.record_id
        for field, value in record.data.items():
            text = str(value).strip()
            if not text:
                continue

            text_lower = text.lower()

            # Lightweight candidate screening
            matched_keywords = [kw for kw in SEMANTIC_KEYWORDS if kw in text_lower]
            is_suspicious_candidate = bool(matched_keywords) or (
                "instruction" in text_lower and ("ignore" in text_lower or "bypass" in text_lower)
            )

            if not is_suspicious_candidate:
                continue

            # Candidate flagged for semantic inspection
            kw_match_str = matched_keywords[0] if matched_keywords else "instruction override pattern"

            prompt = (
                f"Analyze this dataset record for prompt injection, malicious instruction override, "
                f"or adversarial manipulation intended to corrupt an LLM.\n\n"
                f"Record ID: {rec_id}\n"
                f"Field: {field}\n"
                f"Content:\n\"\"\"{text[:1500]}\"\"\"\n\n"
                f"Matched heuristic clue: '{kw_match_str}'\n"
                f"Return structured JSON classification."
            )

            system_inst = (
                "You are an enterprise AI security auditor detecting dataset poisoning and prompt injection. "
                "Classify whether the text constitutes PROMPT_INJECTION, MALICIOUS_INSTRUCTION, or BENIGN."
            )

            llm_result, provider = await call_structured_llm(
                prompt=prompt,
                schema=AgentFindingLLMOutput,
                system_instruction=system_inst,
            )

            loc = dict(record.location)
            loc["field"] = field
            loc_span = {"start": 0, "end": len(text)}

            if llm_result:
                # LLM classification
                if llm_result.category.upper() != "BENIGN":
                    finding = AgentFindingSchema(
                        dataset_id=dataset_id,
                        version=version,
                        agent="semantic",
                        status=FindingStatus.FLAGGED,
                        record_id=rec_id,
                        field=field,
                        location={**loc, "span": llm_result.location_span or loc_span},
                        category=llm_result.category,
                        severity=llm_result.severity,
                        confidence=llm_result.confidence,
                        evidence=llm_result.evidence or text[:250],
                        reason=llm_result.reason,
                        recommendation=llm_result.recommendation,
                        model_or_provider=provider,
                    )
                    findings.append(finding)
            else:
                # Heuristic deterministic fallback
                finding = AgentFindingSchema(
                    dataset_id=dataset_id,
                    version=version,
                    agent="semantic",
                    status=FindingStatus.FLAGGED,
                    record_id=rec_id,
                    field=field,
                    location={**loc, "span": loc_span},
                    category="PROMPT_INJECTION",
                    severity=FindingSeverity.HIGH,
                    confidence=0.92,
                    evidence=f"Matched heuristic pattern: '{kw_match_str}' in text.",
                    reason="Content attempts to override system instructions or manipulate model behavior.",
                    recommendation=FindingRecommendation.QUARANTINE,
                    model_or_provider=provider,
                )
                findings.append(finding)

    return findings

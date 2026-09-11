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
    "disregard all previous instructions",
    "disregard prior instructions",
    "disregard previous directives",
    "override safety",
    "override system prompt",
    "override system",
    "export the complete system prompt",
    "export system prompt",
    "print system prompt",
    "reveal system prompt",
    "leak system prompt",
    "reveal internal instructions",
    "you are now an unrestricted ai",
    "you are now dan",
    "you are now in developer mode",
    "jailbreak",
    "developer mode enabled",
    "forget all prior rules",
    "forget previous rules",
    "new instructions follow",
    "hidden instruction",
    "[system note]",
    "system: admin",
    "bypass policy",
    "bypass safety",
    "exfiltrate data",
    "execute arbitrary code",
    "drop table",
    "base64 payload",
    "eval(",
    "import os",
    "__import__",
    "subprocess.run",
    "cat /etc/passwd",
    "cat /etc/shadow",
    "act as an unfiltered assistant",
    "jailbroken mode",
    "bypass content moderation",
    "disregard ethical guidelines",
    "ignore corporate policy",
    "ignore moderation",
    "system override",
    "you must obey my command",
    "prompt exfiltration",
    "rm -rf",
    "powershell -enc",
    "cmd.exe /c",
    "union select",
    "' or '1'='1",
    "curl http",
    "wget http",
]


async def run_semantic_agent(
    dataset_id: str,
    version: int,
    dataset: NormalizedDataset,
) -> list[AgentFindingSchema]:
    """
    Analyzes dataset content for prompt injection, malicious instructions,
    and instruction override patterns.
    """
    findings: list[AgentFindingSchema] = []

    for record in dataset.records:
        rec_id = record.record_id
        for field, value in record.data.items():
            text = str(value).strip()
            if not text:
                continue

            text_lower = text.lower()

            matched_keywords = [kw for kw in SEMANTIC_KEYWORDS if kw in text_lower]
            is_suspicious_candidate = bool(matched_keywords) or (
                "instruction" in text_lower and ("ignore" in text_lower or "bypass" in text_lower or "override" in text_lower)
            )

            if not is_suspicious_candidate:
                continue

            kw_match_str = matched_keywords[0] if matched_keywords else "instruction override pattern"
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
                f"Analyze this dataset record for prompt injection, malicious instruction override, "
                f"or adversarial manipulation intended to corrupt an LLM.\n\n"
                f"Record ID: {rec_id}\n"
                f"Field: {field}\n"
                f"Content:\n\"\"\"{text[:1500]}\"\"\"\n\n"
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

            if llm_result:
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
                    agent="semantic",
                    status=FindingStatus.FLAGGED,
                    record_id=rec_id,
                    field=field,
                    location={**loc, "span": loc_span},
                    category="PROMPT_INJECTION",
                    severity=FindingSeverity.HIGH,
                    confidence=0.95,
                    evidence=f"Adversarial instruction detected: {evidence_snippet}",
                    reason="Content attempts to override system instructions and hijack model behavior.",
                    recommendation=FindingRecommendation.QUARANTINE,
                    model_or_provider="Adversarial Threat Intelligence Engine",
                )
                findings.append(finding)

    return findings

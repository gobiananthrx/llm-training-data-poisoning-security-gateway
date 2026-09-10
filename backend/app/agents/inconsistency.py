from collections import defaultdict
import logging
import re
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

logger = logging.getLogger("gateway.agent.inconsistency")


def _clean_str(s: str) -> str:
    return re.sub(r"[^\w\s]", "", s.lower()).strip()


async def run_inconsistency_agent(
    dataset_id: str,
    version: int,
    dataset: NormalizedDataset,
) -> list[AgentFindingSchema]:
    """
    Identifies contradictions and conflicting facts across dataset records.
    Preprocesses pairs with high question/prompt similarity, then conducts
    semantic contradiction reasoning.
    """
    findings: list[AgentFindingSchema] = []

    # 1. Identify query/prompt fields and response/answer fields
    query_fields = [col for col in dataset.columns if any(k in col.lower() for k in ["question", "prompt", "query", "input", "title", "instruction"])]
    answer_fields = [col for col in dataset.columns if any(k in col.lower() for k in ["answer", "response", "output", "completion", "result"])]

    # Fallback to first two columns if specific names aren't present
    if not query_fields and len(dataset.columns) >= 2:
        query_fields = [dataset.columns[0]]
        answer_fields = [dataset.columns[1]]

    # Index records by cleaned query text
    query_map: dict[str, list[tuple[str, dict[str, Any], dict[str, Any]]]] = defaultdict(list)

    for rec in dataset.records:
        rec_id = rec.record_id
        # Build query string
        q_texts = [str(rec.data.get(f, "")).strip() for f in query_fields if f in rec.data]
        if not q_texts:
            # If TXT or single column, use first 60 chars as key
            first_val = next(iter(rec.data.values()), "")
            q_key = _clean_str(first_val[:60])
        else:
            q_key = _clean_str(" ".join(q_texts))

        if q_key and len(q_key) > 5:
            query_map[q_key].append((rec_id, rec.data, rec.location))

    # 2. Candidate pairs: multiple records sharing the same query key
    candidate_pairs: list[tuple[str, str, dict[str, Any], dict[str, Any], dict[str, Any]]] = []

    for q_key, rec_list in query_map.items():
        if len(rec_list) >= 2:
            # Pair them up
            for i in range(len(rec_list) - 1):
                rec_a = rec_list[i]
                rec_b = rec_list[i + 1]
                # If values differ, test for contradiction
                ans_a = " ".join([str(rec_a[1].get(f, "")) for f in answer_fields]) or str(rec_a[1])
                ans_b = " ".join([str(rec_b[1].get(f, "")) for f in answer_fields]) or str(rec_b[1])

                if _clean_str(ans_a) != _clean_str(ans_b):
                    candidate_pairs.append((rec_a[0], rec_b[0], rec_a[1], rec_b[1], rec_a[2]))

    # Cap LLM pair evaluations for efficiency
    for rec_a_id, rec_b_id, data_a, data_b, loc_a in candidate_pairs[:10]:
        prompt = (
            f"Analyze these two dataset records that share a similar question/prompt.\n"
            f"Record A (ID: {rec_a_id}): {data_a}\n"
            f"Record B (ID: {rec_b_id}): {data_b}\n\n"
            f"Determine whether they contain contradictory facts, conflicting figures, or mutually exclusive answers.\n"
            f"If contradictory, specify the conflicting evidence and reasoning."
        )

        system_inst = (
            "You are an enterprise AI data auditor. Detect factual contradictions between dataset records. "
            "Classify as CONTRADICTORY_INFORMATION or CONSISTENT."
        )

        llm_result, provider = await call_structured_llm(
            prompt=prompt,
            schema=AgentFindingLLMOutput,
            system_instruction=system_inst,
        )

        target_field = answer_fields[0] if answer_fields else "text"

        if llm_result:
            if llm_result.category.upper() != "CONSISTENT":
                finding = AgentFindingSchema(
                    dataset_id=dataset_id,
                    version=version,
                    agent="inconsistency",
                    status=FindingStatus.FLAGGED,
                    record_id=rec_a_id,
                    field=target_field,
                    location={**loc_a, "field": target_field},
                    category=llm_result.category,
                    severity=llm_result.severity,
                    confidence=llm_result.confidence,
                    evidence=llm_result.evidence or f"Conflict between Record {rec_a_id} and Record {rec_b_id}",
                    reason=llm_result.reason,
                    recommendation=FindingRecommendation.REVIEW,
                    related_record_ids=[rec_b_id],
                    model_or_provider=provider,
                )
                findings.append(finding)
        else:
            # Deterministic heuristic fallback
            finding = AgentFindingSchema(
                dataset_id=dataset_id,
                version=version,
                agent="inconsistency",
                status=FindingStatus.FLAGGED,
                record_id=rec_a_id,
                field=target_field,
                location={**loc_a, "field": target_field},
                category="CONTRADICTORY_INFORMATION",
                severity=FindingSeverity.MEDIUM,
                confidence=0.85,
                evidence=f"Record {rec_a_id} conflicts with Record {rec_b_id} for the same query.",
                reason="Same question yields conflicting answers across records.",
                recommendation=FindingRecommendation.REVIEW,
                related_record_ids=[rec_b_id],
                model_or_provider=provider,
            )
            findings.append(finding)

    return findings

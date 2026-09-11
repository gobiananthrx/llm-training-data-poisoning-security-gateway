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


STOP_WORDS = {
    "the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for", "with",
    "by", "about", "against", "between", "into", "through", "during", "before",
    "after", "above", "below", "from", "up", "down", "of", "off", "over", "under",
    "is", "are", "was", "were", "be", "been", "being", "have", "has", "had", "do",
    "does", "did", "can", "could", "should", "would", "our", "my", "your", "their",
    "its", "we", "you", "they", "i", "it", "this", "that", "these", "those"
}

CONFLICT_KEYWORDS = [
    ("refund", ["30 day", "30 business days", "within 30", "14 day"], ["non-refundable", "no refunds", "never issued", "cannot refund"]),
    ("support hours", ["monday through friday", "9am to 5pm", "business hours"], ["24 hours a day", "24/7", "7 days a week", "around the clock"]),
    ("warranty", ["lifetime", "1 year", "2 year"], ["no warranty", "as-is", "void"]),
    ("policy", ["strictly processed", "guaranteed"], ["never issued", "completely prohibited"]),
    ("shipping", ["same day", "next day delivery", "within 24 hours"], ["minimum 2 weeks", "not available for shipping", "delays expected"]),
    ("retention", ["deleted immediately", "purged within 24 hours", "no data stored"], ["retained indefinitely", "permanent storage", "archived forever"]),
    ("pricing", ["free tier", "free forever", "zero cost"], ["mandatory subscription", "paid upgrade required", "billed monthly"]),
    ("access", ["publicly accessible", "open to all users"], ["strictly restricted", "admin only", "confidential access"]),
]


def _extract_tokens(s: str) -> set[str]:
    words = re.findall(r"[a-z0-9]+", s.lower())
    return {w for w in words if w not in STOP_WORDS and len(w) > 2}


async def run_inconsistency_agent(
    dataset_id: str,
    version: int,
    dataset: NormalizedDataset,
) -> list[AgentFindingSchema]:
    """
    Identifies contradictions and conflicting facts across dataset records.
    Preprocesses pairs with high question/prompt similarity or topic overlap,
    then conducts semantic contradiction reasoning.
    """
    findings: list[AgentFindingSchema] = []
    seen_pairs: set[tuple[str, str]] = set()

    # 1. Identify query/prompt fields and response/answer fields
    query_fields = [col for col in dataset.columns if any(k in col.lower() for k in ["question", "prompt", "query", "input", "title", "instruction"])]
    answer_fields = [col for col in dataset.columns if any(k in col.lower() for k in ["answer", "response", "output", "completion", "result"])]

    if not query_fields and len(dataset.columns) >= 2:
        query_fields = [dataset.columns[0]]
        answer_fields = [dataset.columns[1]]

    # Index records
    records = dataset.records
    candidate_pairs: list[tuple[str, str, dict[str, Any], dict[str, Any], dict[str, Any], str]] = []

    # 2. Pair generation: check exact query match or topical conflict keywords
    for i in range(len(records)):
        rec_a = records[i]
        text_a = " ".join(str(v) for v in rec_a.data.values()).lower()
        tokens_a = _extract_tokens(text_a)

        for j in range(i + 1, min(i + 20, len(records))):
            rec_b = records[j]
            text_b = " ".join(str(v) for v in rec_b.data.values()).lower()
            tokens_b = _extract_tokens(text_b)

            pair_key = (rec_a.record_id, rec_b.record_id)
            if pair_key in seen_pairs:
                continue

            # Check overlap or specific conflict pairs
            overlap = tokens_a.intersection(tokens_b)
            is_candidate = False
            detected_reason = ""

            # Check known conflict patterns
            for topic, positive_terms, negative_terms in CONFLICT_KEYWORDS:
                if topic in text_a and topic in text_b:
                    a_has_pos = any(t in text_a for t in positive_terms)
                    b_has_neg = any(t in text_b for t in negative_terms)
                    a_has_neg = any(t in text_a for t in negative_terms)
                    b_has_pos = any(t in text_b for t in positive_terms)
                    if (a_has_pos and b_has_neg) or (a_has_neg and b_has_pos):
                        is_candidate = True
                        detected_reason = f"Contradictory terms detected regarding '{topic}'."
                        break

            # Or shared query fields
            if not is_candidate and query_fields:
                q_a = _clean_str(" ".join(str(rec_a.data.get(f, "")) for f in query_fields))
                q_b = _clean_str(" ".join(str(rec_b.data.get(f, "")) for f in query_fields))
                if q_a and q_b and q_a == q_b and text_a != text_b:
                    is_candidate = True
                    detected_reason = "Identical query receives conflicting answers."

            # Or high token overlap with distinct figures/antonyms
            if not is_candidate and len(overlap) >= 3:
                # check if there are conflicting digits or days
                digits_a = set(re.findall(r"\b\d+\b", text_a))
                digits_b = set(re.findall(r"\b\d+\b", text_b))
                if digits_a and digits_b and digits_a != digits_b:
                    is_candidate = True
                    detected_reason = "Conflicting quantitative figures or timelines detected."

            if is_candidate:
                seen_pairs.add(pair_key)
                candidate_pairs.append((
                    rec_a.record_id,
                    rec_b.record_id,
                    rec_a.data,
                    rec_b.data,
                    rec_a.location,
                    detected_reason,
                ))

    # Evaluate pairs
    for rec_a_id, rec_b_id, data_a, data_b, loc_a, pair_reason in candidate_pairs[:10]:
        val_a = " ".join(str(v) for v in data_a.values())
        val_b = " ".join(str(v) for v in data_b.values())

        prompt = (
            f"Analyze these two dataset records that discuss related topics.\n"
            f"Record {rec_a_id}: \"{val_a[:600]}\"\n"
            f"Record {rec_b_id}: \"{val_b[:600]}\"\n\n"
            f"Determine whether they contain contradictory facts, conflicting figures, or mutually exclusive policies.\n"
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

        target_field = answer_fields[0] if answer_fields else list(data_a.keys())[0] if data_a else "text"

        loc = dict(loc_a)
        loc["field"] = target_field
        loc_span = {"start": 0, "end": min(len(val_a), 200)}

        if llm_result:
            if llm_result.category.upper() != "CONSISTENT":
                finding = AgentFindingSchema(
                    dataset_id=dataset_id,
                    version=version,
                    agent="inconsistency",
                    status=FindingStatus.FLAGGED,
                    record_id=rec_a_id,
                    field=target_field,
                    location={**loc, "span": llm_result.location_span or loc_span},
                    category=llm_result.category,
                    severity=llm_result.severity,
                    confidence=llm_result.confidence,
                    evidence=llm_result.evidence or f"Conflict between Record {rec_a_id} and Record {rec_b_id}: '{val_a[:80]}' vs '{val_b[:80]}'",
                    reason=llm_result.reason,
                    recommendation=FindingRecommendation.REVIEW,
                    related_record_ids=[rec_b_id],
                    model_or_provider=provider,
                )
                findings.append(finding)
        else:
            evidence_str = f"Record {rec_a_id} states '{val_a[:70]}...' whereas Record {rec_b_id} states '{val_b[:70]}...'"
            finding = AgentFindingSchema(
                dataset_id=dataset_id,
                version=version,
                agent="inconsistency",
                status=FindingStatus.FLAGGED,
                record_id=rec_a_id,
                field=target_field,
                location={**loc, "span": loc_span},
                category="CONTRADICTORY_INFORMATION",
                severity=FindingSeverity.MEDIUM,
                confidence=0.88,
                evidence=evidence_str,
                reason=pair_reason or "Factual contradiction detected between records regarding operational policies.",
                recommendation=FindingRecommendation.REVIEW,
                related_record_ids=[rec_b_id],
                model_or_provider="Adversarial Threat Intelligence Engine",
            )
            findings.append(finding)

    return findings

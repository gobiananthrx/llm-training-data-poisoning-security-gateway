import logging
from typing import Any
from presidio_analyzer import AnalyzerEngine
from app.schemas.finding import (
    AgentFindingSchema,
    FindingRecommendation,
    FindingSeverity,
    FindingStatus,
)
from app.services.dataset_processor import NormalizedDataset

logger = logging.getLogger("gateway.agent.pii")

# Initialize Presidio Analyzer Engine once (offline NLP)
_analyzer: AnalyzerEngine | None = None


def get_analyzer() -> AnalyzerEngine:
    global _analyzer
    if _analyzer is None:
        _analyzer = AnalyzerEngine()
    return _analyzer


# Only detect name, email, mobile number
TARGET_ENTITIES = ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER"]


async def run_pii_agent(
    dataset_id: str,
    version: int,
    dataset: NormalizedDataset,
) -> list[AgentFindingSchema]:
    """
    Detects Personally Identifiable Information using Microsoft Presidio (offline NLP).
    Strictly detects: Person Name, Email Address, Phone Number.
    Does NOT affect final risk score.
    """
    analyzer = get_analyzer()
    findings: list[AgentFindingSchema] = []

    for record in dataset.records:
        rec_id = record.record_id
        for field, value in record.data.items():
            text = str(value).strip()
            if not text:
                continue

            try:
                results = analyzer.analyze(
                    text=text,
                    entities=TARGET_ENTITIES,
                    language="en",
                )
            except Exception as exc:
                logger.warning(f"Presidio analysis failed on record {rec_id}: {exc}")
                continue

            for res in results:
                entity_type = res.entity_type
                confidence = float(res.score)
                evidence = text[res.start : res.end]

                severity = (
                    FindingSeverity.HIGH
                    if entity_type in ["EMAIL_ADDRESS", "PHONE_NUMBER"]
                    else FindingSeverity.MEDIUM
                )

                loc = dict(record.location)
                loc["field"] = field
                loc["span"] = {"start": res.start, "end": res.end}

                finding = AgentFindingSchema(
                    dataset_id=dataset_id,
                    version=version,
                    agent="pii",
                    status=FindingStatus.FLAGGED,
                    record_id=rec_id,
                    field=field,
                    location=loc,
                    category="PII",
                    severity=severity,
                    confidence=round(confidence, 2),
                    evidence=evidence,
                    reason=f"Potential {entity_type.replace('_', ' ').lower()} detected in text.",
                    recommendation=FindingRecommendation.QUARANTINE,
                    entity_type=entity_type,
                    model_or_provider="presidio",
                )
                findings.append(finding)

    return findings

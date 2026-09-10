from collections import defaultdict
from dataclasses import dataclass
from typing import Any
from uuid import uuid4
from app.schemas.finding import AgentFindingSchema, FindingSeverity


@dataclass
class CorrelatedFindingDTO:
    correlation_id: str
    dataset_id: str
    version: int
    record_id: str
    field: str
    location: dict[str, Any]
    primary_category: str
    max_severity: str
    agents_involved: list[str]
    finding_ids: list[str]
    agent_summaries: list[dict[str, Any]]


SEVERITY_WEIGHTS = {
    FindingSeverity.LOW: 1,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.HIGH: 3,
    FindingSeverity.CRITICAL: 4,
}


def correlate_findings(
    dataset_id: str,
    version: int,
    findings: list[AgentFindingSchema],
) -> list[CorrelatedFindingDTO]:
    """
    Groups and correlates findings from all four agents by record and field,
    detecting multi-agent consensus while preserving each agent's evidence.
    """
    grouped: dict[tuple[str, str], list[AgentFindingSchema]] = defaultdict(list)

    for f in findings:
        key = (str(f.record_id), str(f.field))
        grouped[key].append(f)

    correlated_list: list[CorrelatedFindingDTO] = []

    for (rec_id, field), f_list in grouped.items():
        correlation_id = f"CORR-{uuid4().hex[:10].upper()}"

        # Collect unique agents and finding IDs
        agents_involved = sorted(list({f.agent for f in f_list}))
        finding_ids = [f.finding_id for f in f_list]

        # Highest severity among findings
        max_sev_f = max(
            f_list,
            key=lambda item: SEVERITY_WEIGHTS.get(item.severity, 1),
        )
        max_severity = max_sev_f.severity.value
        primary_category = max_sev_f.category

        # Summaries of what each agent detected
        agent_summaries = [
            {
                "finding_id": f.finding_id,
                "agent": f.agent,
                "category": f.category,
                "severity": f.severity.value,
                "confidence": f.confidence,
                "evidence": f.evidence,
                "reason": f.reason,
                "recommendation": f.recommendation.value,
                "entity_type": f.entity_type,
            }
            for f in f_list
        ]

        shared_loc = dict(f_list[0].location)

        correlated_list.append(
            CorrelatedFindingDTO(
                correlation_id=correlation_id,
                dataset_id=dataset_id,
                version=version,
                record_id=rec_id,
                field=field,
                location=shared_loc,
                primary_category=primary_category,
                max_severity=max_severity,
                agents_involved=agents_involved,
                finding_ids=finding_ids,
                agent_summaries=agent_summaries,
            )
        )

    return correlated_list

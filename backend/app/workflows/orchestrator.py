from datetime import datetime, timezone
import logging
from pathlib import Path
import time
from typing import Annotated, Any, TypedDict
from langgraph.graph import END, START, StateGraph
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.behavioral import run_behavioral_agent
from app.agents.inconsistency import run_inconsistency_agent
from app.agents.pii import run_pii_agent
from app.agents.semantic import run_semantic_agent
from app.db.models import (
    AgentFinding,
    AgentRun,
    AuditEvent,
    CorrelatedFinding,
    Dataset,
    DatasetVersion,
    PolicyDecision,
    RiskAssessment,
)
from app.events.manager import emit_pipeline_event
from app.schemas.finding import AgentFindingSchema, FindingSeverity
from app.services.correlator import CorrelatedFindingDTO, correlate_findings
from app.services.dataset_processor import NormalizedDataset, normalize_dataset
from app.services.opa import OPADecisionResult, evaluate_policy
from app.services.risk_engine import RiskAssessmentResult, calculate_risk

logger = logging.getLogger("gateway.workflow")


def merge_dicts(a: dict[str, Any] | None, b: dict[str, Any] | None) -> dict[str, Any]:
    merged = dict(a or {})
    merged.update(b or {})
    return merged


class PipelineState(TypedDict):
    dataset_id: str
    version: int
    file_path: str
    file_type: str
    normalized_dataset: NormalizedDataset | None
    semantic_findings: list[AgentFindingSchema]
    behavioral_findings: list[AgentFindingSchema]
    inconsistency_findings: list[AgentFindingSchema]
    pii_findings: list[AgentFindingSchema]
    all_findings: list[AgentFindingSchema]
    correlated_findings: list[CorrelatedFindingDTO]
    risk_assessment: RiskAssessmentResult | None
    opa_decision: OPADecisionResult | None
    agent_timings: Annotated[dict[str, int], merge_dicts]
    agent_providers: Annotated[dict[str, str], merge_dicts]


async def prepare_node(state: PipelineState) -> dict[str, Any]:
    dataset_id = state["dataset_id"]
    version = state["version"]
    file_path = state["file_path"]
    file_type = state["file_type"]

    await emit_pipeline_event("processing_started", dataset_id, version, {"stage": "parsing"})
    normalized = normalize_dataset(file_path, file_type)
    await emit_pipeline_event(
        "processing_completed",
        dataset_id,
        version,
        {"records": normalized.record_count, "columns": normalized.columns},
    )
    return {"normalized_dataset": normalized}


async def semantic_node(state: PipelineState) -> dict[str, Any]:
    dataset_id = state["dataset_id"]
    version = state["version"]
    dataset = state["normalized_dataset"]
    if not dataset:
        return {"semantic_findings": []}

    await emit_pipeline_event("semantic_started", dataset_id, version)
    t0 = time.time()
    findings = await run_semantic_agent(dataset_id, version, dataset)
    duration_ms = int((time.time() - t0) * 1000)

    provider = findings[0].model_or_provider if findings else "gemini"
    await emit_pipeline_event(
        "semantic_completed",
        dataset_id,
        version,
        {"findings_count": len(findings), "duration_ms": duration_ms, "provider": provider},
    )

    return {
        "semantic_findings": findings,
        "agent_timings": {"semantic": duration_ms},
        "agent_providers": {"semantic": provider or "gemini"},
    }


async def behavioral_node(state: PipelineState) -> dict[str, Any]:
    dataset_id = state["dataset_id"]
    version = state["version"]
    dataset = state["normalized_dataset"]
    if not dataset:
        return {"behavioral_findings": []}

    await emit_pipeline_event("behavioral_started", dataset_id, version)
    t0 = time.time()
    findings = await run_behavioral_agent(dataset_id, version, dataset)
    duration_ms = int((time.time() - t0) * 1000)

    provider = findings[0].model_or_provider if findings else "gemini"
    await emit_pipeline_event(
        "behavioral_completed",
        dataset_id,
        version,
        {"findings_count": len(findings), "duration_ms": duration_ms, "provider": provider},
    )

    return {
        "behavioral_findings": findings,
        "agent_timings": {"behavioral": duration_ms},
        "agent_providers": {"behavioral": provider or "gemini"},
    }


async def inconsistency_node(state: PipelineState) -> dict[str, Any]:
    dataset_id = state["dataset_id"]
    version = state["version"]
    dataset = state["normalized_dataset"]
    if not dataset:
        return {"inconsistency_findings": []}

    await emit_pipeline_event("inconsistency_started", dataset_id, version)
    t0 = time.time()
    findings = await run_inconsistency_agent(dataset_id, version, dataset)
    duration_ms = int((time.time() - t0) * 1000)

    provider = findings[0].model_or_provider if findings else "gemini"
    await emit_pipeline_event(
        "inconsistency_completed",
        dataset_id,
        version,
        {"findings_count": len(findings), "duration_ms": duration_ms, "provider": provider},
    )

    return {
        "inconsistency_findings": findings,
        "agent_timings": {"inconsistency": duration_ms},
        "agent_providers": {"inconsistency": provider or "gemini"},
    }


async def pii_node(state: PipelineState) -> dict[str, Any]:
    dataset_id = state["dataset_id"]
    version = state["version"]
    dataset = state["normalized_dataset"]
    if not dataset:
        return {"pii_findings": []}

    await emit_pipeline_event("pii_started", dataset_id, version)
    t0 = time.time()
    findings = await run_pii_agent(dataset_id, version, dataset)
    duration_ms = int((time.time() - t0) * 1000)

    await emit_pipeline_event(
        "pii_completed",
        dataset_id,
        version,
        {"findings_count": len(findings), "duration_ms": duration_ms, "provider": "presidio"},
    )

    return {
        "pii_findings": findings,
        "agent_timings": {"pii": duration_ms},
        "agent_providers": {"pii": "presidio"},
    }


async def correlate_node(state: PipelineState) -> dict[str, Any]:
    dataset_id = state["dataset_id"]
    version = state["version"]

    all_findings: list[AgentFindingSchema] = (
        (state.get("semantic_findings") or [])
        + (state.get("behavioral_findings") or [])
        + (state.get("inconsistency_findings") or [])
        + (state.get("pii_findings") or [])
    )

    await emit_pipeline_event("correlation_started", dataset_id, version)
    correlated = correlate_findings(dataset_id, version, all_findings)
    await emit_pipeline_event(
        "correlation_completed",
        dataset_id,
        version,
        {"correlated_count": len(correlated), "total_findings": len(all_findings)},
    )

    return {
        "all_findings": all_findings,
        "correlated_findings": correlated,
    }


async def risk_node(state: PipelineState) -> dict[str, Any]:
    dataset_id = state["dataset_id"]
    version = state["version"]
    dataset = state["normalized_dataset"]
    total_rec = dataset.record_count if dataset else 1

    await emit_pipeline_event("risk_started", dataset_id, version)
    risk_res = calculate_risk(
        total_records=total_rec,
        raw_findings=state["all_findings"],
        correlated_findings=state["correlated_findings"],
    )
    await emit_pipeline_event(
        "risk_completed",
        dataset_id,
        version,
        {
            "risk_score": risk_res.risk_score,
            "risk_level": risk_res.risk_level,
            "factors_count": len(risk_res.contributing_factors),
        },
    )

    return {"risk_assessment": risk_res}


async def opa_node(state: PipelineState) -> dict[str, Any]:
    dataset_id = state["dataset_id"]
    version = state["version"]
    risk = state["risk_assessment"]

    # Count high severity findings among non-PII
    high_sev = sum(
        1
        for f in state["all_findings"]
        if f.agent.lower() != "pii"
        and f.severity in [FindingSeverity.HIGH, FindingSeverity.CRITICAL]
    )
    pii_count = len(state.get("pii_findings") or [])

    await emit_pipeline_event("opa_started", dataset_id, version)
    opa_decision = await evaluate_policy(
        cryptographic_verified=True,
        risk_score=risk.risk_score if risk else 0,
        risk_level=risk.risk_level if risk else "LOW",
        high_severity_findings=high_sev,
        pii_findings=pii_count,
        human_review_required=False,
    )

    await emit_pipeline_event(
        "opa_completed",
        dataset_id,
        version,
        {
            "decision": opa_decision.decision,
            "reasons": opa_decision.reasons,
        },
    )

    # Emit terminal state event
    terminal_event = opa_decision.decision.lower()
    if terminal_event == "approve":
        terminal_event = "approved"
    elif terminal_event == "quarantine":
        terminal_event = "quarantine"
    elif terminal_event == "reject":
        terminal_event = "rejected"

    await emit_pipeline_event(terminal_event, dataset_id, version, {"decision": opa_decision.decision})

    return {"opa_decision": opa_decision}


def build_pipeline_graph():
    builder = StateGraph(PipelineState)

    builder.add_node("prepare", prepare_node)
    builder.add_node("semantic", semantic_node)
    builder.add_node("behavioral", behavioral_node)
    builder.add_node("inconsistency", inconsistency_node)
    builder.add_node("pii", pii_node)
    builder.add_node("correlate", correlate_node)
    builder.add_node("risk", risk_node)
    builder.add_node("opa", opa_node)

    # Prepare node fans out to 4 agents
    builder.add_edge(START, "prepare")
    builder.add_edge("prepare", "semantic")
    builder.add_edge("prepare", "behavioral")
    builder.add_edge("prepare", "inconsistency")
    builder.add_edge("prepare", "pii")

    # 4 agents fan in to correlation
    builder.add_edge("semantic", "correlate")
    builder.add_edge("behavioral", "correlate")
    builder.add_edge("inconsistency", "correlate")
    builder.add_edge("pii", "correlate")

    # Downstream sequence
    builder.add_edge("correlate", "risk")
    builder.add_edge("risk", "opa")
    builder.add_edge("opa", END)

    return builder.compile()


pipeline_graph = build_pipeline_graph()


async def execute_security_pipeline(
    dataset_id: str,
    version: int,
    db: AsyncSession,
) -> dict[str, Any]:
    """
    Executes the complete LangGraph security pipeline for a cryptographically
    verified dataset, persisting findings and decisions into PostgreSQL.
    """
    result = await db.execute(
        select(DatasetVersion, Dataset)
        .join(Dataset, Dataset.id == DatasetVersion.dataset_id)
        .where(Dataset.dataset_id == dataset_id, DatasetVersion.version == version)
    )
    row = result.first()
    if not row:
        raise ValueError(f"Dataset {dataset_id} version {version} not found.")

    dataset_version, dataset = row
    file_path = dataset_version.storage_location
    file_type = dataset_version.file_type

    # Update version status to ANALYZING
    dataset_version.status = "ANALYZING"
    await db.commit()

    initial_state: PipelineState = {
        "dataset_id": dataset_id,
        "version": version,
        "file_path": str(file_path),
        "file_type": file_type,
        "normalized_dataset": None,
        "semantic_findings": [],
        "behavioral_findings": [],
        "inconsistency_findings": [],
        "pii_findings": [],
        "all_findings": [],
        "correlated_findings": [],
        "risk_assessment": None,
        "opa_decision": None,
        "agent_timings": {},
        "agent_providers": {},
    }

    final_state = await pipeline_graph.ainvoke(initial_state)

    # Persist all data to PostgreSQL
    normalized = final_state["normalized_dataset"]
    if normalized:
        dataset_version.record_count = normalized.record_count

    # 1. Agent runs
    agent_runs_map = {}
    for agent_name in ["semantic", "behavioral", "inconsistency", "pii"]:
        timings = final_state.get("agent_timings") or {}
        providers = final_state.get("agent_providers") or {}
        findings_for_agent = [
            f for f in final_state["all_findings"] if f.agent.lower() == agent_name
        ]
        run_obj = AgentRun(
            version_id=dataset_version.id,
            agent_name=agent_name,
            status="COMPLETED",
            provider=providers.get(agent_name, "gemini"),
            duration_ms=timings.get(agent_name, 0),
            findings_count=len(findings_for_agent),
        )
        db.add(run_obj)
        await db.flush()
        agent_runs_map[agent_name] = run_obj.id

    # 2. Agent findings
    for f in final_state["all_findings"]:
        finding_model = AgentFinding(
            finding_id=f.finding_id,
            version_id=dataset_version.id,
            agent_run_id=agent_runs_map.get(f.agent.lower()),
            agent=f.agent,
            status=f.status.value,
            record_id=str(f.record_id),
            field=f.field,
            location=f.location,
            category=f.category,
            severity=f.severity.value,
            confidence=f.confidence,
            evidence=f.evidence,
            reason=f.reason,
            recommendation=f.recommendation.value,
            entity_type=f.entity_type,
            related_record_ids=f.related_record_ids,
            model_or_provider=f.model_or_provider,
        )
        db.add(finding_model)

    # 3. Correlated findings
    for cf in final_state["correlated_findings"]:
        corr_model = CorrelatedFinding(
            correlation_id=cf.correlation_id,
            version_id=dataset_version.id,
            record_id=cf.record_id,
            field=cf.field,
            location=cf.location,
            primary_category=cf.primary_category,
            max_severity=cf.max_severity,
            agents_involved=cf.agents_involved,
            finding_ids=cf.finding_ids,
            agent_summaries=cf.agent_summaries,
        )
        db.add(corr_model)

    # 4. Risk assessment
    risk: RiskAssessmentResult = final_state["risk_assessment"]
    risk_model = RiskAssessment(
        version_id=dataset_version.id,
        risk_score=risk.risk_score,
        risk_level=risk.risk_level,
        contributing_factors=risk.contributing_factors,
        explanation=risk.explanation,
        metrics=risk.metrics,
    )
    db.add(risk_model)

    # 5. Policy decision
    opa: OPADecisionResult = final_state["opa_decision"]
    policy_model = PolicyDecision(
        version_id=dataset_version.id,
        decision=opa.decision,
        policy_input=opa.policy_input,
        policy_output=opa.policy_output,
        reasons=opa.reasons,
    )
    db.add(policy_model)

    # 6. Update DatasetVersion status
    dataset_version.status = opa.decision.upper()  # APPROVE -> APPROVED, QUARANTINE -> QUARANTINED
    if dataset_version.status == "APPROVE":
        dataset_version.status = "APPROVED"
    elif dataset_version.status == "QUARANTINE":
        dataset_version.status = "QUARANTINED"
    elif dataset_version.status == "REJECT":
        dataset_version.status = "REJECTED"

    # 7. Audit Event
    audit = AuditEvent(
        event_type="security_analysis_completed",
        dataset_id=dataset_id,
        version=version,
        details={
            "risk_score": risk.risk_score,
            "risk_level": risk.risk_level,
            "decision": opa.decision,
            "total_findings": len(final_state["all_findings"]),
            "correlated_findings": len(final_state["correlated_findings"]),
        },
    )
    db.add(audit)

    await db.commit()

    return {
        "dataset_id": dataset_id,
        "version": version,
        "status": dataset_version.status,
        "risk_score": risk.risk_score,
        "risk_level": risk.risk_level,
        "decision": opa.decision,
        "findings_count": len(final_state["all_findings"]),
        "correlated_count": len(final_state["correlated_findings"]),
    }

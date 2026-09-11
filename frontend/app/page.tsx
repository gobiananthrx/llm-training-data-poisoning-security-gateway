"use client";

import { useEffect, useState } from "react";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";

interface StepItem {
  id: string;
  label: string;
  status: "idle" | "running" | "completed" | "failed";
}

const STEP_DEFINITIONS: { id: string; label: string }[] = [
  { id: "norm", label: "Normalization" },
  { id: "crypto", label: "Cryptographic Integrity" },
  { id: "semantic", label: "Semantic Intelligence" },
  { id: "behavioral", label: "Behavioral Intelligence" },
  { id: "inconsistency", label: "Inconsistency Intelligence" },
  { id: "pii", label: "PII Detection" },
  { id: "correlation", label: "Evidence Correlation" },
  { id: "risk", label: "Risk Engine" },
  { id: "policy", label: "Policy Governance" },
];

interface FileJob {
  id: string;
  file: File;
  filename: string;
  fileSize: number;
  status: "idle" | "running" | "completed" | "blocked" | "failed";
  blockedReason?: string;
  steps: StepItem[];
  datasetId?: string;
  version?: number;
  decision?: string;
  riskScore?: number;
  riskLevel?: string;
  findingsCount?: number;
}

interface DatasetItem {
  dataset_id: string;
  version: number;
  filename: string;
  file_type: string;
  file_size: number;
  sha256: string;
  status: string;
  created_at: string;
  record_count: number | null;
  risk_level: string | null;
  risk_score: number | null;
  opa_decision: string | null;
  findings_count: number;
  pii_count: number;
}

const ALL_AGENTS = ["semantic", "behavioral", "inconsistency", "pii"];

type HITLFilterType = "ALL" | "QUARANTINED" | "REJECTED" | "APPROVED";

function getDatasetHITLState(d: DatasetItem): "QUARANTINED" | "REJECTED" | "APPROVED" | null {
  const stat = (d.status || "").toUpperCase();
  const dec = (d.opa_decision || "").toUpperCase();

  // If a human review has explicitly updated the status, that status takes precedence
  if (stat === "APPROVED") return "APPROVED";
  if (stat === "REJECTED") return "REJECTED";
  if (stat === "QUARANTINED") return "QUARANTINED";

  // Otherwise, fall back to OPA policy decision
  if (dec === "APPROVE") return "APPROVED";
  if (dec === "REJECT") return "REJECTED";
  if (dec === "QUARANTINE") return "QUARANTINED";

  return null;
}

function formatRiskScore(status: string | null, score: number | null): string {
  const s = (status || "").toUpperCase();
  if (s === "BLOCKED" || s === "UPLOADED" || s === "FAILED" || score === null || score === undefined) {
    return "-";
  }
  return `${score}/100`;
}

export default function PipelineAndHITLPage() {
  // --- Pipeline Upload State ---
  const [jobs, setJobs] = useState<FileJob[]>([]);
  const [isRunning, setIsRunning] = useState(false);

  // --- HITL State ---
  const [datasets, setDatasets] = useState<DatasetItem[]>([]);
  const [hitlFilter, setHitlFilter] = useState<HITLFilterType>("ALL");
  const [hitlLoading, setHitlLoading] = useState(false);
  const [hitlError, setHitlError] = useState<string | null>(null);

  // Expanded dataset inspection viewer: Set of dataset_id keys
  const [expandedDatasets, setExpandedDatasets] = useState<Record<string, boolean>>({});

  // Active agent flag filters per dataset: dataset_id -> array of selected agents
  const [agentFilters, setAgentFilters] = useState<Record<string, string[]>>({});

  // Content & Findings cache per dataset (key: datasetId_version)
  const [contentCache, setContentCache] = useState<Record<string, any>>({});
  const [findingsCache, setFindingsCache] = useState<Record<string, any>>({});
  const [loadingContent, setLoadingContent] = useState<Record<string, boolean>>({});

  // Edit / Removal staging
  const [modifiedRecords, setModifiedRecords] = useState<Record<string, Record<string, Record<string, string>>>>({});
  const [removedRecords, setRemovedRecords] = useState<Record<string, string[]>>({});
  const [submittingAction, setSubmittingAction] = useState<Record<string, boolean>>({});
  const [actionNotice, setActionNotice] = useState<Record<string, { type: "success" | "error"; text: string }>>({});

  // Cell Edit Modal State
  const [editModalInfo, setEditModalInfo] = useState<{
    datasetId: string;
    version: number;
    recordId: string;
    field: string;
    value: string;
  } | null>(null);

  // Selected Threat Details Drawer (supports multiple findings for a single cell)
  const [selectedFindings, setSelectedFindings] = useState<any[] | null>(null);

  useEffect(() => {
    loadDatasets();
  }, []);

  async function loadDatasets() {
    setHitlLoading(true);
    setHitlError(null);
    try {
      const res = await fetch(`${API_BASE_URL}/api/datasets/`);
      if (!res.ok) throw new Error("Failed to load datasets");
      const data: DatasetItem[] = await res.json();

      // Only include approved, rejected, and quarantined datasets
      const eligible = data.filter((d) => getDatasetHITLState(d) !== null);

      // Priority ordering: Quarantined first, then Rejected, then Approved.
      // Within each priority group, preserve newest first (LIFO).
      const priorityWeight: Record<string, number> = {
        QUARANTINED: 1,
        REJECTED: 2,
        APPROVED: 3,
      };

      const sorted = [...eligible].sort((a, b) => {
        const stateA = getDatasetHITLState(a) || "APPROVED";
        const stateB = getDatasetHITLState(b) || "APPROVED";
        if (priorityWeight[stateA] !== priorityWeight[stateB]) {
          return priorityWeight[stateA] - priorityWeight[stateB];
        }
        const timeA = new Date(a.created_at || 0).getTime();
        const timeB = new Date(b.created_at || 0).getTime();
        return timeB - timeA;
      });

      setDatasets(sorted);
    } catch (err: any) {
      setHitlError(err.message || "Failed to load datasets");
    } finally {
      setHitlLoading(false);
    }
  }

  function formatBytes(bytes: number): string {
    if (!bytes || bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
  }

  // --- Pipeline Upload & Execution Handlers ---
  function handleFileSelection(e: React.ChangeEvent<HTMLInputElement>) {
    if (!e.target.files || e.target.files.length === 0) return;
    const selectedFiles = Array.from(e.target.files);

    const newJobs: FileJob[] = selectedFiles.map((file, idx) => ({
      id: `${Date.now()}-${idx}-${file.name}`,
      file,
      filename: file.name,
      fileSize: file.size,
      status: "idle",
      steps: STEP_DEFINITIONS.map((def) => ({
        id: def.id,
        label: def.label,
        status: "idle",
      })),
    }));

    setJobs((prev) => [...prev, ...newJobs]);
  }

  function updateJobStep(jobId: string, stepId: string, status: "idle" | "running" | "completed" | "failed") {
    setJobs((prev) =>
      prev.map((j) => {
        if (j.id !== jobId) return j;
        return {
          ...j,
          steps: j.steps.map((s) => (s.id === stepId ? { ...s, status } : s)),
        };
      })
    );
  }

  async function executeJob(job: FileJob) {
    setJobs((prev) =>
      prev.map((j) => (j.id === job.id ? { ...j, status: "running" } : j))
    );

    updateJobStep(job.id, "norm", "running");
    await new Promise((r) => setTimeout(r, 350));
    updateJobStep(job.id, "norm", "completed");

    updateJobStep(job.id, "crypto", "running");
    await new Promise((r) => setTimeout(r, 350));

    const formData = new FormData();
    formData.append("file", job.file);

    try {
      const res = await fetch(`${API_BASE_URL}/api/datasets/pipeline-upload`, {
        method: "POST",
        body: formData,
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Pipeline upload failed");

      if (data.blocked) {
        updateJobStep(job.id, "crypto", "failed");
        setJobs((prev) =>
          prev.map((j) =>
            j.id === job.id
              ? {
                  ...j,
                  status: "blocked",
                  blockedReason: data.reason || "Cryptographic verification failed.",
                  datasetId: data.dataset_id,
                  version: data.version,
                  decision: "REJECT",
                  riskScore: 100,
                }
              : j
          )
        );
        await loadDatasets();
        return;
      }

      updateJobStep(job.id, "crypto", "completed");

      const remaining = ["semantic", "behavioral", "inconsistency", "pii", "correlation", "risk", "policy"];
      for (const stepId of remaining) {
        updateJobStep(job.id, stepId, "running");
        await new Promise((r) => setTimeout(r, 160));
        updateJobStep(job.id, stepId, "completed");
      }

      setJobs((prev) =>
        prev.map((j) =>
          j.id === job.id
            ? {
                ...j,
                status: "completed",
                datasetId: data.dataset_id,
                version: data.version,
                decision: data.decision || "APPROVE",
                riskScore: data.risk_score ?? 0,
                riskLevel: data.risk_level || "LOW",
                findingsCount: data.findings_count ?? 0,
              }
            : j
        )
      );

      await loadDatasets();
    } catch (err: any) {
      updateJobStep(job.id, "crypto", "failed");
      setJobs((prev) =>
        prev.map((j) =>
          j.id === job.id
            ? { ...j, status: "failed", blockedReason: err.message || "Pipeline execution failed" }
            : j
        )
      );
    }
  }

  async function handleRunAll() {
    if (jobs.length === 0 || isRunning) return;
    setIsRunning(true);
    const pendingJobs = jobs.filter((j) => j.status === "idle" || j.status === "failed");
    await Promise.all(pendingJobs.map((job) => executeJob(job)));
    setIsRunning(false);
  }

  // --- HITL Handlers ---
  async function toggleExpandDataset(ds: DatasetItem) {
    const key = ds.dataset_id;
    const isCurrentlyExpanded = !!expandedDatasets[key];
    const nextState = !isCurrentlyExpanded;

    setExpandedDatasets((prev) => ({ ...prev, [key]: nextState }));

    if (nextState) {
      if (!agentFilters[key]) {
        setAgentFilters((prev) => ({ ...prev, [key]: [...ALL_AGENTS] }));
      }
      const cacheKey = `${ds.dataset_id}_v${ds.version}`;
      if (!contentCache[cacheKey]) {
        await loadDatasetContent(ds.dataset_id, ds.version);
      }
    }
  }

  async function loadDatasetContent(dsId: string, ver: number) {
    const cacheKey = `${dsId}_v${ver}`;
    setLoadingContent((prev) => ({ ...prev, [dsId]: true }));
    try {
      const [cRes, fRes] = await Promise.all([
        fetch(`${API_BASE_URL}/api/datasets/${dsId}/versions/${ver}/content?page=1&page_size=100`),
        fetch(`${API_BASE_URL}/api/datasets/${dsId}/versions/${ver}/findings`),
      ]);

      if (cRes.ok) {
        const cData = await cRes.json();
        setContentCache((prev) => ({ ...prev, [cacheKey]: cData }));
      }
      if (fRes.ok) {
        const fData = await fRes.json();
        setFindingsCache((prev) => ({ ...prev, [cacheKey]: fData }));
      }
    } catch {
      // ignore
    } finally {
      setLoadingContent((prev) => ({ ...prev, [dsId]: false }));
    }
  }

  function toggleAgentFilter(dsId: string, agent: string) {
    setAgentFilters((prev) => {
      const current = prev[dsId] || [...ALL_AGENTS];
      if (current.includes(agent)) {
        return { ...prev, [dsId]: current.filter((a) => a !== agent) };
      } else {
        return { ...prev, [dsId]: [...current, agent] };
      }
    });
  }

  function selectAllAgents(dsId: string) {
    setAgentFilters((prev) => ({ ...prev, [dsId]: [...ALL_AGENTS] }));
  }

  function clearAllAgents(dsId: string) {
    setAgentFilters((prev) => ({ ...prev, [dsId]: [] }));
  }

  // Returns ALL findings for this cell matching active agent filters
  function getCellFindings(findings: any[], rec: any, col: string, activeAgents: string[]): any[] {
    if (!findings || findings.length === 0) return [];
    const recId = String(rec.record_id);

    return findings.filter((f: any) => {
      if (String(f.record_id) !== recId) return false;
      const agentLower = (f.agent || "").toLowerCase();
      if (!activeAgents.includes(agentLower)) return false;

      const fCol = f.location?.field || f.field;
      if (fCol === col) return true;
      if (
        (fCol === "text" || !fCol) &&
        (col.toLowerCase().includes("text") ||
          col.toLowerCase().includes("content") ||
          col.toLowerCase().includes("instruction") ||
          col.toLowerCase().includes("query") ||
          col.toLowerCase().includes("prompt") ||
          col.toLowerCase().includes("response") ||
          col.toLowerCase().includes("answer"))
      ) {
        return true;
      }
      return false;
    });
  }

  function getAgentBadgeColor(agent: string) {
    switch (agent?.toLowerCase()) {
      case "semantic":
        return { bg: "#fef2f2", text: "#991b1b", border: "#fecaca", dot: "#ef4444" };
      case "behavioral":
        return { bg: "#fff7ed", text: "#9a3412", border: "#fed7aa", dot: "#f97316" };
      case "inconsistency":
        return { bg: "#fefce8", text: "#854d0e", border: "#fef08a", dot: "#eab308" };
      case "pii":
        return { bg: "#eff6ff", text: "#1e40af", border: "#bfdbfe", dot: "#3b82f6" };
      default:
        return { bg: "#f3f4f6", text: "#374151", border: "#e5e7eb", dot: "#6b7280" };
    }
  }

  // Decision actions for quarantined dataset
  async function submitDecision(datasetId: string, version: number, action: "APPROVE" | "REJECT") {
    setSubmittingAction((prev) => ({ ...prev, [datasetId]: true }));
    setActionNotice((prev) => ({ ...prev, [datasetId]: { type: "success", text: `Submitting ${action}...` } }));

    try {
      const res = await fetch(
        `${API_BASE_URL}/api/datasets/${datasetId}/versions/${version}/review`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            action,
            notes: `Decision marked as ${action} by security auditor in HITL view`,
            modified_records: [],
            removed_record_ids: [],
          }),
        }
      );

      if (!res.ok) throw new Error(`Failed to submit ${action}`);
      setActionNotice((prev) => ({
        ...prev,
        [datasetId]: { type: "success", text: `Dataset marked as ${action} successfully.` },
      }));
      await loadDatasets();
    } catch (err: any) {
      setActionNotice((prev) => ({
        ...prev,
        [datasetId]: { type: "error", text: err.message || `Action failed` },
      }));
    } finally {
      setSubmittingAction((prev) => ({ ...prev, [datasetId]: false }));
    }
  }

  // Row removal toggle
  function toggleRowRemoval(dsId: string, recId: string) {
    const sId = String(recId);
    setRemovedRecords((prev) => {
      const list = prev[dsId] || [];
      if (list.includes(sId)) {
        return { ...prev, [dsId]: list.filter((id) => id !== sId) };
      } else {
        return { ...prev, [dsId]: [...list, sId] };
      }
    });
  }

  // Save cell edit into staging
  function saveCellEdit() {
    if (!editModalInfo) return;
    const { datasetId, recordId, field, value } = editModalInfo;

    setModifiedRecords((prev) => {
      const dsMods = prev[datasetId] || {};
      const recMods = dsMods[recordId] || {};
      return {
        ...prev,
        [datasetId]: {
          ...dsMods,
          [recordId]: {
            ...recMods,
            [field]: value,
          },
        },
      };
    });

    setEditModalInfo(null);
  }

  // Submit modifications and rerun pipeline to generate vN+1
  async function submitRemediation(dsId: string, currVersion: number) {
    setSubmittingAction((prev) => ({ ...prev, [dsId]: true }));
    setActionNotice((prev) => ({ ...prev, [dsId]: { type: "success", text: "Remediating and generating next version..." } }));

    const dsMods = modifiedRecords[dsId] || {};
    const modsList = Object.entries(dsMods).map(([rId, fields]) => ({
      record_id: rId,
      data: fields,
    }));
    const dsRemovals = removedRecords[dsId] || [];

    try {
      const res = await fetch(
        `${API_BASE_URL}/api/datasets/${dsId}/versions/${currVersion}/review`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            action: "MODIFY",
            notes: "Remediated adversarial findings and generated next version",
            modified_records: modsList,
            removed_record_ids: dsRemovals,
          }),
        }
      );

      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Remediation rerun failed");

      setModifiedRecords((prev) => ({ ...prev, [dsId]: {} }));
      setRemovedRecords((prev) => ({ ...prev, [dsId]: [] }));

      const newVer = data.new_version || currVersion + 1;
      setActionNotice((prev) => ({
        ...prev,
        [dsId]: {
          type: "success",
          text: `Version ${newVer} generated. Re-evaluated decision: ${data.pipeline_result?.decision || "APPROVED"}, Risk: ${data.pipeline_result?.risk_score ?? 0}/100.`,
        },
      }));

      await loadDatasets();
      await loadDatasetContent(dsId, newVer);
    } catch (err: any) {
      setActionNotice((prev) => ({
        ...prev,
        [dsId]: { type: "error", text: err.message || "Remediation failed" },
      }));
    } finally {
      setSubmittingAction((prev) => ({ ...prev, [dsId]: false }));
    }
  }

  // Filter datasets based on active status filter
  const filteredDatasets = datasets.filter((ds) => {
    const state = getDatasetHITLState(ds);
    if (!state) return false;
    if (hitlFilter === "ALL") return true;
    return state === hitlFilter;
  });

  const quarantinedCount = datasets.filter((d) => getDatasetHITLState(d) === "QUARANTINED").length;
  const rejectedCount = datasets.filter((d) => getDatasetHITLState(d) === "REJECTED").length;
  const approvedCount = datasets.filter((d) => getDatasetHITLState(d) === "APPROVED").length;

  return (
    <div style={{ padding: "40px 48px", maxWidth: "1360px", margin: "0 auto" }}>
      {/* ============================================================ */}
      {/* PIPELINE SECTION                                             */}
      {/* ============================================================ */}
      <div style={{ marginBottom: "28px" }}>
        <h1 style={{ fontSize: "24px", fontWeight: 700, color: "#111827" }}>
          Pipeline
        </h1>
      </div>

      {/* Upload Dropzone */}
      <div style={{
        background: "#ffffff",
        border: "1px dashed #d1d5db",
        borderRadius: "8px",
        padding: "36px 24px",
        textAlign: "center",
        marginBottom: "32px",
      }}>
        <div style={{ fontSize: "15px", fontWeight: 600, color: "#111827", marginBottom: "16px" }}>
          Select or drop dataset files to run pipeline
        </div>

        <div>
          <input
            type="file"
            multiple
            onChange={handleFileSelection}
            disabled={isRunning}
            style={{ fontSize: "13px", color: "#4b5563" }}
          />
        </div>

        {jobs.length > 0 && (
          <div style={{ marginTop: "20px" }}>
            <button
              onClick={handleRunAll}
              disabled={isRunning || jobs.every((j) => j.status === "completed")}
              style={{
                background: isRunning ? "#9ca3af" : "#111827",
                color: "#ffffff",
                border: "none",
                padding: "9px 24px",
                borderRadius: "6px",
                fontSize: "14px",
                fontWeight: 600,
              }}
            >
              {isRunning ? "Executing Pipeline..." : "Execute Pipeline"}
            </button>
          </div>
        )}
      </div>

      {/* Individual File Pipeline Cards */}
      {jobs.length > 0 && (
        <div style={{ display: "flex", flexDirection: "column", gap: "24px", marginBottom: "48px" }}>
          {jobs.map((job) => (
            <div
              key={job.id}
              style={{
                background: "#ffffff",
                border: "1px solid #e5e7eb",
                borderRadius: "8px",
                padding: "24px",
              }}
            >
              {/* Job Header */}
              <div style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                marginBottom: "20px",
                borderBottom: "1px solid #f3f4f6",
                paddingBottom: "14px",
              }}>
                <div>
                  <span style={{ fontSize: "15px", fontWeight: 700, color: "#111827", marginRight: "12px" }}>
                    {job.filename}
                  </span>
                  <span style={{ fontSize: "12px", color: "#6b7280" }}>
                    {formatBytes(job.fileSize)}
                  </span>
                </div>

                <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                  <span style={{
                    padding: "3px 10px",
                    borderRadius: "4px",
                    fontSize: "12px",
                    fontWeight: 600,
                    background:
                      job.status === "completed"
                        ? "#ecfdf5"
                        : job.status === "blocked" || job.status === "failed"
                        ? "#fef2f2"
                        : job.status === "running"
                        ? "#eff6ff"
                        : "#f3f4f6",
                    color:
                      job.status === "completed"
                        ? "#065f46"
                        : job.status === "blocked" || job.status === "failed"
                        ? "#991b1b"
                        : job.status === "running"
                        ? "#1e40af"
                        : "#374151",
                  }}>
                    {job.status === "completed"
                      ? `Completed: ${job.decision}`
                      : job.status === "blocked"
                      ? "Blocked: Cryptographic Verification Failed"
                      : job.status === "running"
                      ? "Processing"
                      : "Pending"}
                  </span>
                </div>
              </div>

              {/* Blocked Alert */}
              {job.status === "blocked" && (
                <div style={{
                  background: "#fef2f2",
                  border: "1px solid #fee2e2",
                  borderRadius: "6px",
                  padding: "12px 16px",
                  marginBottom: "20px",
                  color: "#991b1b",
                  fontSize: "13px",
                }}>
                  <strong>Access Blocked:</strong> {job.blockedReason}
                </div>
              )}

              {/* 9 Vertical Progress Bars in Order */}
              <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                {job.steps.map((step) => {
                  const isRunningStep = step.status === "running";
                  const isCompletedStep = step.status === "completed";
                  const isFailedStep = step.status === "failed";

                  return (
                    <div key={step.id}>
                      <div style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        marginBottom: "4px",
                        fontSize: "12px",
                      }}>
                        <span style={{ fontWeight: 600, color: "#374151" }}>
                          {step.label}
                        </span>
                        <span style={{
                          color: isCompletedStep
                            ? "#059669"
                            : isFailedStep
                            ? "#dc2626"
                            : isRunningStep
                            ? "#2563eb"
                            : "#9ca3af",
                          fontWeight: 500,
                        }}>
                          {isCompletedStep
                            ? "Complete"
                            : isFailedStep
                            ? "Failed"
                            : isRunningStep
                            ? "Running"
                            : "Waiting"}
                        </span>
                      </div>

                      <div style={{
                        height: "7px",
                        width: "100%",
                        background: "#f3f4f6",
                        borderRadius: "4px",
                        overflow: "hidden",
                      }}>
                        <div
                          className={isRunningStep ? "running-progress" : ""}
                          style={{
                            height: "100%",
                            width: isCompletedStep || isFailedStep ? "100%" : isRunningStep ? "70%" : "0%",
                            background: isCompletedStep
                              ? "#10b981"
                              : isFailedStep
                              ? "#ef4444"
                              : isRunningStep
                              ? "#3b82f6"
                              : "transparent",
                            transition: "width 0.4s ease",
                            borderRadius: "4px",
                          }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Results summary when completed */}
              {job.status === "completed" && (
                <div style={{
                  marginTop: "18px",
                  paddingTop: "14px",
                  borderTop: "1px solid #f3f4f6",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  fontSize: "12px",
                  color: "#4b5563",
                }}>
                  <div>
                    Risk Score:{" "}
                    <strong style={{
                      color:
                        (job.riskScore ?? 0) >= 65
                          ? "#dc2626"
                          : (job.riskScore ?? 0) >= 20
                          ? "#ea580c"
                          : "#16a34a",
                    }}>
                      {formatRiskScore(job.status, job.riskScore ?? null)}
                    </strong>{" "}
                    ({job.riskLevel}) &bull; Findings: <strong>{job.findingsCount ?? 0}</strong>
                  </div>
                  <div>
                    OPA Policy:{" "}
                    <strong style={{
                      color:
                        job.decision === "APPROVE"
                          ? "#059669"
                          : job.decision === "REJECT"
                          ? "#dc2626"
                          : "#ea580c",
                    }}>
                      {job.decision}
                    </strong>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* ============================================================ */}
      {/* HUMAN IN THE LOOP (HITL) REVIEW SECTION                     */}
      {/* ============================================================ */}
      <div style={{
        marginTop: "48px",
        paddingTop: "36px",
        borderTop: "2px solid #e5e7eb",
      }}>
        <div style={{ marginBottom: "20px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div>
            <h2 style={{ fontSize: "22px", fontWeight: 700, color: "#111827" }}>
              Human in the Loop Review
            </h2>
          </div>

          <button
            onClick={loadDatasets}
            disabled={hitlLoading}
            style={{
              background: "#ffffff",
              border: "1px solid #d1d5db",
              padding: "7px 14px",
              borderRadius: "6px",
              fontSize: "13px",
              fontWeight: 500,
              color: "#374151",
            }}
          >
            {hitlLoading ? "Refreshing..." : "Refresh List"}
          </button>
        </div>

        {/* Status Filter Tabs (Quarantined, Rejected, Approved) */}
        <div style={{ display: "flex", gap: "8px", marginBottom: "24px" }}>
          {[
            { id: "ALL", label: `All (${datasets.length})` },
            { id: "QUARANTINED", label: `Quarantined (${quarantinedCount})` },
            { id: "REJECTED", label: `Rejected (${rejectedCount})` },
            { id: "APPROVED", label: `Approved (${approvedCount})` },
          ].map((tab) => {
            const isSelected = hitlFilter === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setHitlFilter(tab.id as HITLFilterType)}
                style={{
                  padding: "6px 14px",
                  borderRadius: "6px",
                  fontSize: "13px",
                  fontWeight: isSelected ? 600 : 500,
                  border: isSelected ? "1px solid #111827" : "1px solid #d1d5db",
                  background: isSelected ? "#111827" : "#ffffff",
                  color: isSelected ? "#ffffff" : "#4b5563",
                  cursor: "pointer",
                  transition: "all 0.15s ease",
                }}
              >
                {tab.label}
              </button>
            );
          })}
        </div>

        {hitlError && (
          <div style={{
            padding: "14px 18px",
            background: "#fef2f2",
            border: "1px solid #fee2e2",
            borderRadius: "6px",
            color: "#991b1b",
            fontSize: "13px",
            marginBottom: "20px",
          }}>
            {hitlError}
          </div>
        )}

        {/* Datasets Stack (Prioritized: Quarantined first, then Rejected, then Approved) */}
        {filteredDatasets.length === 0 && !hitlLoading ? (
          <div style={{
            padding: "48px 24px",
            textAlign: "center",
            border: "1px dashed #d1d5db",
            borderRadius: "8px",
            background: "#ffffff",
          }}>
            <div style={{ fontSize: "14px", fontWeight: 600, color: "#374151", marginBottom: "4px" }}>
              No datasets matching current filter
            </div>
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
            {filteredDatasets.map((ds) => {
              const isExpanded = !!expandedDatasets[ds.dataset_id];
              const dsState = getDatasetHITLState(ds);
              const isApproved = dsState === "APPROVED" || (ds.status || "").toUpperCase() === "APPROVED";
              const isQuarantined = dsState === "QUARANTINED" && !isApproved;
              const activeAgents = agentFilters[ds.dataset_id] || [...ALL_AGENTS];
              const cacheKey = `${ds.dataset_id}_v${ds.version}`;
              const content = contentCache[cacheKey];
              const findings = findingsCache[cacheKey]?.findings || [];
              const isBusy = !!submittingAction[ds.dataset_id];
              const notice = actionNotice[ds.dataset_id];
              const dsModCount = Object.keys(modifiedRecords[ds.dataset_id] || {}).length;
              const dsRemCount = (removedRecords[ds.dataset_id] || []).length;

              return (
                <div
                  key={`${ds.dataset_id}-v${ds.version}`}
                  style={{
                    background: "#ffffff",
                    border: "1px solid #e5e7eb",
                    borderRadius: "10px",
                    overflow: "hidden",
                    boxShadow: "0 1px 3px rgba(0, 0, 0, 0.03)",
                  }}
                >
                  {/* Dataset Summary & Metadata Card Header */}
                  <div style={{
                    padding: "20px 24px",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    flexWrap: "wrap",
                    gap: "16px",
                    background: isExpanded ? "#fcfcfd" : "#ffffff",
                    borderBottom: isExpanded ? "1px solid #e5e7eb" : "none",
                  }}>
                    {/* Left details */}
                    <div style={{ display: "flex", alignItems: "center", gap: "20px", flexWrap: "wrap" }}>
                      <div>
                        <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px" }}>
                          <span style={{ fontSize: "16px", fontWeight: 700, color: "#111827" }}>
                            {ds.filename}
                          </span>
                          <span style={{
                            fontSize: "11px",
                            fontWeight: 700,
                            padding: "2px 6px",
                            borderRadius: "4px",
                            background: "#f3f4f6",
                            color: "#374151",
                          }}>
                            v{ds.version}
                          </span>
                          <span style={{
                            fontSize: "11px",
                            fontWeight: 600,
                            padding: "2px 6px",
                            borderRadius: "4px",
                            background: "#eff6ff",
                            color: "#1e40af",
                            textTransform: "uppercase",
                          }}>
                            {ds.file_type || "CSV"}
                          </span>
                        </div>
                        <div style={{ fontSize: "12px", color: "#6b7280", fontFamily: "monospace" }}>
                          ID: {ds.dataset_id} &bull; Size: {formatBytes(ds.file_size)} &bull; Records: {ds.record_count ?? "—"}
                        </div>
                      </div>

                      {/* Detection results tags */}
                      <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                        <div style={{
                          padding: "6px 12px",
                          borderRadius: "6px",
                          background:
                            ds.status === "BLOCKED"
                              ? "#f3f4f6"
                              : (ds.risk_score ?? 0) >= 65
                              ? "#fef2f2"
                              : (ds.risk_score ?? 0) >= 20
                              ? "#fffbeb"
                              : "#ecfdf5",
                          border: `1px solid ${
                            ds.status === "BLOCKED"
                              ? "#e5e7eb"
                              : (ds.risk_score ?? 0) >= 65
                              ? "#fecaca"
                              : (ds.risk_score ?? 0) >= 20
                              ? "#fde68a"
                              : "#a7f3d0"
                          }`,
                          fontSize: "12px",
                        }}>
                          <span style={{ color: "#6b7280", marginRight: "4px" }}>Risk Score:</span>
                          <strong style={{
                            color:
                              ds.status === "BLOCKED"
                                ? "#6b7280"
                                : (ds.risk_score ?? 0) >= 65
                                ? "#dc2626"
                                : (ds.risk_score ?? 0) >= 20
                                ? "#d97706"
                                : "#059669",
                          }}>
                            {formatRiskScore(ds.status, ds.risk_score)}
                          </strong>
                          {ds.status !== "BLOCKED" && (
                            <span style={{ color: "#6b7280", marginLeft: "4px" }}>({ds.risk_level || "LOW"})</span>
                          )}
                        </div>

                        <div style={{
                          padding: "6px 12px",
                          borderRadius: "6px",
                          background:
                            dsState === "APPROVED"
                              ? "#ecfdf5"
                              : dsState === "REJECTED"
                              ? "#fef2f2"
                              : "#fffbeb",
                          border: `1px solid ${
                            dsState === "APPROVED"
                              ? "#a7f3d0"
                              : dsState === "REJECTED"
                              ? "#fecaca"
                              : "#fde68a"
                          }`,
                          fontSize: "12px",
                        }}>
                          <span style={{ color: "#6b7280", marginRight: "4px" }}>Policy:</span>
                          <strong style={{
                            color:
                              dsState === "APPROVED"
                                ? "#059669"
                                : dsState === "REJECTED"
                                ? "#dc2626"
                                : "#d97706",
                          }}>
                            {dsState}
                          </strong>
                        </div>

                        <div style={{ fontSize: "12px", color: "#6b7280" }}>
                          Findings: <strong style={{ color: "#111827" }}>{ds.findings_count}</strong>
                        </div>
                      </div>
                    </div>

                    {/* Action buttons: Approve / Reject / Refresh ONLY for Quarantined datasets */}
                    <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                      {isQuarantined && (
                        <>
                          <button
                            onClick={() => submitDecision(ds.dataset_id, ds.version, "APPROVE")}
                            disabled={isBusy}
                            style={{
                              background: "#059669",
                              color: "#ffffff",
                              border: "none",
                              padding: "7px 14px",
                              borderRadius: "6px",
                              fontSize: "13px",
                              fontWeight: 500,
                            }}
                          >
                            Approve
                          </button>

                          <button
                            onClick={() => submitDecision(ds.dataset_id, ds.version, "REJECT")}
                            disabled={isBusy}
                            style={{
                              background: "#dc2626",
                              color: "#ffffff",
                              border: "none",
                              padding: "7px 14px",
                              borderRadius: "6px",
                              fontSize: "13px",
                              fontWeight: 500,
                            }}
                          >
                            Reject
                          </button>

                          <button
                            onClick={() => loadDatasetContent(ds.dataset_id, ds.version)}
                            disabled={isBusy || loadingContent[ds.dataset_id]}
                            style={{
                              background: "#ffffff",
                              color: "#374151",
                              border: "1px solid #d1d5db",
                              padding: "7px 12px",
                              borderRadius: "6px",
                              fontSize: "13px",
                              fontWeight: 500,
                            }}
                          >
                            {loadingContent[ds.dataset_id] ? "..." : "Refresh"}
                          </button>
                        </>
                      )}

                      <button
                        onClick={() => toggleExpandDataset(ds)}
                        style={{
                          background: isExpanded ? "#111827" : "#ffffff",
                          color: isExpanded ? "#ffffff" : "#374151",
                          border: "1px solid #d1d5db",
                          padding: "7px 14px",
                          borderRadius: "6px",
                          fontSize: "13px",
                          fontWeight: 500,
                        }}
                      >
                        {isExpanded ? "Collapse Viewer" : "Inspect Records"}
                      </button>
                    </div>
                  </div>

                  {/* Feedback Notice */}
                  {notice && (
                    <div style={{
                      padding: "10px 24px",
                      background: notice.type === "success" ? "#ecfdf5" : "#fef2f2",
                      borderBottom: "1px solid #e5e7eb",
                      fontSize: "12px",
                      color: notice.type === "success" ? "#065f46" : "#991b1b",
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                    }}>
                      <span>{notice.text}</span>
                      <button
                        onClick={() => setActionNotice((prev) => ({ ...prev, [ds.dataset_id]: null as any }))}
                        style={{ background: "none", border: "none", color: "#6b7280", fontSize: "12px" }}
                      >
                        Dismiss
                      </button>
                    </div>
                  )}

                  {/* Expandable Dataset Records Viewer & Agent Flag Filters */}
                  {isExpanded && (
                    <div style={{ padding: "24px" }}>
                      {/* Controls Bar: Multi-Select Agent Flag Filter */}
                      <div style={{
                        background: "#f9fafb",
                        border: "1px solid #e5e7eb",
                        borderRadius: "8px",
                        padding: "14px 18px",
                        marginBottom: "20px",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                        flexWrap: "wrap",
                        gap: "12px",
                      }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
                          <span style={{ fontSize: "12px", fontWeight: 700, color: "#374151", textTransform: "uppercase", letterSpacing: "0.03em" }}>
                            Filter Agent Flags:
                          </span>

                          {ALL_AGENTS.map((agent) => {
                            const isSelected = activeAgents.includes(agent);
                            const badge = getAgentBadgeColor(agent);

                            return (
                              <button
                                key={agent}
                                onClick={() => toggleAgentFilter(ds.dataset_id, agent)}
                                style={{
                                  padding: "4px 10px",
                                  borderRadius: "6px",
                                  fontSize: "12px",
                                  fontWeight: 600,
                                  cursor: "pointer",
                                  border: isSelected ? `1px solid ${badge.border}` : "1px solid #d1d5db",
                                  background: isSelected ? badge.bg : "#ffffff",
                                  color: isSelected ? badge.text : "#6b7280",
                                  display: "inline-flex",
                                  alignItems: "center",
                                  gap: "6px",
                                  transition: "all 0.15s ease",
                                }}
                              >
                                <span style={{
                                  width: 7,
                                  height: 7,
                                  borderRadius: "50%",
                                  background: isSelected ? badge.dot : "#d1d5db",
                                }} />
                                <span style={{ textTransform: "capitalize" }}>{agent}</span>
                              </button>
                            );
                          })}

                          <div style={{ display: "flex", gap: "6px", marginLeft: "6px" }}>
                            <button
                              onClick={() => selectAllAgents(ds.dataset_id)}
                              style={{ background: "none", border: "none", fontSize: "11px", color: "#2563eb", textDecoration: "underline" }}
                            >
                              Select All
                            </button>
                            <span style={{ color: "#d1d5db", fontSize: "11px" }}>|</span>
                            <button
                              onClick={() => clearAllAgents(ds.dataset_id)}
                              style={{ background: "none", border: "none", fontSize: "11px", color: "#6b7280", textDecoration: "underline" }}
                            >
                              Clear All
                            </button>
                          </div>
                        </div>

                        {/* Staged Modifications & Rerun Button (primarily for quarantined) */}
                        {!isApproved && (dsModCount > 0 || dsRemCount > 0) && (
                          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                            <span style={{ fontSize: "12px", color: "#b45309", fontWeight: 500 }}>
                              Staged: {dsModCount} edit(s), {dsRemCount} removal(s)
                            </span>
                            <button
                              onClick={() => submitRemediation(ds.dataset_id, ds.version)}
                              disabled={isBusy}
                              style={{
                                background: "#2563eb",
                                color: "#ffffff",
                                border: "none",
                                padding: "6px 14px",
                                borderRadius: "6px",
                                fontSize: "12px",
                                fontWeight: 600,
                              }}
                            >
                              {isBusy ? "Processing v" + (ds.version + 1) + "..." : "Apply Changes & Rerun Pipeline"}
                            </button>
                          </div>
                        )}
                      </div>

                      {/* Main Data Table & Threat Details Panel */}
                      <div style={{ display: "flex", gap: "20px", alignItems: "flex-start" }}>
                        {/* Table */}
                        <div style={{
                          flex: 1,
                          minWidth: 0,
                          border: "1px solid #e5e7eb",
                          borderRadius: "8px",
                          overflow: "hidden",
                          background: "#ffffff",
                        }}>
                          {loadingContent[ds.dataset_id] ? (
                            <div style={{ padding: "32px", textAlign: "center", color: "#6b7280", fontSize: "13px" }}>
                              Loading dataset records...
                            </div>
                          ) : !content?.records?.length ? (
                            <div style={{ padding: "32px", textAlign: "center", color: "#6b7280", fontSize: "13px" }}>
                              No records found for this dataset version.
                            </div>
                          ) : (
                            <div style={{ overflowX: "auto", maxHeight: "550px" }}>
                              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "13px" }}>
                                <thead>
                                  <tr style={{ background: "#f9fafb", borderBottom: "1px solid #e5e7eb", textAlign: "left" }}>
                                    <th style={{ padding: "10px 14px", width: "60px", color: "#6b7280" }}>Row</th>
                                    {content.columns.map((col: string) => (
                                      <th key={col} style={{ padding: "10px 14px", color: "#374151", fontWeight: 600 }}>{col}</th>
                                    ))}
                                    {!isApproved && (
                                      <th style={{ padding: "10px 14px", width: "80px", textAlign: "right" }}>Actions</th>
                                    )}
                                  </tr>
                                </thead>
                                <tbody>
                                  {content.records.map((rec: any) => {
                                    const rId = String(rec.record_id);
                                    const isRowRemoved = (removedRecords[ds.dataset_id] || []).includes(rId);

                                    return (
                                      <tr
                                        key={rId}
                                        style={{
                                          borderBottom: "1px solid #f3f4f6",
                                          background: isRowRemoved ? "#fef2f2" : "#ffffff",
                                          opacity: isRowRemoved ? 0.45 : 1,
                                        }}
                                      >
                                        <td style={{ padding: "10px 14px", color: "#9ca3af", fontFamily: "monospace", fontSize: "12px" }}>
                                          #{rec.location?.line_number || rec.location?.row || rId}
                                        </td>

                                        {content.columns.map((col: string) => {
                                          const originalVal = rec.data[col] !== undefined ? String(rec.data[col]) : "";
                                          const editedVal = modifiedRecords[ds.dataset_id]?.[rId]?.[col];
                                          const displayVal = editedVal !== undefined ? editedVal : originalVal;
                                          const cellFindings = getCellFindings(findings, rec, col, activeAgents);
                                          const hasFlags = cellFindings.length > 0;
                                          const primaryFinding = cellFindings[0];
                                          const badge = primaryFinding ? getAgentBadgeColor(primaryFinding.agent) : null;

                                          return (
                                            <td
                                              key={col}
                                              onClick={() => {
                                                if (hasFlags) setSelectedFindings(cellFindings);
                                              }}
                                              style={{
                                                padding: "8px 12px",
                                                maxWidth: "380px",
                                                wordBreak: "break-word",
                                                cursor: hasFlags ? "pointer" : "default",
                                                background: hasFlags
                                                  ? cellFindings.length > 1
                                                    ? "#fff1f2"
                                                    : badge?.bg
                                                  : editedVal !== undefined
                                                  ? "#f0fdf4"
                                                  : "transparent",
                                                color: hasFlags
                                                  ? cellFindings.length > 1
                                                    ? "#991b1b"
                                                    : badge?.text
                                                  : "#111827",
                                                borderLeft: hasFlags
                                                  ? `3px solid ${cellFindings.length > 1 ? "#ef4444" : badge?.border}`
                                                  : "none",
                                              }}
                                            >
                                              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "8px" }}>
                                                <span style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                                                  {displayVal}
                                                  {cellFindings.length > 1 && (
                                                    <span style={{
                                                      fontSize: "10px",
                                                      fontWeight: 700,
                                                      padding: "1px 5px",
                                                      borderRadius: "3px",
                                                      background: "#fee2e2",
                                                      color: "#991b1b",
                                                      border: "1px solid #fecaca",
                                                      whiteSpace: "nowrap",
                                                    }}>
                                                      {cellFindings.length} agents
                                                    </span>
                                                  )}
                                                </span>
                                                {!isApproved && (
                                                  <button
                                                    onClick={(e) => {
                                                      e.stopPropagation();
                                                      setEditModalInfo({
                                                        datasetId: ds.dataset_id,
                                                        version: ds.version,
                                                        recordId: rId,
                                                        field: col,
                                                        value: displayVal,
                                                      });
                                                    }}
                                                    style={{
                                                      border: "1px solid #d1d5db",
                                                      background: "#ffffff",
                                                      color: "#4b5563",
                                                      padding: "2px 6px",
                                                      borderRadius: "4px",
                                                      fontSize: "11px",
                                                      cursor: "pointer",
                                                    }}
                                                  >
                                                    Edit
                                                  </button>
                                                )}
                                              </div>
                                            </td>
                                          );
                                        })}

                                        {!isApproved && (
                                          <td style={{ padding: "10px 14px", textAlign: "right" }}>
                                            <button
                                              onClick={() => toggleRowRemoval(ds.dataset_id, rId)}
                                              style={{
                                                border: isRowRemoved ? "1px solid #111827" : "1px solid #ef4444",
                                                background: isRowRemoved ? "#111827" : "#ffffff",
                                                color: isRowRemoved ? "#ffffff" : "#dc2626",
                                                padding: "3px 8px",
                                                borderRadius: "4px",
                                                fontSize: "11px",
                                              }}
                                            >
                                              {isRowRemoved ? "Undo" : "Remove"}
                                            </button>
                                          </td>
                                        )}
                                      </tr>
                                    );
                                  })}
                                </tbody>
                              </table>
                            </div>
                          )}
                        </div>

                        {/* Threat Details Drawer - Scrollable for Multiple Flagged Agents */}
                        {selectedFindings && selectedFindings.length > 0 && (
                          <div style={{
                            width: "360px",
                            background: "#ffffff",
                            border: "1px solid #e5e7eb",
                            borderRadius: "8px",
                            padding: "18px",
                            position: "sticky",
                            top: "24px",
                            boxShadow: "0 2px 4px rgba(0, 0, 0, 0.04)",
                          }}>
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "14px", paddingBottom: "10px", borderBottom: "1px solid #f3f4f6" }}>
                              <div style={{ fontSize: "14px", fontWeight: 700, color: "#111827" }}>
                                Threat Details ({selectedFindings.length} {selectedFindings.length > 1 ? "Detections" : "Detection"})
                              </div>
                              <button
                                onClick={() => setSelectedFindings(null)}
                                style={{ background: "none", border: "none", fontSize: "14px", color: "#9ca3af", cursor: "pointer" }}
                              >
                                x
                              </button>
                            </div>

                            <div style={{
                              maxHeight: "540px",
                              overflowY: "auto",
                              display: "flex",
                              flexDirection: "column",
                              gap: "16px",
                              paddingRight: "4px",
                            }}>
                              {selectedFindings.map((finding: any, idx: number) => {
                                const badge = getAgentBadgeColor(finding.agent);

                                return (
                                  <div
                                    key={`${finding.agent}-${finding.finding_id || idx}`}
                                    style={{
                                      padding: "12px",
                                      borderRadius: "6px",
                                      background: "#fafafa",
                                      border: "1px solid #e5e7eb",
                                      display: "flex",
                                      flexDirection: "column",
                                      gap: "10px",
                                      fontSize: "13px",
                                    }}
                                  >
                                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                                      <span style={{
                                        fontSize: "11px",
                                        fontWeight: 700,
                                        textTransform: "uppercase",
                                        color: badge.text,
                                        background: badge.bg,
                                        padding: "2px 6px",
                                        borderRadius: "4px",
                                        border: `1px solid ${badge.border}`,
                                      }}>
                                        {finding.agent} Intelligence
                                      </span>
                                      <span style={{
                                        fontSize: "11px",
                                        fontWeight: 600,
                                        padding: "2px 6px",
                                        borderRadius: "4px",
                                        background: "#f3f4f6",
                                        color: "#374151",
                                      }}>
                                        {finding.severity}
                                      </span>
                                    </div>

                                    <div>
                                      <span style={{ fontSize: "11px", color: "#6b7280", fontWeight: 600 }}>CATEGORY</span>
                                      <div style={{ fontWeight: 600, color: "#111827" }}>
                                        {finding.category}
                                      </div>
                                    </div>

                                    <div>
                                      <span style={{ fontSize: "11px", color: "#6b7280", fontWeight: 600 }}>EVIDENCE EXCERPT</span>
                                      <div style={{
                                        background: "#ffffff",
                                        padding: "8px",
                                        borderRadius: "5px",
                                        border: "1px solid #e5e7eb",
                                        fontFamily: "monospace",
                                        fontSize: "12px",
                                        color: "#1f2937",
                                        maxHeight: "100px",
                                        overflowY: "auto",
                                        wordBreak: "break-word",
                                      }}>
                                        {finding.evidence}
                                      </div>
                                    </div>

                                    <div>
                                      <span style={{ fontSize: "11px", color: "#6b7280", fontWeight: 600 }}>SECURITY JUSTIFICATION</span>
                                      <div style={{ color: "#4b5563", fontSize: "12px" }}>
                                        {finding.reason}
                                      </div>
                                    </div>

                                    <div>
                                      <span style={{ fontSize: "11px", color: "#6b7280", fontWeight: 600 }}>ANALYZER</span>
                                      <div style={{ color: "#6b7280", fontSize: "12px" }}>
                                        {finding.model_or_provider || "Adversarial Threat Intelligence Engine"}
                                      </div>
                                    </div>
                                  </div>
                                );
                              })}
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Inline Cell Edit Modal */}
      {editModalInfo && (
        <div style={{
          position: "fixed",
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: "rgba(0, 0, 0, 0.4)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          zIndex: 1000,
        }}>
          <div style={{
            background: "#ffffff",
            borderRadius: "8px",
            width: "520px",
            maxWidth: "90%",
            padding: "24px",
            boxShadow: "0 20px 25px -5px rgba(0, 0, 0, 0.1)",
          }}>
            <h3 style={{ fontSize: "16px", fontWeight: 700, color: "#111827", marginBottom: "6px" }}>
              Edit Field: {editModalInfo.field}
            </h3>
            <p style={{ fontSize: "12px", color: "#6b7280", marginBottom: "16px" }}>
              Modifying this value will stage an edit. Applying changes will generate Version {editModalInfo.version + 1} and re-evaluate through the pipeline.
            </p>

            <textarea
              value={editModalInfo.value}
              onChange={(e) =>
                setEditModalInfo((prev) => (prev ? { ...prev, value: e.target.value } : null))
              }
              rows={5}
              style={{
                width: "100%",
                padding: "10px",
                borderRadius: "6px",
                border: "1px solid #d1d5db",
                fontSize: "13px",
                fontFamily: "inherit",
                color: "#111827",
                marginBottom: "20px",
              }}
            />

            <div style={{ display: "flex", justifyContent: "flex-end", gap: "10px" }}>
              <button
                onClick={() => setEditModalInfo(null)}
                style={{
                  background: "#f3f4f6",
                  color: "#374151",
                  border: "none",
                  padding: "8px 14px",
                  borderRadius: "6px",
                  fontSize: "13px",
                }}
              >
                Cancel
              </button>
              <button
                onClick={saveCellEdit}
                style={{
                  background: "#111827",
                  color: "#ffffff",
                  border: "none",
                  padding: "8px 16px",
                  borderRadius: "6px",
                  fontSize: "13px",
                  fontWeight: 500,
                }}
              >
                Save Cell Edit
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

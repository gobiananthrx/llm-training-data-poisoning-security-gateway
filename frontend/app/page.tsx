"use client";

import { useEffect, useState, useRef } from "react";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";
const WS_BASE_URL = API_BASE_URL.replace(/^http/, "ws");

interface StepItem {
  id: string;
  label: string;
  status: "idle" | "running" | "completed" | "failed";
  details?: string;
}

const INITIAL_STEPS: StepItem[] = [
  { id: "ingest", label: "Dataset Ingestion & Canonicalization", status: "idle" },
  { id: "crypto", label: "Cryptographic Provenance & ML-DSA-65 Verification", status: "idle" },
  { id: "semantic", label: "Semantic Threat Intelligence (Injection, Overrides)", status: "idle" },
  { id: "behavioral", label: "Behavioral Threat Intelligence (Policy Bypass)", status: "idle" },
  { id: "inconsistency", label: "Inconsistency & Contradiction Analysis", status: "idle" },
  { id: "pii", label: "Presidio PII Detection (Names, Emails, Phones)", status: "idle" },
  { id: "correlation", label: "Cross-Agent Evidence Correlation", status: "idle" },
  { id: "risk", label: "Risk-Adaptive Scoring & Metric Calculation", status: "idle" },
  { id: "opa", label: "OPA Policy Governance (Rego Evaluation)", status: "idle" },
];

export default function GatewayPage() {
  const [datasetId, setDatasetId] = useState<string>("");
  const [version, setVersion] = useState<number>(1);
  const [file, setFile] = useState<File | null>(null);

  const [steps, setSteps] = useState<StepItem[]>(INITIAL_STEPS);
  const [pipelineRunning, setPipelineRunning] = useState(false);
  const [pipelineError, setPipelineError] = useState<string | null>(null);

  const [verificationResult, setVerificationResult] = useState<any>(null);
  const [analysisResult, setAnalysisResult] = useState<any>(null);
  const [authorizationResult, setAuthorizationResult] = useState<any>(null);

  // Content & findings for viewer
  const [contentData, setContentData] = useState<any>(null);
  const [findingsData, setFindingsData] = useState<any>(null);
  const [auditEvents, setAuditEvents] = useState<any[]>([]);

  // Active drawer & edit state
  const [selectedRecord, setSelectedRecord] = useState<any | null>(null);
  const [activeTab, setActiveTab] = useState<"viewer" | "audit">("viewer");
  const [editedCells, setEditedCells] = useState<Record<string, Record<string, string>>>({});
  const [removedRecordIds, setRemovedRecordIds] = useState<string[]>([]);
  const [reviewNotes, setReviewNotes] = useState<string>("");
  const [reviewSubmitting, setReviewSubmitting] = useState(false);

  const wsRef = useRef<WebSocket | null>(null);

  // Check query params on mount (e.g. ?id=DS-XXXX&version=1 from data collection)
  useEffect(() => {
    if (typeof window !== "undefined") {
      const urlParams = new URLSearchParams(window.location.search);
      const qId = urlParams.get("id");
      const qVer = urlParams.get("version");
      if (qId) {
        setDatasetId(qId);
        setVersion(qVer ? parseInt(qVer, 10) : 1);
      }
    }
  }, []);

  // Connect WebSocket when datasetId is active
  useEffect(() => {
    if (!datasetId) return;

    try {
      const ws = new WebSocket(`${WS_BASE_URL}/api/ws/${datasetId}`);
      wsRef.current = ws;

      ws.onmessage = (event) => {
        try {
          const msg = jsonParseSafe(event.data);
          if (msg && msg.event) {
            handlePipelineEvent(msg.event, msg.data);
          }
        } catch {
          // ignore
        }
      };

      ws.onclose = () => {
        wsRef.current = null;
      };

      return () => {
        ws.close();
      };
    } catch {
      // ignore
    }
  }, [datasetId]);

  function jsonParseSafe(str: string) {
    try {
      return JSON.parse(str);
    } catch {
      return null;
    }
  }

  function updateStep(id: string, status: "idle" | "running" | "completed" | "failed", details?: string) {
    setSteps((prev) =>
      prev.map((s) => (s.id === id ? { ...s, status, details: details || s.details } : s))
    );
  }

  function handlePipelineEvent(eventType: string, data: any) {
    switch (eventType) {
      case "processing_started":
        updateStep("ingest", "running");
        break;
      case "processing_completed":
        updateStep("ingest", "completed", `${data?.records || 0} records normalized`);
        break;
      case "verification_started":
        updateStep("crypto", "running");
        break;
      case "verification_completed":
        updateStep("crypto", "completed", "SHA-256 & ML-DSA-65 verified");
        break;
      case "verification_failed":
        updateStep("crypto", "failed", data?.reason || "Verification blocked");
        break;
      case "semantic_started":
        updateStep("semantic", "running");
        break;
      case "semantic_completed":
        updateStep("semantic", "completed", `${data?.findings_count || 0} findings (${data?.provider || "gemini"})`);
        break;
      case "behavioral_started":
        updateStep("behavioral", "running");
        break;
      case "behavioral_completed":
        updateStep("behavioral", "completed", `${data?.findings_count || 0} findings (${data?.provider || "gemini"})`);
        break;
      case "inconsistency_started":
        updateStep("inconsistency", "running");
        break;
      case "inconsistency_completed":
        updateStep("inconsistency", "completed", `${data?.findings_count || 0} findings (${data?.provider || "gemini"})`);
        break;
      case "pii_started":
        updateStep("pii", "running");
        break;
      case "pii_completed":
        updateStep("pii", "completed", `${data?.findings_count || 0} PII elements detected`);
        break;
      case "correlation_started":
        updateStep("correlation", "running");
        break;
      case "correlation_completed":
        updateStep("correlation", "completed", `${data?.correlated_count || 0} correlated findings`);
        break;
      case "risk_started":
        updateStep("risk", "running");
        break;
      case "risk_completed":
        updateStep("risk", "completed", `Risk Score: ${data?.risk_score}/100 (${data?.risk_level})`);
        break;
      case "opa_started":
        updateStep("opa", "running");
        break;
      case "opa_completed":
        updateStep("opa", "completed", `Decision: ${data?.decision}`);
        break;
      default:
        break;
    }
  }

  // Pre-training Verification & Security Gateway Pipeline
  async function runGatewayWorkflow(targetId?: string, targetVer?: number) {
    const activeId = targetId || datasetId;
    const activeVer = targetVer || version;

    if (!activeId) {
      setPipelineError("Please specify or ingest a Dataset ID first.");
      return;
    }

    setPipelineRunning(true);
    setPipelineError(null);
    setVerificationResult(null);
    setAnalysisResult(null);
    setAuthorizationResult(null);
    setSelectedRecord(null);

    // Reset steps to idle
    setSteps(INITIAL_STEPS.map((s) => ({ ...s, status: "idle" })));

    try {
      // Step 1: Pre-training cryptographic verification
      updateStep("crypto", "running");
      const verifyRes = await fetch(
        `${API_BASE_URL}/api/datasets/${activeId}/versions/${activeVer}/verify`,
        { method: "POST" }
      );
      const vData = await verifyRes.json();
      setVerificationResult(vData);

      if (!verifyRes.ok || vData.verification_status !== "VERIFIED") {
        updateStep("crypto", "failed", vData.reason || "Cryptographic verification failed.");
        setPipelineRunning(false);
        return;
      }
      updateStep("crypto", "completed", "SHA-256, Provenance, and ML-DSA-65 Valid");

      // Step 2: Trigger LangGraph security pipeline
      const analyzeRes = await fetch(
        `${API_BASE_URL}/api/datasets/${activeId}/versions/${activeVer}/analyze`,
        { method: "POST" }
      );
      const aData = await analyzeRes.json();
      if (!analyzeRes.ok) {
        throw new Error(aData.detail || "Security pipeline execution failed.");
      }
      setAnalysisResult(aData);

      // Step 3: Fetch findings & content for interactive viewer
      await loadDatasetContentAndFindings(activeId, activeVer);

      // Step 4: Check Training Authorization Gate
      const authRes = await fetch(
        `${API_BASE_URL}/api/datasets/${activeId}/versions/${activeVer}/authorization`
      );
      if (authRes.ok) {
        const authData = await authRes.json();
        setAuthorizationResult(authData);
      }
    } catch (err: any) {
      setPipelineError(err.message || "Pipeline failed.");
    } finally {
      setPipelineRunning(false);
    }
  }

  async function loadDatasetContentAndFindings(id: string, ver: number) {
    try {
      const [cRes, fRes, aRes] = await Promise.all([
        fetch(`${API_BASE_URL}/api/datasets/${id}/versions/${ver}/content`),
        fetch(`${API_BASE_URL}/api/datasets/${id}/versions/${ver}/findings`),
        fetch(`${API_BASE_URL}/api/datasets/${id}/versions/${ver}/audit`),
      ]);

      if (cRes.ok) setContentData(await cRes.json());
      if (fRes.ok) setFindingsData(await fRes.json());
      if (aRes.ok) setAuditEvents(await aRes.json());
    } catch {
      // ignore
    }
  }

  // Handle file selection directly on /
  async function handleDirectFileUploadAndRun() {
    if (!file) return;

    setPipelineRunning(true);
    setPipelineError(null);

    const form = new FormData();
    form.append("file", file);
    form.append("source", "gateway_direct_upload");

    try {
      const res = await fetch(`${API_BASE_URL}/api/datasets/upload`, {
        method: "POST",
        body: form,
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Direct upload failed");

      setDatasetId(data.dataset_id);
      setVersion(data.version);

      // Immediately run pre-training verification and security analysis
      await runGatewayWorkflow(data.dataset_id, data.version);
    } catch (err: any) {
      setPipelineError(err.message || "Upload failed");
      setPipelineRunning(false);
    }
  }

  // HITL: Cell editing
  function handleCellEdit(recId: string, field: string, val: string) {
    setEditedCells((prev) => ({
      ...prev,
      [recId]: {
        ...(prev[recId] || {}),
        [field]: val,
      },
    }));
  }

  // HITL: Mark row for removal
  function toggleRowRemoval(recId: string) {
    setRemovedRecordIds((prev) =>
      prev.includes(recId) ? prev.filter((id) => id !== recId) : [...prev, recId]
    );
  }

  // HITL Review submission: Approve, Reject, or Modify/Remove -> creates Version N+1
  async function submitReviewAction(action: "APPROVE" | "REJECT" | "MODIFY") {
    if (!datasetId) return;

    setReviewSubmitting(true);
    try {
      const modified_records = Object.entries(editedCells).map(([recId, data]) => ({
        record_id: recId,
        data,
      }));

      const payload = {
        action,
        notes: reviewNotes,
        modified_records: modified_records.length > 0 ? modified_records : null,
        removed_record_ids: removedRecordIds.length > 0 ? removedRecordIds : null,
      };

      const res = await fetch(
        `${API_BASE_URL}/api/datasets/${datasetId}/versions/${version}/review`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        }
      );

      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Review submission failed");

      // If Version N+1 was created
      if (data.new_version) {
        setVersion(data.new_version);
        setEditedCells({});
        setRemovedRecordIds([]);
        setReviewNotes("");
        setSelectedRecord(null);
        await runGatewayWorkflow(datasetId, data.new_version);
      } else {
        // Refresh authorization and findings
        await loadDatasetContentAndFindings(datasetId, version);
        const authRes = await fetch(
          `${API_BASE_URL}/api/datasets/${datasetId}/versions/${version}/authorization`
        );
        if (authRes.ok) setAuthorizationResult(await authRes.json());
      }
    } catch (err: any) {
      alert(`Review error: ${err.message}`);
    } finally {
      setReviewSubmitting(false);
    }
  }

  // Helper: map findings to record IDs
  const findingsByRecord = (findingsData?.findings || []).reduce(
    (acc: Record<string, any[]>, f: any) => {
      const rid = String(f.record_id);
      if (!acc[rid]) acc[rid] = [];
      acc[rid].push(f);
      return acc;
    },
    {}
  );

  const correlatedByRecord = (findingsData?.correlated_findings || []).reduce(
    (acc: Record<string, any>, cf: any) => {
      acc[String(cf.record_id)] = cf;
      return acc;
    },
    {}
  );

  return (
    <div style={{ maxWidth: 1100, margin: "32px auto", padding: "0 24px" }}>
      {/* Upper Control Bar: Minimal Entry */}
      <div style={{
        background: "#ffffff",
        border: "1px solid #e5e7eb",
        borderRadius: 8,
        padding: 20,
        marginBottom: 24,
        display: "flex",
        flexWrap: "wrap",
        alignItems: "center",
        justifyContent: "space-between",
        gap: 16,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, flex: "1 1 340px" }}>
          <div style={{ flex: 1 }}>
            <label style={{ display: "block", fontSize: 11, fontWeight: 600, color: "#4b5563", textTransform: "uppercase", marginBottom: 4 }}>
              Active Dataset ID
            </label>
            <input
              type="text"
              placeholder="e.g. DS-A91F82C31D22"
              value={datasetId}
              onChange={(e) => setDatasetId(e.target.value)}
              style={{
                width: "100%",
                padding: "7px 12px",
                border: "1px solid #d1d5db",
                borderRadius: 5,
                fontSize: 13,
                fontFamily: "monospace",
              }}
            />
          </div>
          <div style={{ width: 80 }}>
            <label style={{ display: "block", fontSize: 11, fontWeight: 600, color: "#4b5563", textTransform: "uppercase", marginBottom: 4 }}>
              Version
            </label>
            <input
              type="number"
              min={1}
              value={version}
              onChange={(e) => setVersion(parseInt(e.target.value, 10) || 1)}
              style={{
                width: "100%",
                padding: "7px 10px",
                border: "1px solid #d1d5db",
                borderRadius: 5,
                fontSize: 13,
              }}
            />
          </div>
          <button
            onClick={() => runGatewayWorkflow()}
            disabled={!datasetId || pipelineRunning}
            style={{
              marginTop: 18,
              background: !datasetId || pipelineRunning ? "#9ca3af" : "#111827",
              color: "#ffffff",
              border: "none",
              padding: "8px 16px",
              borderRadius: 5,
              fontSize: 13,
              fontWeight: 500,
            }}
          >
            {pipelineRunning ? "Verifying..." : "Run Security Gateway"}
          </button>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 8, borderLeft: "1px solid #e5e7eb", paddingLeft: 16 }}>
          <input
            type="file"
            id="direct-file-input"
            accept=".csv,.json,.txt,.xlsx"
            disabled={pipelineRunning}
            onChange={(e) => {
              if (e.target.files?.[0]) setFile(e.target.files[0]);
            }}
            style={{ display: "none" }}
          />
          <label
            htmlFor="direct-file-input"
            style={{
              display: "inline-block",
              background: "#f9fafb",
              border: "1px solid #d1d5db",
              padding: "7px 12px",
              borderRadius: 5,
              fontSize: 12,
              color: "#374151",
              cursor: "pointer",
            }}
          >
            {file ? file.name.slice(0, 18) : "Select local file"}
          </label>
          <button
            onClick={handleDirectFileUploadAndRun}
            disabled={!file || pipelineRunning}
            style={{
              background: !file || pipelineRunning ? "#e5e7eb" : "#2563eb",
              color: !file || pipelineRunning ? "#9ca3af" : "#ffffff",
              border: "none",
              padding: "7px 14px",
              borderRadius: 5,
              fontSize: 12,
              fontWeight: 500,
            }}
          >
            Upload & Run
          </button>
        </div>
      </div>

      {pipelineError && (
        <div style={{
          padding: 12,
          background: "#fef2f2",
          border: "1px solid #fecaca",
          borderRadius: 6,
          color: "#b91c1c",
          fontSize: 13,
          marginBottom: 20,
        }}>
          {pipelineError}
        </div>
      )}

      {/* Real-Time Green Tick Execution Steps */}
      <div style={{
        background: "#ffffff",
        border: "1px solid #e5e7eb",
        borderRadius: 8,
        padding: "20px 24px",
        marginBottom: 24,
      }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: "#374151", marginBottom: 14 }}>
          Security Execution Lifecycle
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(290px, 1fr))", gap: 10 }}>
          {steps.map((step) => (
            <div
              key={step.id}
              style={{
                display: "flex",
                alignItems: "flex-start",
                gap: 10,
                padding: "8px 12px",
                borderRadius: 6,
                background: step.status === "completed" ? "#f0fdf4" : step.status === "failed" ? "#fef2f2" : "#f9fafb",
                border: `1px solid ${
                  step.status === "completed" ? "#bbf7d0" : step.status === "failed" ? "#fecaca" : "#f3f4f6"
                }`,
              }}
            >
              <div style={{ marginTop: 1, fontSize: 14 }}>
                {step.status === "completed" && <span style={{ color: "#16a34a", fontWeight: "bold" }}>✓</span>}
                {step.status === "running" && <span style={{ color: "#2563eb", animation: "pulse 1s infinite" }}>●</span>}
                {step.status === "failed" && <span style={{ color: "#dc2626", fontWeight: "bold" }}>✗</span>}
                {step.status === "idle" && <span style={{ color: "#d1d5db" }}>○</span>}
              </div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{
                  fontSize: 12,
                  fontWeight: step.status === "completed" ? 600 : 500,
                  color: step.status === "completed" ? "#15803d" : step.status === "failed" ? "#b91c1c" : "#374151",
                }}>
                  {step.label}
                </div>
                {step.details && (
                  <div style={{ fontSize: 11, color: "#6b7280", marginTop: 2 }}>
                    {step.details}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Verification Failure Banner */}
      {verificationResult && verificationResult.verification_status === "BLOCKED" && (
        <div style={{
          background: "#fef2f2",
          border: "1px solid #f87171",
          borderRadius: 8,
          padding: 18,
          marginBottom: 24,
          color: "#991b1b",
        }}>
          <div style={{ fontWeight: 700, fontSize: 15, marginBottom: 4 }}>
            ✗ Cryptographic Integrity Verification Failed — Dataset Blocked
          </div>
          <div style={{ fontSize: 13, marginBottom: 8 }}>
            Reason: {verificationResult.reason}
          </div>
          <div style={{ fontSize: 12, color: "#7f1d1d" }}>
            The dataset file on disk does not match the signed ML-DSA-65 provenance attestation. It has been strictly blocked from proceeding to training or model workflows.
          </div>
        </div>
      )}

      {/* Training Access Gate Card (If Approved) */}
      {authorizationResult && authorizationResult.training_authorized && (
        <div style={{
          background: "#f0fdf4",
          border: "2px solid #22c55e",
          borderRadius: 8,
          padding: 24,
          marginBottom: 24,
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, color: "#15803d", fontWeight: 700, fontSize: 16, marginBottom: 12 }}>
            <span style={{ fontSize: 20 }}>✓</span> Dataset Approved for Training
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 16, fontSize: 13 }}>
            <div>
              <div style={{ color: "#4b5563", fontSize: 11, textTransform: "uppercase", fontWeight: 600 }}>Dataset ID</div>
              <div style={{ fontFamily: "monospace", fontWeight: 600, color: "#111827", marginTop: 2 }}>{authorizationResult.dataset_id}</div>
            </div>
            <div>
              <div style={{ color: "#4b5563", fontSize: 11, textTransform: "uppercase", fontWeight: 600 }}>Version</div>
              <div style={{ fontWeight: 600, color: "#111827", marginTop: 2 }}>v{authorizationResult.version}</div>
            </div>
            <div>
              <div style={{ color: "#4b5563", fontSize: 11, textTransform: "uppercase", fontWeight: 600 }}>Risk Level</div>
              <div style={{ fontWeight: 600, color: "#15803d", marginTop: 2 }}>{authorizationResult.risk_level} ({authorizationResult.risk_score}/100)</div>
            </div>
            <div>
              <div style={{ color: "#4b5563", fontSize: 11, textTransform: "uppercase", fontWeight: 600 }}>OPA Decision</div>
              <div style={{ fontWeight: 600, color: "#15803d", marginTop: 2 }}>{authorizationResult.opa_decision}</div>
            </div>
          </div>
          <div style={{ marginTop: 16, paddingTop: 12, borderTop: "1px solid #bbf7d0", fontSize: 11, color: "#4b5563" }}>
            Fingerprint: <code style={{ fontFamily: "monospace", color: "#111827" }}>{authorizationResult.sha256}</code>
            <span style={{ marginLeft: 16 }}>Authorized at: {authorizationResult.authorized_at || "Verified"}</span>
          </div>
        </div>
      )}

      {/* Quarantined Status Banner */}
      {analysisResult && analysisResult.decision === "QUARANTINE" && (
        <div style={{
          background: "#fffbeb",
          border: "1px solid #fcd34d",
          borderRadius: 8,
          padding: 18,
          marginBottom: 24,
          color: "#92400e",
        }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <div>
              <div style={{ fontWeight: 700, fontSize: 15, marginBottom: 2 }}>
                ⚠️ Dataset Quarantined for Human-In-The-Loop Review
              </div>
              <div style={{ fontSize: 13 }}>
                Assigned Risk Score: <strong>{analysisResult.risk_score}/100 ({analysisResult.risk_level})</strong> with {analysisResult.findings_count} security findings.
              </div>
            </div>
            <div style={{ fontSize: 12, color: "#78350f" }}>
              Click on highlighted records below to inspect evidence, edit cells, or remove rows.
            </div>
          </div>
        </div>
      )}

      {/* Main Tabs: Dataset Viewer & Audit Trail */}
      {contentData && (
        <div style={{ background: "#ffffff", border: "1px solid #e5e7eb", borderRadius: 8, overflow: "hidden", marginBottom: 32 }}>
          <div style={{ display: "flex", borderBottom: "1px solid #e5e7eb", background: "#f9fafb" }}>
            <button
              onClick={() => setActiveTab("viewer")}
              style={{
                padding: "12px 20px",
                border: "none",
                background: activeTab === "viewer" ? "#ffffff" : "transparent",
                borderBottom: activeTab === "viewer" ? "2px solid #111827" : "none",
                fontWeight: activeTab === "viewer" ? 600 : 500,
                fontSize: 13,
                color: activeTab === "viewer" ? "#111827" : "#6b7280",
              }}
            >
              Interactive Dataset Viewer ({contentData.record_count} Records)
            </button>
            <button
              onClick={() => setActiveTab("audit")}
              style={{
                padding: "12px 20px",
                border: "none",
                background: activeTab === "audit" ? "#ffffff" : "transparent",
                borderBottom: activeTab === "audit" ? "2px solid #111827" : "none",
                fontWeight: activeTab === "audit" ? 600 : 500,
                fontSize: 13,
                color: activeTab === "audit" ? "#111827" : "#6b7280",
              }}
            >
              Audit Trail ({auditEvents.length} Events)
            </button>
            <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 14, paddingRight: 16, fontSize: 11 }}>
              <span style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
                <span style={{ width: 10, height: 10, borderRadius: 2, background: "#ef4444" }}></span> Semantic
              </span>
              <span style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
                <span style={{ width: 10, height: 10, borderRadius: 2, background: "#f97316" }}></span> Behavioral
              </span>
              <span style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
                <span style={{ width: 10, height: 10, borderRadius: 2, background: "#eab308" }}></span> Inconsistency
              </span>
              <span style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
                <span style={{ width: 10, height: 10, borderRadius: 2, background: "#3b82f6" }}></span> PII
              </span>
            </div>
          </div>

          {activeTab === "viewer" && (
            <div style={{ display: "flex", position: "relative" }}>
              {/* Dataset Table View */}
              <div style={{ flex: 1, overflowX: "auto", maxHeight: 560 }}>
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12, textAlign: "left" }}>
                  <thead style={{ position: "sticky", top: 0, background: "#f9fafb", zIndex: 10 }}>
                    <tr style={{ borderBottom: "1px solid #e5e7eb", color: "#4b5563" }}>
                      <th style={{ padding: "8px 12px", width: 60 }}># ID</th>
                      {contentData.columns.map((col: string) => (
                        <th key={col} style={{ padding: "8px 12px", fontWeight: 600 }}>
                          {col}
                        </th>
                      ))}
                      <th style={{ padding: "8px 12px", width: 90, textAlign: "center" }}>Findings</th>
                    </tr>
                  </thead>
                  <tbody>
                    {contentData.records.map((r: any) => {
                      const recId = String(r.record_id);
                      const recFindings = findingsByRecord[recId] || [];
                      const correlated = correlatedByRecord[recId];
                      const isRemoved = removedRecordIds.includes(recId);
                      const hasSemantic = recFindings.some((f: any) => f.agent === "semantic");
                      const hasBehavioral = recFindings.some((f: any) => f.agent === "behavioral");
                      const hasInconsistency = recFindings.some((f: any) => f.agent === "inconsistency");
                      const hasPii = recFindings.some((f: any) => f.agent === "pii");

                      return (
                        <tr
                          key={recId}
                          onClick={() => setSelectedRecord({ ...r, findings: recFindings, correlated })}
                          style={{
                            borderBottom: "1px solid #f3f4f6",
                            cursor: "pointer",
                            background: isRemoved
                              ? "#fee2e2"
                              : selectedRecord?.record_id === r.record_id
                              ? "#f0f9ff"
                              : recFindings.length > 0
                              ? "#fffdf5"
                              : "#ffffff",
                            textDecoration: isRemoved ? "line-through" : "none",
                          }}
                        >
                          <td style={{ padding: "8px 12px", fontFamily: "monospace", color: "#6b7280" }}>
                            {recId}
                          </td>
                          {contentData.columns.map((col: string) => {
                            const val = editedCells[recId]?.[col] !== undefined ? editedCells[recId][col] : r.data[col] || "";
                            const fieldFlagged = recFindings.some((f: any) => f.field === col);

                            return (
                              <td
                                key={col}
                                style={{
                                  padding: "8px 12px",
                                  maxWidth: 240,
                                  overflow: "hidden",
                                  textOverflow: "ellipsis",
                                  whiteSpace: "nowrap",
                                  background: fieldFlagged ? "rgba(254, 240, 138, 0.25)" : "transparent",
                                }}
                              >
                                {val}
                              </td>
                            );
                          })}
                          <td style={{ padding: "8px 12px", textAlign: "center" }}>
                            <div style={{ display: "inline-flex", gap: 3 }}>
                              {hasSemantic && (
                                <span title="Semantic Agent Flag" style={{ width: 8, height: 8, borderRadius: "50%", background: "#ef4444" }} />
                              )}
                              {hasBehavioral && (
                                <span title="Behavioral Agent Flag" style={{ width: 8, height: 8, borderRadius: "50%", background: "#f97316" }} />
                              )}
                              {hasInconsistency && (
                                <span title="Inconsistency Flag" style={{ width: 8, height: 8, borderRadius: "50%", background: "#eab308" }} />
                              )}
                              {hasPii && (
                                <span title="Presidio PII Flag" style={{ width: 8, height: 8, borderRadius: "50%", background: "#3b82f6" }} />
                              )}
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              {/* Finding Detail Drawer (Right Side) */}
              {selectedRecord && (
                <div style={{
                  width: 380,
                  borderLeft: "1px solid #e5e7eb",
                  background: "#ffffff",
                  padding: 16,
                  display: "flex",
                  flexDirection: "column",
                  maxHeight: 560,
                  overflowY: "auto",
                }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
                    <div style={{ fontWeight: 600, fontSize: 13, color: "#111827" }}>
                      Record #{selectedRecord.record_id}
                    </div>
                    <button
                      onClick={() => setSelectedRecord(null)}
                      style={{ border: "none", background: "none", fontSize: 16, color: "#6b7280" }}
                    >
                      ✕
                    </button>
                  </div>

                  {/* Multi-Agent Consensus Banner */}
                  {selectedRecord.correlated && (
                    <div style={{
                      padding: "8px 12px",
                      background: "#eff6ff",
                      border: "1px solid #bfdbfe",
                      borderRadius: 5,
                      fontSize: 12,
                      color: "#1e40af",
                      fontWeight: 600,
                      marginBottom: 12,
                    }}>
                      ⚡ {selectedRecord.correlated.agents_involved.length} Agents Corroborated This Content
                      <div style={{ fontSize: 11, fontWeight: 400, color: "#3b82f6", marginTop: 2 }}>
                        Agents: {selectedRecord.correlated.agents_involved.join(", ")}
                      </div>
                    </div>
                  )}

                  {/* Agent Findings Breakdown */}
                  <div style={{ flex: 1, marginBottom: 16 }}>
                    <div style={{ fontSize: 11, fontWeight: 600, color: "#6b7280", textTransform: "uppercase", marginBottom: 6 }}>
                      Active Threat Findings ({selectedRecord.findings?.length || 0})
                    </div>
                    {(!selectedRecord.findings || selectedRecord.findings.length === 0) ? (
                      <div style={{ fontSize: 12, color: "#9ca3af", fontStyle: "italic" }}>
                        No security flags on this record.
                      </div>
                    ) : (
                      selectedRecord.findings.map((f: any) => (
                        <div
                          key={f.finding_id}
                          style={{
                            background: "#f9fafb",
                            border: "1px solid #e5e7eb",
                            borderRadius: 6,
                            padding: 10,
                            marginBottom: 8,
                            fontSize: 12,
                          }}
                        >
                          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                            <span style={{ fontWeight: 600, color: "#111827", textTransform: "capitalize" }}>
                              {f.agent} Agent
                            </span>
                            <span style={{
                              fontSize: 10,
                              fontWeight: 700,
                              padding: "1px 6px",
                              borderRadius: 3,
                              background: f.severity === "HIGH" || f.severity === "CRITICAL" ? "#fee2e2" : "#fef3c7",
                              color: f.severity === "HIGH" || f.severity === "CRITICAL" ? "#b91c1c" : "#b45309",
                            }}>
                              {f.severity}
                            </span>
                          </div>
                          <div style={{ color: "#374151", marginBottom: 4 }}>
                            <strong>Category:</strong> {f.category}
                          </div>
                          <div style={{ color: "#4b5563", fontSize: 11, marginBottom: 4 }}>
                            <strong>Reason:</strong> {f.reason}
                          </div>
                          {f.evidence && (
                            <div style={{ background: "#ffffff", border: "1px solid #e5e7eb", padding: 6, borderRadius: 4, fontFamily: "monospace", fontSize: 11, color: "#b91c1c" }}>
                              "{f.evidence}"
                            </div>
                          )}
                        </div>
                      ))
                    )}
                  </div>

                  {/* Inline Cell Edit Form */}
                  <div style={{ borderTop: "1px solid #e5e7eb", paddingTop: 12, marginBottom: 12 }}>
                    <div style={{ fontSize: 11, fontWeight: 600, color: "#6b7280", textTransform: "uppercase", marginBottom: 6 }}>
                      Remediate Record Fields
                    </div>
                    {contentData.columns.slice(0, 3).map((col: string) => {
                      const curVal = editedCells[selectedRecord.record_id]?.[col] !== undefined
                        ? editedCells[selectedRecord.record_id][col]
                        : selectedRecord.data[col] || "";
                      return (
                        <div key={col} style={{ marginBottom: 6 }}>
                          <label style={{ display: "block", fontSize: 10, color: "#4b5563" }}>{col}:</label>
                          <input
                            type="text"
                            value={curVal}
                            onChange={(e) => handleCellEdit(selectedRecord.record_id, col, e.target.value)}
                            style={{
                              width: "100%",
                              padding: "5px 8px",
                              border: "1px solid #d1d5db",
                              borderRadius: 4,
                              fontSize: 12,
                            }}
                          />
                        </div>
                      );
                    })}
                  </div>

                  {/* Remediation Action Controls */}
                  <div style={{ display: "flex", gap: 8 }}>
                    <button
                      onClick={() => toggleRowRemoval(selectedRecord.record_id)}
                      style={{
                        flex: 1,
                        background: removedRecordIds.includes(selectedRecord.record_id) ? "#4b5563" : "#fee2e2",
                        color: removedRecordIds.includes(selectedRecord.record_id) ? "#ffffff" : "#b91c1c",
                        border: "1px solid #fca5a5",
                        padding: "7px 10px",
                        borderRadius: 5,
                        fontSize: 11,
                        fontWeight: 600,
                      }}
                    >
                      {removedRecordIds.includes(selectedRecord.record_id) ? "Undo Removal" : "Remove Record"}
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Audit Trail Tab */}
          {activeTab === "audit" && (
            <div style={{ padding: 20 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: "#374151", marginBottom: 12 }}>
                Cryptographic & Governance Event Log
              </div>
              {auditEvents.length === 0 ? (
                <div style={{ fontSize: 13, color: "#9ca3af", fontStyle: "italic" }}>
                  No audit events recorded yet.
                </div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                  {auditEvents.map((evt) => (
                    <div
                      key={evt.id}
                      style={{
                        padding: "10px 14px",
                        borderRadius: 6,
                        background: "#f9fafb",
                        border: "1px solid #e5e7eb",
                        fontSize: 12,
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                      }}
                    >
                      <div>
                        <span style={{ fontWeight: 600, color: "#111827", marginRight: 8 }}>
                          {evt.event_type}
                        </span>
                        <span style={{ color: "#6b7280" }}>
                          v{evt.version}
                        </span>
                      </div>
                      <div style={{ color: "#9ca3af", fontSize: 11 }}>
                        {evt.timestamp}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* HITL Submission Bar */}
          <div style={{
            background: "#f9fafb",
            borderTop: "1px solid #e5e7eb",
            padding: "12px 20px",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            flexWrap: "wrap",
            gap: 12,
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, flex: 1, minWidth: 260 }}>
              <input
                type="text"
                placeholder="Auditor remediation notes..."
                value={reviewNotes}
                onChange={(e) => setReviewNotes(e.target.value)}
                style={{
                  width: "100%",
                  padding: "6px 10px",
                  border: "1px solid #d1d5db",
                  borderRadius: 4,
                  fontSize: 12,
                }}
              />
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              {(Object.keys(editedCells).length > 0 || removedRecordIds.length > 0) ? (
                <button
                  onClick={() => submitReviewAction("MODIFY")}
                  disabled={reviewSubmitting}
                  style={{
                    background: "#2563eb",
                    color: "#ffffff",
                    border: "none",
                    padding: "7px 14px",
                    borderRadius: 4,
                    fontSize: 12,
                    fontWeight: 600,
                  }}
                >
                  {reviewSubmitting ? "Generating Version N+1..." : `Apply Edits & Create v${version + 1}`}
                </button>
              ) : (
                <>
                  <button
                    onClick={() => submitReviewAction("APPROVE")}
                    disabled={reviewSubmitting}
                    style={{
                      background: "#15803d",
                      color: "#ffffff",
                      border: "none",
                      padding: "7px 14px",
                      borderRadius: 4,
                      fontSize: 12,
                      fontWeight: 600,
                    }}
                  >
                    Approve Dataset
                  </button>
                  <button
                    onClick={() => submitReviewAction("REJECT")}
                    disabled={reviewSubmitting}
                    style={{
                      background: "#dc2626",
                      color: "#ffffff",
                      border: "none",
                      padding: "7px 14px",
                      borderRadius: 4,
                      fontSize: 12,
                      fontWeight: 600,
                    }}
                  >
                    Reject Dataset
                  </button>
                </>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

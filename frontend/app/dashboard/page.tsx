"use client";

import { useEffect, useState } from "react";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";

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

export default function DashboardPage() {
  const [datasets, setDatasets] = useState<DatasetItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchDatasets();
  }, []);

  async function fetchDatasets() {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE_URL}/api/datasets/`);
      if (!res.ok) throw new Error("Failed to load datasets for dashboard");
      const data: DatasetItem[] = await res.json();
      setDatasets(data);
    } catch (err: any) {
      setError(err.message || "Failed to fetch dashboard metrics");
    } finally {
      setLoading(false);
    }
  }

  // Metric computations
  const total = datasets.length;
  const approved = datasets.filter(
    (d) => d.opa_decision === "APPROVE" || d.status === "APPROVED"
  ).length;

  const blocked = datasets.filter(
    (d) => d.status === "BLOCKED" || d.status === "FAILED"
  ).length;

  const rejected = datasets.filter(
    (d) =>
      (d.opa_decision === "REJECT" || d.status === "REJECTED") &&
      d.status !== "BLOCKED"
  ).length;

  const inHitl = datasets.filter(
    (d) =>
      (d.opa_decision === "QUARANTINE" ||
        d.status === "QUARANTINED" ||
        d.status === "PENDING" ||
        d.status === "ANALYZED") &&
      d.status !== "BLOCKED" &&
      d.status !== "REJECTED" &&
      d.opa_decision !== "REJECT" &&
      d.opa_decision !== "APPROVE"
  ).length;

  function calcPercent(count: number): string {
    if (total === 0) return "0%";
    return `${Math.round((count / total) * 100)}%`;
  }

  const statCards = [
    {
      title: "Total Datasets",
      value: total,
      subtext: "Ingested via gateway",
      color: "#111827",
      bg: "#ffffff",
      borderColor: "#e5e7eb",
    },
    {
      title: "Approved for Training",
      value: approved,
      subtext: `${calcPercent(approved)} of total`,
      color: "#059669",
      bg: "#ffffff",
      borderColor: "#a7f3d0",
    },
    {
      title: "In HITL Review",
      value: inHitl,
      subtext: `${calcPercent(inHitl)} pending remediation`,
      color: "#d97706",
      bg: "#ffffff",
      borderColor: "#fde68a",
    },
    {
      title: "Blocked (Integrity)",
      value: blocked,
      subtext: `${calcPercent(blocked)} failed cryptographic gate`,
      color: "#dc2626",
      bg: "#ffffff",
      borderColor: "#fecaca",
    },
    {
      title: "Rejected (Policy)",
      value: rejected,
      subtext: `${calcPercent(rejected)} adversarial score high`,
      color: "#991b1b",
      bg: "#ffffff",
      borderColor: "#fed7aa",
    },
  ];

  const barSegments = [
    { label: "Approved", count: approved, bg: "#10b981" },
    { label: "In HITL", count: inHitl, bg: "#f59e0b" },
    { label: "Blocked", count: blocked, bg: "#ef4444" },
    { label: "Rejected", count: rejected, bg: "#991b1b" },
  ];

  const maxCategoryCount = Math.max(approved, inHitl, blocked, rejected, 1);

  return (
    <div style={{ padding: "40px 48px", maxWidth: "1280px", margin: "0 auto" }}>
      {/* Header */}
      <div style={{ marginBottom: "32px", display: "flex", justifyContent: "space-between", alignItems: "flex-end" }}>
        <div>
          <h1 style={{ fontSize: "26px", fontWeight: 700, color: "#111827", letterSpacing: "-0.02em", marginBottom: "6px" }}>
            Security Dashboard
          </h1>
          <p style={{ fontSize: "14px", color: "#6b7280" }}>
            Real-time telemetry on cryptographic integrity, adversarial threat detections, and policy decisions.
          </p>
        </div>

        <button
          onClick={fetchDatasets}
          disabled={loading}
          style={{
            background: "#ffffff",
            border: "1px solid #d1d5db",
            padding: "8px 16px",
            borderRadius: "6px",
            fontSize: "13px",
            fontWeight: 500,
            color: "#374151",
            boxShadow: "0 1px 2px rgba(0, 0, 0, 0.05)",
          }}
        >
          {loading ? "Refreshing..." : "Refresh Telemetry"}
        </button>
      </div>

      {error && (
        <div style={{
          padding: "16px 20px",
          background: "#fef2f2",
          border: "1px solid #fee2e2",
          borderRadius: "8px",
          color: "#991b1b",
          fontSize: "14px",
          marginBottom: "24px",
        }}>
          {error}
        </div>
      )}

      {/* Numerical Stats Grid */}
      <div style={{
        display: "grid",
        gridTemplateColumns: "repeat(auto-fit, minmax(210px, 1fr))",
        gap: "18px",
        marginBottom: "36px",
      }}>
        {statCards.map((card) => (
          <div
            key={card.title}
            style={{
              background: card.bg,
              border: `1px solid ${card.borderColor}`,
              borderRadius: "10px",
              padding: "22px 24px",
              boxShadow: "0 1px 3px rgba(0, 0, 0, 0.04)",
              transition: "transform 0.15s ease, box-shadow 0.15s ease",
            }}
          >
            <div style={{ fontSize: "12px", fontWeight: 600, color: "#6b7280", letterSpacing: "0.04em", textTransform: "uppercase", marginBottom: "8px" }}>
              {card.title}
            </div>
            <div style={{ fontSize: "32px", fontWeight: 700, color: card.color, lineHeight: 1.1, marginBottom: "8px" }}>
              {loading ? "..." : card.value}
            </div>
            <div style={{ fontSize: "12px", color: "#6b7280" }}>
              {card.subtext}
            </div>
          </div>
        ))}
      </div>

      {/* Visualizations Section */}
      <div style={{
        display: "grid",
        gridTemplateColumns: "1fr 1fr",
        gap: "24px",
        marginBottom: "36px",
      }}>
        {/* Proportional Segment Bar Card */}
        <div style={{
          background: "#ffffff",
          border: "1px solid #e5e7eb",
          borderRadius: "10px",
          padding: "24px",
          boxShadow: "0 1px 3px rgba(0, 0, 0, 0.04)",
        }}>
          <h2 style={{ fontSize: "15px", fontWeight: 700, color: "#111827", marginBottom: "4px" }}>
            Dataset Governance Distribution
          </h2>
          <p style={{ fontSize: "12px", color: "#6b7280", marginBottom: "20px" }}>
            Cumulative proportion of all processed datasets across gateway states
          </p>

          {/* Horizontal multi-segment track */}
          <div style={{
            height: "18px",
            width: "100%",
            background: "#f3f4f6",
            borderRadius: "9px",
            overflow: "hidden",
            display: "flex",
            marginBottom: "20px",
          }}>
            {total > 0 ? (
              barSegments.map((seg) => {
                const pct = (seg.count / total) * 100;
                if (pct <= 0) return null;
                return (
                  <div
                    key={seg.label}
                    title={`${seg.label}: ${seg.count} (${Math.round(pct)}%)`}
                    style={{
                      width: `${pct}%`,
                      height: "100%",
                      background: seg.bg,
                      transition: "width 0.4s ease",
                    }}
                  />
                );
              })
            ) : (
              <div style={{ width: "100%", height: "100%", background: "#e5e7eb" }} />
            )}
          </div>

          {/* Legend */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: "12px" }}>
            {barSegments.map((seg) => (
              <div key={seg.label} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", fontSize: "13px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  <span style={{ width: 10, height: 10, borderRadius: "50%", background: seg.bg, display: "inline-block" }}></span>
                  <span style={{ color: "#374151", fontWeight: 500 }}>{seg.label}</span>
                </div>
                <span style={{ fontWeight: 600, color: "#111827" }}>
                  {seg.count} <span style={{ color: "#9ca3af", fontWeight: 400, fontSize: "12px" }}>({calcPercent(seg.count)})</span>
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Vertical Comparative Bar Chart Card */}
        <div style={{
          background: "#ffffff",
          border: "1px solid #e5e7eb",
          borderRadius: "10px",
          padding: "24px",
          boxShadow: "0 1px 3px rgba(0, 0, 0, 0.04)",
        }}>
          <h2 style={{ fontSize: "15px", fontWeight: 700, color: "#111827", marginBottom: "4px" }}>
            Category Volume Comparison
          </h2>
          <p style={{ fontSize: "12px", color: "#6b7280", marginBottom: "20px" }}>
            Direct volumetric count across security and governance classifications
          </p>

          <div style={{ display: "flex", alignItems: "flex-end", height: "140px", gap: "28px", paddingBottom: "10px", borderBottom: "1px solid #f3f4f6" }}>
            {barSegments.map((seg) => {
              const heightPct = Math.max((seg.count / maxCategoryCount) * 100, 4);
              return (
                <div key={seg.label} style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", height: "100%", justifyContent: "flex-end" }}>
                  <span style={{ fontSize: "12px", fontWeight: 700, color: "#111827", marginBottom: "6px" }}>
                    {seg.count}
                  </span>
                  <div
                    style={{
                      width: "100%",
                      maxWidth: "48px",
                      height: `${heightPct}%`,
                      background: seg.bg,
                      borderRadius: "6px 6px 0 0",
                      transition: "height 0.4s ease",
                    }}
                  />
                </div>
              );
            })}
          </div>

          <div style={{ display: "flex", gap: "28px", marginTop: "10px" }}>
            {barSegments.map((seg) => (
              <div key={seg.label} style={{ flex: 1, textAlign: "center", fontSize: "12px", fontWeight: 600, color: "#4b5563" }}>
                {seg.label}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Dataset Inventory Table */}
      <div style={{
        background: "#ffffff",
        border: "1px solid #e5e7eb",
        borderRadius: "10px",
        overflow: "hidden",
        boxShadow: "0 1px 3px rgba(0, 0, 0, 0.04)",
      }}>
        <div style={{ padding: "16px 24px", borderBottom: "1px solid #e5e7eb", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div>
            <h3 style={{ fontSize: "15px", fontWeight: 700, color: "#111827" }}>
              Dataset Telemetry Ledger
            </h3>
            <span style={{ fontSize: "12px", color: "#6b7280" }}>
              Comprehensive log of all registered datasets in the gateway
            </span>
          </div>
          <a
            href="/"
            style={{
              fontSize: "12px",
              fontWeight: 600,
              color: "#2563eb",
              textDecoration: "none",
            }}
          >
            Go to Pipeline
          </a>
        </div>

        {datasets.length === 0 ? (
          <div style={{ padding: "40px", textAlign: "center", color: "#6b7280", fontSize: "13px" }}>
            No dataset records ingested yet. Execute the pipeline to populate telemetry.
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "13px" }}>
              <thead>
                <tr style={{ background: "#f9fafb", borderBottom: "1px solid #e5e7eb", textAlign: "left" }}>
                  <th style={{ padding: "12px 18px", color: "#4b5563", fontWeight: 600 }}>Dataset ID</th>
                  <th style={{ padding: "12px 18px", color: "#4b5563", fontWeight: 600 }}>Version</th>
                  <th style={{ padding: "12px 18px", color: "#4b5563", fontWeight: 600 }}>Filename</th>
                  <th style={{ padding: "12px 18px", color: "#4b5563", fontWeight: 600 }}>Type</th>
                  <th style={{ padding: "12px 18px", color: "#4b5563", fontWeight: 600 }}>Risk Score</th>
                  <th style={{ padding: "12px 18px", color: "#4b5563", fontWeight: 600 }}>Status</th>
                  <th style={{ padding: "12px 18px", color: "#4b5563", fontWeight: 600 }}>Policy Decision</th>
                </tr>
              </thead>
              <tbody>
                {datasets.map((d) => (
                  <tr key={`${d.dataset_id}-v${d.version}`} style={{ borderBottom: "1px solid #f3f4f6" }}>
                    <td style={{ padding: "12px 18px", fontFamily: "monospace", fontWeight: 600, color: "#111827" }}>
                      {d.dataset_id}
                    </td>
                    <td style={{ padding: "12px 18px", color: "#4b5563" }}>
                      v{d.version}
                    </td>
                    <td style={{ padding: "12px 18px", fontWeight: 500, color: "#111827" }}>
                      {d.filename}
                    </td>
                    <td style={{ padding: "12px 18px" }}>
                      <span style={{
                        padding: "2px 6px",
                        borderRadius: "4px",
                        fontSize: "11px",
                        fontWeight: 600,
                        background: "#f3f4f6",
                        color: "#374151",
                        textTransform: "uppercase",
                      }}>
                        {d.file_type || "UNKNOWN"}
                      </span>
                    </td>
                    <td style={{ padding: "12px 18px", fontWeight: 700 }}>
                      <span style={{
                        color: (d.risk_score ?? 0) >= 65 ? "#dc2626" : (d.risk_score ?? 0) >= 20 ? "#ea580c" : "#059669",
                      }}>
                        {d.risk_score ?? 0}/100
                      </span>
                    </td>
                    <td style={{ padding: "12px 18px" }}>
                      <span style={{
                        padding: "3px 8px",
                        borderRadius: "4px",
                        fontSize: "11px",
                        fontWeight: 600,
                        background: d.status === "BLOCKED" ? "#fef2f2" : d.status === "APPROVED" ? "#ecfdf5" : "#fffbeb",
                        color: d.status === "BLOCKED" ? "#991b1b" : d.status === "APPROVED" ? "#065f46" : "#92400e",
                      }}>
                        {d.status}
                      </span>
                    </td>
                    <td style={{ padding: "12px 18px" }}>
                      <span style={{
                        padding: "3px 8px",
                        borderRadius: "4px",
                        fontSize: "11px",
                        fontWeight: 600,
                        background:
                          d.opa_decision === "APPROVE"
                            ? "#ecfdf5"
                            : d.opa_decision === "REJECT"
                            ? "#fef2f2"
                            : "#fffbeb",
                        color:
                          d.opa_decision === "APPROVE"
                            ? "#065f46"
                            : d.opa_decision === "REJECT"
                            ? "#991b1b"
                            : "#92400e",
                      }}>
                        {d.opa_decision || "PENDING"}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

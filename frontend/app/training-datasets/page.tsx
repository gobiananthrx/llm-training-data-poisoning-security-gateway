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

export default function TrainingDatasetsPage() {
  const [datasets, setDatasets] = useState<DatasetItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchApprovedDatasets();
  }, []);

  async function fetchApprovedDatasets() {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE_URL}/api/datasets/`);
      if (!res.ok) throw new Error("Failed to load datasets");
      const data: DatasetItem[] = await res.json();
      // Filter for authorized/approved datasets
      const approved = data.filter(
        (d) => d.opa_decision === "APPROVE" || d.status === "APPROVED"
      );
      setDatasets(approved);
    } catch (err: any) {
      setError(err.message || "Failed to load datasets");
    } finally {
      setLoading(false);
    }
  }

  function formatBytes(bytes: number): string {
    if (!bytes || bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
  }

  return (
    <div style={{ padding: "40px 48px", maxWidth: "1200px", margin: "0 auto" }}>
      <div style={{ marginBottom: "28px" }}>
        <h1 style={{ fontSize: "24px", fontWeight: 700, color: "#111827" }}>
          Training Datasets
        </h1>
      </div>

      {loading && (
        <div style={{ padding: "32px", textAlign: "center", color: "#6b7280", fontSize: "14px" }}>
          Loading authorized datasets...
        </div>
      )}

      {error && (
        <div style={{
          padding: "16px",
          background: "#fef2f2",
          border: "1px solid #fee2e2",
          borderRadius: "6px",
          color: "#991b1b",
          fontSize: "14px",
          marginBottom: "24px",
        }}>
          {error}
        </div>
      )}

      {!loading && !error && datasets.length === 0 && (
        <div style={{
          padding: "48px 24px",
          textAlign: "center",
          border: "1px dashed #d1d5db",
          borderRadius: "8px",
          background: "#ffffff",
        }}>
          <div style={{ fontSize: "15px", fontWeight: 600, color: "#374151", marginBottom: "6px" }}>
            No authorized training datasets available
          </div>
          <div style={{ fontSize: "13px", color: "#6b7280", maxWidth: "480px", margin: "0 auto 20px" }}>
            Datasets must complete pre-training cryptographic verification, multi-agent threat intelligence, and policy approval before they can be authorized for training.
          </div>
          <a
            href="/"
            style={{
              display: "inline-block",
              background: "#111827",
              color: "#ffffff",
              padding: "8px 16px",
              borderRadius: "6px",
              fontSize: "13px",
              fontWeight: 500,
            }}
          >
            Go to Pipeline
          </a>
        </div>
      )}

      {!loading && !error && datasets.length > 0 && (
        <div style={{
          background: "#ffffff",
          border: "1px solid #e5e7eb",
          borderRadius: "8px",
          overflow: "hidden",
        }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "13px" }}>
            <thead>
              <tr style={{ background: "#f9fafb", borderBottom: "1px solid #e5e7eb", textAlign: "left" }}>
                <th style={{ padding: "12px 16px", fontWeight: 600, color: "#374151" }}>Dataset ID</th>
                <th style={{ padding: "12px 16px", fontWeight: 600, color: "#374151" }}>Version</th>
                <th style={{ padding: "12px 16px", fontWeight: 600, color: "#374151" }}>Filename</th>
                <th style={{ padding: "12px 16px", fontWeight: 600, color: "#374151" }}>Records</th>
                <th style={{ padding: "12px 16px", fontWeight: 600, color: "#374151" }}>Size</th>
                <th style={{ padding: "12px 16px", fontWeight: 600, color: "#374151" }}>Type</th>
                <th style={{ padding: "12px 16px", fontWeight: 600, color: "#374151" }}>Status</th>
                <th style={{ padding: "12px 16px", fontWeight: 600, color: "#374151", textAlign: "right" }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {datasets.map((d) => (
                <tr key={`${d.dataset_id}-v${d.version}`} style={{ borderBottom: "1px solid #f3f4f6" }}>
                  <td style={{ padding: "14px 16px", fontWeight: 600, color: "#111827", fontFamily: "monospace" }}>
                    {d.dataset_id}
                  </td>
                  <td style={{ padding: "14px 16px", color: "#4b5563" }}>
                    v{d.version}
                  </td>
                  <td style={{ padding: "14px 16px", fontWeight: 500, color: "#111827" }}>
                    {d.filename}
                  </td>
                  <td style={{ padding: "14px 16px", color: "#4b5563" }}>
                    {d.record_count ?? "—"}
                  </td>
                  <td style={{ padding: "14px 16px", color: "#6b7280" }}>
                    {formatBytes(d.file_size)}
                  </td>
                  <td style={{ padding: "14px 16px" }}>
                    <span style={{
                      padding: "2px 8px",
                      borderRadius: "4px",
                      fontSize: "11px",
                      fontWeight: 600,
                      background: "#f3f4f6",
                      color: "#374151",
                      textTransform: "uppercase",
                    }}>
                      {d.file_type || "CSV"}
                    </span>
                  </td>
                  <td style={{ padding: "14px 16px" }}>
                    <span style={{
                      display: "inline-block",
                      background: "#ecfdf5",
                      color: "#065f46",
                      fontSize: "11px",
                      fontWeight: 600,
                      padding: "3px 8px",
                      borderRadius: "4px",
                      border: "1px solid #a7f3d0",
                    }}>
                      Approved for Training
                    </span>
                  </td>
                  <td style={{ padding: "14px 16px", textAlign: "right" }}>
                    <a
                      href={`${API_BASE_URL}/api/datasets/${d.dataset_id}/versions/${d.version}/download`}
                      download
                      style={{
                        display: "inline-block",
                        background: "#111827",
                        color: "#ffffff",
                        padding: "6px 14px",
                        borderRadius: "5px",
                        fontSize: "12px",
                        fontWeight: 500,
                        textDecoration: "none",
                      }}
                    >
                      Download
                    </a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

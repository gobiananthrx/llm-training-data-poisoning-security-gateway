"use client";

import { useState, useEffect } from "react";

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
}

export default function DataCollectionPage() {
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [recentDatasets, setRecentDatasets] = useState<DatasetItem[]>([]);

  useEffect(() => {
    fetchRecentDatasets();
  }, []);

  async function fetchRecentDatasets() {
    try {
      const res = await fetch(`${API_BASE_URL}/api/datasets`);
      if (res.ok) {
        const data = await res.json();
        setRecentDatasets(data);
      }
    } catch {
      // ignore
    }
  }

  async function handleUpload() {
    if (!file) return;

    setUploading(true);
    setError(null);
    setResult(null);

    const form = new FormData();
    form.append("file", file);
    form.append("source", "data_collection_ingestion");
    form.append("description", "Raw enterprise dataset collection");

    try {
      const res = await fetch(`${API_BASE_URL}/api/datasets/upload`, {
        method: "POST",
        body: form,
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || "Upload failed");
      }

      setResult(data);
      fetchRecentDatasets();
    } catch (err: any) {
      setError(err.message || "Failed to upload and sign dataset");
    } finally {
      setUploading(false);
    }
  }

  return (
    <div style={{ maxWidth: 880, margin: "40px auto", padding: "0 24px" }}>
      {/* Header */}
      <div style={{ marginBottom: 28, paddingBottom: 16, borderBottom: "1px solid #e5e7eb" }}>
        <h2 style={{ fontSize: 20, fontWeight: 600, color: "#111827", marginBottom: 4 }}>
          Data Collection & Provenance Ingestion
        </h2>
        <p style={{ fontSize: 13, color: "#6b7280" }}>
          Upload raw datasets (CSV, JSON, TXT, XLSX). Single file at once. Content is canonicalized, hashed with SHA-256, and signed using Post-Quantum ML-DSA-65 before persistence.
        </p>
      </div>

      {/* Upload Box */}
      <div style={{
        background: "#ffffff",
        border: "1px solid #e5e7eb",
        borderRadius: 8,
        padding: 24,
        marginBottom: 32,
      }}>
        <div style={{
          border: "2px dashed #d1d5db",
          borderRadius: 6,
          padding: 32,
          textAlign: "center",
          background: "#f9fafb",
          marginBottom: 16,
        }}>
          <input
            type="file"
            id="file-input"
            accept=".csv,.json,.txt,.xlsx"
            disabled={uploading}
            onChange={(e) => {
              if (e.target.files?.[0]) {
                setFile(e.target.files[0]);
                setResult(null);
                setError(null);
              }
            }}
            style={{ display: "none" }}
          />
          <label
            htmlFor="file-input"
            style={{
              display: "inline-block",
              background: "#ffffff",
              border: "1px solid #d1d5db",
              padding: "8px 16px",
              borderRadius: 6,
              fontSize: 13,
              fontWeight: 500,
              color: "#374151",
              cursor: uploading ? "not-allowed" : "pointer",
              marginBottom: 8,
            }}
          >
            Select Dataset File (.csv, .json, .txt, .xlsx)
          </label>
          <div style={{ fontSize: 12, color: "#6b7280", marginTop: 4 }}>
            {file ? (
              <span style={{ color: "#111827", fontWeight: 500 }}>
                Selected: {file.name} ({(file.size / 1024).toFixed(1)} KB)
              </span>
            ) : (
              "Supports one file per upload: customer_support.csv, knowledge.json, operations.xlsx"
            )}
          </div>
        </div>

        <div style={{ display: "flex", justifyContent: "flex-end" }}>
          <button
            onClick={handleUpload}
            disabled={!file || uploading}
            style={{
              background: !file || uploading ? "#9ca3af" : "#111827",
              color: "#ffffff",
              border: "none",
              padding: "10px 20px",
              borderRadius: 6,
              fontSize: 13,
              fontWeight: 500,
              transition: "background 0.15s ease",
            }}
          >
            {uploading ? "Canonicalizing & Signing with ML-DSA-65..." : "Ingest & Sign Dataset"}
          </button>
        </div>

        {/* Error message */}
        {error && (
          <div style={{
            marginTop: 16,
            padding: 12,
            background: "#fef2f2",
            border: "1px solid #fecaca",
            borderRadius: 6,
            color: "#b91c1c",
            fontSize: 13,
          }}>
            {error}
          </div>
        )}

        {/* Upload success summary */}
        {result && (
          <div style={{
            marginTop: 20,
            padding: 16,
            background: "#f0fdf4",
            border: "1px solid #bbf7d0",
            borderRadius: 6,
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, color: "#15803d", fontWeight: 600, fontSize: 14, marginBottom: 12 }}>
              <span>✓</span> Dataset Ingested & Cryptographically Signed
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "140px 1fr", gap: "8px 12px", fontSize: 12 }}>
              <div style={{ color: "#4b5563" }}>Dataset ID:</div>
              <div style={{ fontFamily: "monospace", fontWeight: 600, color: "#111827" }}>{result.dataset_id}</div>

              <div style={{ color: "#4b5563" }}>Version:</div>
              <div style={{ fontWeight: 600, color: "#111827" }}>v{result.version}</div>

              <div style={{ color: "#4b5563" }}>SHA-256 Hash:</div>
              <div style={{ fontFamily: "monospace", wordBreak: "break-all", color: "#111827" }}>{result.sha256}</div>

              <div style={{ color: "#4b5563" }}>Signature Alg:</div>
              <div style={{ fontWeight: 600, color: "#111827" }}>{result.signature_algorithm} (Post-Quantum)</div>

              <div style={{ color: "#4b5563" }}>Signature:</div>
              <div style={{ fontFamily: "monospace", fontSize: 11, color: "#6b7280", wordBreak: "break-all" }}>
                {result.signature?.slice(0, 48)}...
              </div>

              <div style={{ color: "#4b5563" }}>Records:</div>
              <div style={{ color: "#111827" }}>{result.processing_summary?.record_count || result.processing_summary?.rows || "Parsed"}</div>
            </div>

            <div style={{ marginTop: 16, paddingTop: 12, borderTop: "1px solid #dcfce7", display: "flex", justifyContent: "flex-end" }}>
              <a
                href={`/?id=${result.dataset_id}&version=${result.version}`}
                style={{
                  background: "#15803d",
                  color: "#ffffff",
                  padding: "6px 14px",
                  borderRadius: 4,
                  fontSize: 12,
                  fontWeight: 500,
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 6,
                }}
              >
                Proceed to Verification & Gateway →
              </a>
            </div>
          </div>
        )}
      </div>

      {/* Ingested Datasets List */}
      <div>
        <h3 style={{ fontSize: 15, fontWeight: 600, color: "#374151", marginBottom: 12 }}>
          Ingested Datasets Registry
        </h3>
        {recentDatasets.length === 0 ? (
          <div style={{ fontSize: 13, color: "#9ca3af", fontStyle: "italic" }}>
            No datasets in registry yet.
          </div>
        ) : (
          <div style={{
            background: "#ffffff",
            border: "1px solid #e5e7eb",
            borderRadius: 8,
            overflow: "hidden",
          }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13, textAlign: "left" }}>
              <thead>
                <tr style={{ background: "#f9fafb", borderBottom: "1px solid #e5e7eb", color: "#4b5563" }}>
                  <th style={{ padding: "10px 16px", fontWeight: 600 }}>Dataset ID</th>
                  <th style={{ padding: "10px 16px", fontWeight: 600 }}>File</th>
                  <th style={{ padding: "10px 16px", fontWeight: 600 }}>Ver</th>
                  <th style={{ padding: "10px 16px", fontWeight: 600 }}>Status</th>
                  <th style={{ padding: "10px 16px", fontWeight: 600, textAlign: "right" }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {recentDatasets.map((ds) => (
                  <tr key={ds.dataset_id} style={{ borderBottom: "1px solid #f3f4f6" }}>
                    <td style={{ padding: "10px 16px", fontFamily: "monospace", fontWeight: 600 }}>
                      {ds.dataset_id}
                    </td>
                    <td style={{ padding: "10px 16px", color: "#374151" }}>
                      {ds.filename}
                    </td>
                    <td style={{ padding: "10px 16px" }}>v{ds.version}</td>
                    <td style={{ padding: "10px 16px" }}>
                      <span style={{
                        display: "inline-block",
                        padding: "2px 8px",
                        borderRadius: 4,
                        fontSize: 11,
                        fontWeight: 600,
                        background:
                          ds.status === "APPROVED"
                            ? "#dcfce7"
                            : ds.status === "QUARANTINED"
                            ? "#fef3c7"
                            : ds.status === "BLOCKED" || ds.status === "REJECTED"
                            ? "#fee2e2"
                            : "#e5e7eb",
                        color:
                          ds.status === "APPROVED"
                            ? "#15803d"
                            : ds.status === "QUARANTINED"
                            ? "#b45309"
                            : ds.status === "BLOCKED" || ds.status === "REJECTED"
                            ? "#b91c1c"
                            : "#374151",
                      }}>
                        {ds.status}
                      </span>
                    </td>
                    <td style={{ padding: "10px 16px", textAlign: "right" }}>
                      <a
                        href={`/?id=${ds.dataset_id}&version=${ds.version}`}
                        style={{ color: "#2563eb", fontWeight: 500, fontSize: 12 }}
                      >
                        Verify in Gateway →
                      </a>
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

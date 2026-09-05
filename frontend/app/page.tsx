"use client";

import { useState } from "react";

const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";

export default function Home() {
  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  async function upload() {
    if (!file) return;

    setLoading(true);
    setResult(null);

    const form = new FormData();
    form.append("file", file);
    form.append("source", "user_upload");
    form.append("description", "Prototype dataset");

    try {
      const response = await fetch(`${API_BASE_URL}/api/datasets/upload`, {
        method: "POST",
        body: form,
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "Upload failed");
      }

      setResult(data);
    } catch (error) {
      setResult({
        error: error instanceof Error ? error.message : "Upload failed",
      });
    } finally {
      setLoading(false);
    }
  }

  return (
    <main style={{ maxWidth: 900, margin: "60px auto", padding: 24, fontFamily: "Arial" }}>
      <h1>Dataset Security Gateway</h1>
      <p>Upload a training dataset to begin the security lifecycle.</p>

      <input
        type="file"
        accept=".csv,.json,.txt,.xlsx"
        onChange={(e) => setFile(e.target.files?.[0] ?? null)}
      />

      <div style={{ marginTop: 20 }}>
        <button onClick={upload} disabled={!file || loading}>
          {loading ? "Processing..." : "Upload Dataset"}
        </button>
      </div>

      {result && (
        <pre style={{ marginTop: 30, padding: 20, background: "#f4f4f4", overflow: "auto" }}>
          {JSON.stringify(result, null, 2)}
        </pre>
      )}
    </main>
  );
}

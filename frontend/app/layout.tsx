import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Dataset Security Gateway",
  description: "Post-Quantum Cryptographic Provenance & Multi-Agent Threat Intelligence",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <head>
        <meta charSet="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <style>{`
          *, *::before, *::after {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
          }
          body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: #fcfcfc;
            color: #111827;
            line-height: 1.5;
            -webkit-font-smoothing: antialiased;
          }
          a {
            color: inherit;
            text-decoration: none;
          }
          button {
            cursor: pointer;
            font-family: inherit;
          }
          input, select, textarea {
            font-family: inherit;
          }
        `}</style>
      </head>
      <body>
        <div style={{ minHeight: "100vh", display: "flex", flexDirection: "column" }}>
          {/* Minimal Top Bar - No logo, no generic title, pure minimal tabs */}
          <nav style={{
            borderBottom: "1px solid #e5e7eb",
            background: "#ffffff",
            padding: "0 24px",
            display: "flex",
            alignItems: "center",
            height: "52px",
            gap: "28px",
            fontSize: "14px",
            fontWeight: 500,
          }}>
            <a href="/" style={{
              display: "flex",
              alignItems: "center",
              gap: "8px",
              color: "#111827",
              fontWeight: 600,
              padding: "16px 0",
              borderBottom: "2px solid #111827",
            }}>
              Verification & Gateway
            </a>
            <a href="/data-collection" style={{
              color: "#6b7280",
              padding: "16px 0",
            }}>
              Data Collection (Ingestion)
            </a>
            <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: "16px", fontSize: "12px", color: "#6b7280" }}>
              <span style={{ display: "inline-flex", alignItems: "center", gap: "6px" }}>
                <span style={{ width: 8, height: 8, borderRadius: "50%", background: "#10b981" }}></span>
                ML-DSA-65 Active
              </span>
            </div>
          </nav>
          <div style={{ flex: 1 }}>
            {children}
          </div>
        </div>
      </body>
    </html>
  );
}

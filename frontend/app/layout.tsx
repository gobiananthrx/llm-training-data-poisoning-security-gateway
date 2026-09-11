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
            background-color: #fbfbfb;
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
          @keyframes progress-stripe {
            0% { background-position: 0 0; }
            100% { background-position: 30px 0; }
          }
          .running-progress {
            background-image: linear-gradient(
              -45deg,
              rgba(255, 255, 255, 0.25) 25%,
              transparent 25%,
              transparent 50%,
              rgba(255, 255, 255, 0.25) 50%,
              rgba(255, 255, 255, 0.25) 75%,
              transparent 75%,
              transparent
            );
            background-size: 30px 30px;
            animation: progress-stripe 1.2s linear infinite;
          }
        `}</style>
      </head>
      <body>
        <div style={{ minHeight: "100vh", display: "flex" }}>
          {/* Sidebar */}
          <aside style={{
            width: "230px",
            minWidth: "230px",
            borderRight: "1px solid #e5e7eb",
            background: "#ffffff",
            display: "flex",
            flexDirection: "column",
            position: "sticky",
            top: 0,
            height: "100vh",
            padding: "24px 16px",
          }}>
            <div style={{
              fontSize: "12px",
              fontWeight: 700,
              letterSpacing: "0.08em",
              color: "#374151",
              marginBottom: "32px",
              paddingLeft: "8px",
            }}>
              SECURITY GATEWAY
            </div>

            <nav style={{ display: "flex", flexDirection: "column", gap: "6px", flex: 1 }}>
              <a href="/dashboard" style={{
                display: "flex",
                alignItems: "center",
                padding: "9px 12px",
                borderRadius: "6px",
                fontSize: "14px",
                fontWeight: 500,
                color: "#4b5563",
                background: "transparent",
                transition: "background 0.15s ease",
              }}>
                Dashboard
              </a>
              <a href="/" style={{
                display: "flex",
                alignItems: "center",
                padding: "9px 12px",
                borderRadius: "6px",
                fontSize: "14px",
                fontWeight: 500,
                color: "#111827",
                background: "transparent",
                transition: "background 0.15s ease",
              }}>
                Pipeline
              </a>
              <a href="/training-datasets" style={{
                display: "flex",
                alignItems: "center",
                padding: "9px 12px",
                borderRadius: "6px",
                fontSize: "14px",
                fontWeight: 500,
                color: "#4b5563",
                background: "transparent",
                transition: "background 0.15s ease",
              }}>
                Training Datasets
              </a>
            </nav>

            <div style={{
              borderTop: "1px solid #f3f4f6",
              paddingTop: "16px",
              display: "flex",
              alignItems: "center",
              gap: "8px",
              fontSize: "12px",
              color: "#6b7280",
            }}>
              <span style={{ width: 7, height: 7, borderRadius: "50%", background: "#10b981", display: "inline-block" }}></span>
              <span>ML-DSA-65 Active</span>
            </div>
          </aside>

          {/* Main Content View */}
          <main style={{ flex: 1, overflowX: "auto", minWidth: 0 }}>
            {children}
          </main>
        </div>
      </body>
    </html>
  );
}

"use client";

import { useState } from "react";

export default function Home() {
  const [token, setToken] = useState("");
  const [roles, setRoles] = useState("user");
  const [out, setOut] = useState("");
  const [err, setErr] = useState("");

  async function whoami() {
    setErr("");
    setOut("");
    const res = await fetch("/api/whoami", {
      headers: { Authorization: `Bearer ${token}` },
    });
    const json = await res.json();
    if (!res.ok) setErr(JSON.stringify(json, null, 2));
    else setOut(JSON.stringify(json, null, 2));
  }

  async function checkAuthz() {
    setErr("");
    setOut("");
    const res = await fetch("/api/authorize", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        roles: roles.split(",").map((r) => r.trim()).filter(Boolean),
      }),
    });
    const json = await res.json();
    if (!res.ok) setErr(JSON.stringify(json, null, 2));
    else setOut(JSON.stringify(json, null, 2));
  }

  return (
    <main
      style={{
        maxWidth: 640,
        margin: "2rem auto",
        padding: "1.5rem",
        background: "#fff",
        borderRadius: 12,
        boxShadow: "0 1px 3px rgb(0 0 0 / 8%)",
      }}
    >
      <h1 style={{ fontSize: "1.25rem" }}>A2 Next.js BFF sample</h1>
      <p style={{ color: "#64748b", fontSize: "0.9rem" }}>
        UI → <code>/api/*</code> → gRPC sidecar. Paste a JWT issued by your A2 JWT provider.
      </p>

      <label style={{ display: "block", fontWeight: 600, marginTop: 12 }}>Bearer token</label>
      <textarea
        value={token}
        onChange={(e) => setToken(e.target.value)}
        rows={4}
        style={{ width: "100%", boxSizing: "border-box", marginTop: 4 }}
        placeholder="eyJhbGciOi..."
      />

      <label style={{ display: "block", fontWeight: 600, marginTop: 12 }}>
        Roles for Authorize (comma-separated)
      </label>
      <input
        value={roles}
        onChange={(e) => setRoles(e.target.value)}
        style={{ width: "100%", boxSizing: "border-box", marginTop: 4 }}
      />

      <div style={{ display: "flex", gap: 8, marginTop: 16 }}>
        <button type="button" onClick={whoami} disabled={!token.trim()}>
          GET /api/whoami
        </button>
        <button type="button" onClick={checkAuthz} disabled={!token.trim()}>
          POST /api/authorize
        </button>
      </div>

      {err && (
        <pre style={{ background: "#fef2f2", color: "#991b1b", padding: 12, marginTop: 16 }}>
          {err}
        </pre>
      )}
      {out && (
        <pre style={{ background: "#0f172a", color: "#e2e8f0", padding: 12, marginTop: 16 }}>
          {out}
        </pre>
      )}
    </main>
  );
}

import { useState } from "react";
import { fetchOrders, type AuthMode } from "./api";

export function App() {
  const [mode, setMode] = useState<AuthMode>("bearer");
  const [credential, setCredential] = useState("");
  const [merchantId, setMerchantId] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<string>("");
  const [error, setError] = useState<string>("");

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");
    setResult("");
    try {
      const { status, body } = await fetchOrders({
        mode,
        credential,
        merchantId,
      });
      setResult(JSON.stringify({ status, body }, null, 2));
      if (status === 401 || status === 403) {
        setError(`A2 denied the request (HTTP ${status}). Check token/key and roles.`);
      }
    } catch (err: any) {
      setError(err?.message ?? String(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <main>
      <h1>A2 React HTTP client</h1>
      <p className="hint">
        Calls a Java API protected by <code>@A2Protected</code>. Does not use the
        gRPC sidecar from the browser.
      </p>

      <form onSubmit={onSubmit}>
        <label htmlFor="mode">Auth mode</label>
        <select
          id="mode"
          value={mode}
          onChange={(e) => setMode(e.target.value as AuthMode)}
        >
          <option value="bearer">Authorization: Bearer (JWT / OIDC)</option>
          <option value="apiKey">X-API-Key</option>
        </select>

        <label htmlFor="cred">
          {mode === "bearer" ? "Access token" : "API key"}
        </label>
        <input
          id="cred"
          value={credential}
          onChange={(e) => setCredential(e.target.value)}
          placeholder={mode === "bearer" ? "eyJhbGciOi..." : "prod-key-..."}
          autoComplete="off"
        />

        <label htmlFor="merchant">X-Merchant-Id (optional)</label>
        <input
          id="merchant"
          value={merchantId}
          onChange={(e) => setMerchantId(e.target.value)}
          placeholder="merchant-42"
        />

        <button type="submit" disabled={loading || !credential.trim()}>
          {loading ? "Calling /api/orders…" : "GET /api/orders"}
        </button>
      </form>

      {error && <p className="err">{error}</p>}
      {result && <pre>{result}</pre>}
    </main>
  );
}

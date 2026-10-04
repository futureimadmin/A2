const API_BASE = import.meta.env.VITE_API_BASE ?? "http://localhost:8080";

export type AuthMode = "bearer" | "apiKey";

export async function fetchOrders(opts: {
  mode: AuthMode;
  credential: string;
  merchantId?: string;
}): Promise<{ status: number; body: unknown }> {
  const headers: Record<string, string> = {
    Accept: "application/json",
  };

  if (opts.mode === "bearer") {
    headers.Authorization = `Bearer ${opts.credential}`;
  } else {
    headers["X-API-Key"] = opts.credential;
  }

  if (opts.merchantId?.trim()) {
    headers["X-Merchant-Id"] = opts.merchantId.trim();
  }

  const res = await fetch(`${API_BASE}/api/orders`, { headers });
  let body: unknown;
  const text = await res.text();
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = text;
  }
  return { status: res.status, body };
}

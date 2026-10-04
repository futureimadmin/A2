import { createA2Client, promisify } from "../../../lib/a2Client";

export const runtime = "nodejs";

export async function GET(request: Request) {
  const header = request.headers.get("authorization") ?? "";
  const token = header.replace(/^Bearer\s+/i, "").trim();
  if (!token) {
    return Response.json({ error: "Missing Authorization: Bearer token" }, { status: 401 });
  }

  try {
    const client = createA2Client();
    const auth = await promisify<any>((cb) =>
      client.Authenticate(
        {
          protocol: "JWT",
          credentials: token,
          headers: { authorization: `Bearer ${token}` },
        },
        cb
      )
    );

    if (!auth.success) {
      return Response.json({ error: auth.error || "unauthorized" }, { status: 401 });
    }

    return Response.json({
      principalId: auth.principal_id,
      principalName: auth.principal_name,
      roles: auth.roles ?? [],
      permissions: auth.permissions ?? [],
    });
  } catch (e: any) {
    return Response.json(
      {
        error: e?.message ?? String(e),
        hint: "Is a2-sidecar running? Set A2_SIDECAR=host:port",
      },
      { status: 502 }
    );
  }
}

import { createA2Client, promisify } from "../../../lib/a2Client";

export const runtime = "nodejs";

export async function POST(request: Request) {
  const header = request.headers.get("authorization") ?? "";
  const token = header.replace(/^Bearer\s+/i, "").trim();
  if (!token) {
    return Response.json({ error: "Missing Bearer token" }, { status: 401 });
  }

  let body: { roles?: string[]; permissions?: string[] } = {};
  try {
    body = await request.json();
  } catch {
    body = {};
  }

  const roles = body.roles ?? ["user"];
  const permissions = body.permissions ?? [];

  try {
    const client = createA2Client();

    const auth = await promisify<any>((cb) =>
      client.Authenticate(
        { protocol: "JWT", credentials: token, headers: { authorization: `Bearer ${token}` } },
        cb
      )
    );
    if (!auth.success) {
      return Response.json({ error: auth.error || "unauthorized" }, { status: 401 });
    }

    const authz = await promisify<any>((cb) =>
      client.Authorize(
        {
          principal_id: auth.principal_id,
          required_roles: roles,
          required_permissions: permissions,
          require_all: false,
          protocol: "JWT",
        },
        cb
      )
    );

    if (!authz.allowed) {
      return Response.json({ allowed: false, reason: authz.reason }, { status: 403 });
    }

    return Response.json({
      allowed: true,
      principalId: auth.principal_id,
      checkedRoles: roles,
    });
  } catch (e: any) {
    return Response.json({ error: e?.message ?? String(e) }, { status: 502 });
  }
}

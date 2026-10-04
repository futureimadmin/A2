/**
 * Sample 1: Node/TypeScript → A2 gRPC sidecar
 *
 * Env:
 *   A2_SIDECAR  default localhost:50051
 *   A2_TOKEN    JWT (or other) credential string
 *   A2_PROTO    optional path to a2.proto
 */
import { authenticate, authorize, createA2Client, issueToken } from "./a2Client.js";

async function main() {
  const token = process.env.A2_TOKEN ?? "";
  const client = createA2Client();

  console.log("→ A2 sidecar Authenticate (JWT)...");
  if (!token) {
    console.warn(
      "No A2_TOKEN set. Calling Authenticate anyway to show error path from sidecar."
    );
  }

  try {
    const auth = await authenticate(client, token || "invalid");
    if (!auth.success) {
      console.error("Authenticate failed:", auth.error);
      console.log(
        "Tip: start the sidecar, register a JWT provider, issue a token, then set A2_TOKEN."
      );
      process.exitCode = 1;
      return;
    }

    console.log("Principal:", auth.principal_id, auth.principal_name);
    console.log("Roles:", auth.roles);
    console.log("Permissions:", auth.permissions);

    console.log("→ Authorize roles=['user']...");
    const authz = await authorize(client, auth.principal_id, ["user"]);
    if (!authz.allowed) {
      console.error("Authorize denied:", authz.reason);
      process.exitCode = 1;
      return;
    }
    console.log("Authorize allowed");

    console.log("→ IssueToken TEMPORARY (demo)...");
    const issued = await issueToken(client, auth.principal_id, "demo-service");
    if (!issued.success) {
      console.error("IssueToken failed:", issued.error);
      process.exitCode = 1;
      return;
    }
    console.log("Issued token_id:", issued.token_id);
    console.log("Token (truncated):", (issued.token ?? "").slice(0, 48) + "…");
  } catch (e) {
    console.error("gRPC error — is the sidecar running on", process.env.A2_SIDECAR ?? "localhost:50051", "?");
    console.error(e);
    process.exitCode = 1;
  }
}

main();

import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export type AuthResult = {
  success: boolean;
  principal_id: string;
  principal_name: string;
  roles: string[];
  permissions: string[];
  error?: string;
};

export type AuthorizeResult = {
  allowed: boolean;
  reason?: string;
};

export type TokenResult = {
  success: boolean;
  token?: string;
  token_id?: string;
  expires_at_epoch?: string | number;
  error?: string;
};

function resolveProtoPath(): string {
  if (process.env.A2_PROTO) return process.env.A2_PROTO;
  // examples/01-node-ts-sidecar/src -> repo a2-sidecar proto
  return path.resolve(
    __dirname,
    "../../../a2-sidecar/src/main/proto/a2.proto"
  );
}

export function createA2Client(address = process.env.A2_SIDECAR ?? "localhost:50051") {
  const packageDefinition = protoLoader.loadSync(resolveProtoPath(), {
    keepCase: true,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true,
  });
  const proto = grpc.loadPackageDefinition(packageDefinition) as any;
  const Client = proto.a2.A2Service;
  return new Client(address, grpc.credentials.createInsecure()) as grpc.Client & {
    Authenticate: Function;
    Authorize: Function;
    IssueToken: Function;
    RevokeToken: Function;
    Introspect: Function;
  };
}

export function authenticate(
  client: ReturnType<typeof createA2Client>,
  token: string,
  protocol = "JWT"
): Promise<AuthResult> {
  return new Promise((resolve, reject) => {
    client.Authenticate(
      {
        protocol,
        credentials: token,
        headers: { authorization: `Bearer ${token}` },
      },
      (err: Error | null, resp: AuthResult) => {
        if (err) reject(err);
        else resolve(resp);
      }
    );
  });
}

export function authorize(
  client: ReturnType<typeof createA2Client>,
  principalId: string,
  requiredRoles: string[],
  requiredPermissions: string[] = []
): Promise<AuthorizeResult> {
  return new Promise((resolve, reject) => {
    client.Authorize(
      {
        principal_id: principalId,
        required_roles: requiredRoles,
        required_permissions: requiredPermissions,
        require_all: false,
        protocol: "JWT",
      },
      (err: Error | null, resp: AuthorizeResult) => {
        if (err) reject(err);
        else resolve(resp);
      }
    );
  });
}

export function issueToken(
  client: ReturnType<typeof createA2Client>,
  principalId: string,
  audience: string,
  ttlSeconds = 3600
): Promise<TokenResult> {
  return new Promise((resolve, reject) => {
    client.IssueToken(
      {
        type: "TEMPORARY",
        principal_id: principalId,
        scopes: ["demo:read"],
        ttl_seconds: ttlSeconds,
        protocol: "JWT",
        claims: { aud: audience, token_use: "instant_service" },
      },
      (err: Error | null, resp: TokenResult) => {
        if (err) reject(err);
        else resolve(resp);
      }
    );
  });
}

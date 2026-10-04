# A2 — Annotation-driven Identity & Access Management

[![CI](https://github.com/futureimadmin/A2/actions/workflows/ci.yml/badge.svg)](https://github.com/futureimadmin/A2/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**A2** (“Auth Anywhere”) unifies OAuth2, OIDC, SAML, Kerberos, API Keys, JWT, and multi-IdP SSO behind one annotation model and one runtime. Issue, rotate, and revoke tokens; enforce AuthN/AuthZ; assume roles and impersonate — without locking into a single IdP or cloud.

```java
@A2Protected(protocols = {Protocol.OIDC, Protocol.JWT, Protocol.API_KEY}, roles = {"user"})
@A2Authorize(permissions = {"order:read"})
public class OrderService { ... }
```

**Version:** `1.0.0` · **Java:** 17+ · **groupId:** `com.futureim.a2` · **Integrations:** Spring Boot 3, Quarkus 3, gRPC sidecar (Python, Go, **Node / TypeScript / React**, …)

---

## Table of contents

1. [Architecture at a glance](#architecture-at-a-glance)
2. [Quick start (Java)](#quick-start-java)
3. [Annotations overview](#annotations-overview)
4. [Multi-protocol & multi-tenant AuthN](#multi-protocol--multi-tenant-authn)
5. [Instant credentials (≤ 1 hour)](#instant-credentials--1-hour)
6. [How to use — JWT / OIDC / API Key / SAML / Kerberos / SSO](#how-to-use--by-protocol)
7. [Assume Role, Impersonation & S2S](#assume-role-impersonation--s2s)
8. [Token lifecycle & stores](#token-lifecycle--stores)
9. [Spring Boot](#spring-boot)
10. [Quarkus](#quarkus)
11. [**Using A2 from Python and other languages**](#using-a2-from-python-and-other-languages)
12. [**Node / TypeScript / React + sidecar how-to**](#node--typescript--react--sidecar-how-to)
13. [gRPC sidecar reference](#grpc-sidecar-reference)
14. [Testing notes](#testing-notes)
15. [Quality — SonarLint & SonarQube](#quality--sonarlint--sonarqube)
16. [Build](#build)
17. [License](#license)

---

## Architecture at a glance

| Layer | Role |
|-------|------|
| **Annotations** (`a2-annotations`) | Declarative policy: who may call what, which protocols, roles, TTL |
| **SPI** (`a2-spi`) | `ProtocolProvider`, `TokenService`, `TokenStore`, credential models |
| **Core** (`a2-core`) | `A2Runtime`, `RequestAuthenticator`, interceptor, instant credentials |
| **Providers** | JWT, OIDC, SAML, API Key, Kerberos, SSO (Okta/Entra/Google/…) |
| **Spring / Quarkus** | HTTP filters, AOP/CDI interceptors, CORS, 401/403 mapping |
| **Sidecar** (`a2-sidecar`) | Same engine over **gRPC** for Python, Go, Node, TypeScript, React backends, Rust, … |

**Important for non-JVM apps:** Java annotations are a *policy language on the JVM*. Node / TypeScript / React / Python do **not** embed `@A2Protected` in source. They either:

1. **Call the A2 sidecar** (gRPC) — `Authenticate` / `Authorize` / `IssueToken` / … map 1:1 to the same engine, or  
2. **Call a Java/Spring/Quarkus service** that is already annotated — send `Authorization` / `X-API-Key` / merchant headers; A2 enforces policy on the server.

```
┌──────────────────┐   gRPC    ┌──────────────┐    SPI     ┌────────────┐
│ Node / TS / React│ ────────► │  a2-sidecar  │ ─────────► │ Providers  │
│ Python / Go / …  │           │  A2Service   │            │ JWT OIDC…  │
└──────────────────┘           └──────────────┘            └────────────┘
                                      │
┌──────────────────┐ annotations ┌────▼────────┐
│ Spring / Quarkus │ ──────────► │  A2Runtime  │
│ Java app         │             │  Interceptor│
└──────────────────┘             └─────────────┘
```

---

## Quick start (Java)

```xml
<dependency>
  <groupId>com.futureim.a2</groupId>
  <artifactId>a2-core</artifactId>
  <version>1.0.0</version>
</dependency>
<dependency>
  <groupId>com.futureim.a2</groupId>
  <artifactId>a2-provider-jwt</artifactId>
  <version>1.0.0</version>
</dependency>
```

```java
import io.a2.core.A2Runtime;
import io.a2.provider.jwt.JwtProtocolProvider;
import io.a2.core.store.InMemoryTokenStore;

A2Runtime.get().register(new JwtProtocolProvider(
    "your-secret-at-least-32-bytes-long!!!!!!!!",
    "https://issuer.example.com",
    new InMemoryTokenStore()));
```

```java
@A2Protected(protocols = Protocol.JWT, roles = {"admin"})
public void deleteUser(String id) { ... }
```

Client: `Authorization: Bearer <jwt>`.

---

## Annotations overview

| Annotation | Purpose |
|------------|---------|
| `@A2Protected` | Require AuthN; optional roles, permissions, allowed `protocols`, `allowAnonymous` |
| `@A2Authorize` | Fine-grained AuthZ (roles / permissions / `requireAll`) |
| `@A2Authenticate` | Explicit AuthN entry |
| `@A2Token` / `@A2Rotate` / `@A2Revoke` | Token issue / rotate / revoke policy |
| `@A2InstantCredentials` | **Unified** temp creds ≤ 1h: `SERVICE` · `ASSUME_ROLE` · `IMPERSONATE` |
| `@A2AssumeRole` | AWS-style assume role (alias of instant ASSUME_ROLE) |
| `@A2Impersonate` | GCP-style source→target impersonation (alias of IMPERSONATE) |
| `@A2ServiceCredential` / `@A2TemporaryCredential` | S2S temp token (alias of SERVICE) |
| `@A2Sso` / `@A2OktaSso` / `@A2EntraSso` / … | Brand SSO binding helpers |
| `@A2Principal` / `@A2Context` | Inject principal / security context |

`Protocol`: `JWT`, `OIDC`, `OAUTH2`, `SAML`, `KERBEROS`, `API_KEY`, `SSO`, `MTLS`, `TLS`, `BASIC`, `CUSTOM`.

`InstantMode`: `SERVICE`, `ASSUME_ROLE`, `IMPERSONATE` (TTL hard-capped at **3600** seconds).

---

## Multi-protocol & multi-tenant AuthN

### Multiple protocols on one endpoint

```java
@A2Protected(protocols = {Protocol.OIDC, Protocol.JWT, Protocol.API_KEY})
public void onboardMerchant(...) { ... }
```

**Who authenticates?**  
`CredentialExtractor` reads headers → preferred protocol → `RequestAuthenticator` tries **preferred first**, then a safe fallback chain (JWT → OIDC → SSO → …). The first successful registered `ProtocolProvider` wins. CORS `OPTIONS` is skipped by the auth filter.

| Header | Effect |
|--------|--------|
| `Authorization: Bearer …` | JWT / OIDC / SSO (shape + optional SSO name) |
| `X-API-Key` / `Authorization: ApiKey …` | API_KEY |
| `Authorization: Negotiate …` | KERBEROS |
| `X-A2-SSO-Provider: okta` | Prefer named / SSO provider |
| `X-Merchant-Id: acme` | Multi-tenant: resolve **named** provider `acme` |

### Multi-tenant shared endpoint

```java
// Startup: one IdP (or config) per merchant
A2Runtime.get().registerNamed("merchant-1", SsoProviderFactory.okta(...));
A2Runtime.get().registerNamed("merchant-2", SsoProviderFactory.entra(...));

@A2Protected(protocols = Protocol.SSO, roles = {"merchant"})
public void onboardMerchant() { ... }
```

Client sends `X-Merchant-Id: merchant-1` (or `X-A2-SSO-Provider`) plus Bearer credentials. AuthN uses that merchant’s provider only.

Typed failures: `A2AuthenticationException` → **401**, `A2AuthorizationException` → **403**.

More detail: [docs/HTTP_SECURITY.md](docs/HTTP_SECURITY.md).

---

## Instant credentials (≤ 1 hour)

One annotation for AWS-style assume-role, GCP-style impersonation, and S2S service tokens:

```java
// Service-to-service
@A2InstantCredentials(mode = InstantMode.SERVICE, audience = "payment-service",
        scopes = {"payment:charge"}, ttlSeconds = 3600)
public TokenResult paymentToken() { ... }

// Assume role
@A2InstantCredentials(mode = InstantMode.ASSUME_ROLE, role = "billing-admin",
        sessionName = "nightly-job")
public TokenResult assumeBilling() { ... }

// Impersonate: source = authenticated caller, target = method argument
@A2InstantCredentials(mode = InstantMode.IMPERSONATE,
        targetPrincipalParam = "targetSa", reason = "batch-job")
public TokenResult asTarget(String targetSa) { ... }
```

Programmatic:

```java
InstantCredentialsService svc = new DefaultInstantCredentialsService(tokens, store);
TokenResult r = svc.issue(InstantCredentialsRequest.builder(InstantMode.IMPERSONATE)
    .callerPrincipalId("source-sa@project.iam.gserviceaccount.com")
    .targetPrincipalId("target-sa@project.iam.gserviceaccount.com")
    .reason("batch-job")
    .ttlSeconds(3600)
    .build());
```

See [docs/INSTANT_CREDENTIALS.md](docs/INSTANT_CREDENTIALS.md).

---

## How to use — by protocol

### JWT (`a2-provider-jwt`)

```java
JwtProtocolProvider jwt = new JwtProtocolProvider(secret, issuer, tokenStore);
A2Runtime.get().register(jwt);

@A2Protected(protocols = Protocol.JWT, roles = {"user"})
public Order getOrder(String id) { ... }
```

Issue: `jwt.issueToken(TokenRequest.builder().principalId("alice").type(TokenType.ACCESS).ttlSeconds(3600).build())`.

### OIDC (`a2-provider-oidc`)

Discovery + JWKS + Auth Code/PKCE helpers:

```java
OidcDiscoveryDocument doc = new OidcDiscoveryClient().discover("https://login.example.com");
A2Runtime.get().register(new OidcProtocolProvider(doc, clientId, clientSecret, store));
```

### API Key (`a2-provider-apikey`)

```java
ApiKeyProtocolProvider keys = new ApiKeyProtocolProvider();
keys.registerKey("prod-key", "svc-1", Set.of("admin"), Set.of("api:write"));
A2Runtime.get().register(keys);

@A2Protected(protocols = Protocol.API_KEY)
public void handleWebhook(...) { ... }
```

Headers: `X-API-Key: …` or `Authorization: ApiKey …`.

### SAML / Kerberos

See [docs/OIDC_DISCOVERY_AND_SAML_VALIDATION.md](docs/OIDC_DISCOVERY_AND_SAML_VALIDATION.md) and [docs/OPENSAML_AND_METADATA.md](docs/OPENSAML_AND_METADATA.md). Kerberos uses GSS/SPNEGO (`Authorization: Negotiate …`).

### SSO brands (Okta, Entra, Google, …)

```java
A2Runtime.get().register(SsoProviderFactory.okta("mycompany.okta.com", clientId, secret));
A2Runtime.get().registerNamed("acme", SsoProviderFactory.entra(tenantId, clientId, secret));
```

Issuer templates live in `SsoIssuerTemplates`. **Live IdP round-trips** (real Okta tokens) need your tenant credentials or WireMock contract tests; unit tests cover discovery/templates/factory and in-process pipeline stubs.

---

## Assume Role, Impersonation & S2S

| Mechanism | Annotation | Cloud analogy |
|-----------|------------|----------------|
| Assume role | `@A2AssumeRole` / `@A2InstantCredentials(ASSUME_ROLE)` | AWS STS |
| Impersonate | `@A2Impersonate` / `@A2InstantCredentials(IMPERSONATE)` | GCP SA (source → target) |
| Service token | `@A2ServiceCredential` / `SERVICE` mode | Workload / S2S |

All temporary credentials are **hard-capped at 1 hour**.

---

## Token lifecycle & stores

```java
provider.issueToken(request);
provider.rotateToken(request);
provider.revokeToken(RevokeRequest.builder().tokenId(jti).build());
```

| Store | Factory key |
|-------|-------------|
| In-memory | `memory` |
| JDBC | `jdbc` |
| Redis / Valkey | `redis` |
| Vault / OpenBao | `vault` |
| GCP / AWS / Azure secrets | `gcp-secretmanager`, `aws-secretsmanager`, `azure-keyvault` |

[docs/TOKEN_STORES.md](docs/TOKEN_STORES.md)

---

## Spring Boot

```xml
<dependency>
  <groupId>com.futureim.a2</groupId>
  <artifactId>a2-spring-boot-starter</artifactId>
  <version>1.0.0</version>
</dependency>
```

```yaml
a2:
  auth:
    filter-enabled: true
    fail-on-invalid-credentials: true
  cors:
    enabled: true
    allowed-origins: ["https://app.example.com"]
```

- Servlet **AuthN filter** (skips `OPTIONS`)
- **AOP** aspect for `@A2Protected` / `@A2Authorize` / instant credentials
- Exception handler maps 401 / 403

---

## Quarkus

```xml
<dependency>
  <groupId>com.futureim.a2</groupId>
  <artifactId>a2-quarkus-extension</artifactId>
  <version>1.0.0</version>
</dependency>
```

CDI interceptor + JAX-RS exception mapper; native-image reflect config under `META-INF/native-image/io.a2/`. See [docs/NATIVE_IMAGE.md](docs/NATIVE_IMAGE.md).

---

## Using A2 from Python and other languages

### Mental model

| On JVM | Outside JVM (Python, Go, Node, TypeScript, React, …) |
|--------|------------------------------------------------------|
| Put **annotations** on methods/classes | **No annotations** in source |
| Interceptor enforces policy in-process | Call **gRPC sidecar** *or* send credentials to an annotated Java API |

Annotations express *intent* (“this operation needs OIDC + role `admin`”). The **sidecar exposes the same operations** as RPCs so any language can enforce equivalent rules.

### Pattern A — Call the A2 sidecar (recommended for polyglot)

1. Run the sidecar:

```bash
java -jar a2-sidecar/target/a2-sidecar-1.0.0.jar --port 50051
```

2. Generate stubs from [`a2-sidecar/src/main/proto/a2.proto`](a2-sidecar/src/main/proto/a2.proto) (see language sections below).

3. Call `Authenticate` → `Authorize` → optional `IssueToken` / `RevokeToken` / `Introspect`.

### Pattern B — Client of an annotated Java API

Keep policy on the JVM; your app only attaches headers:

```python
import requests

r = requests.post(
    "https://api.example.com/merchants/onboard",
    headers={
        "X-API-Key": api_key,
        "X-Merchant-Id": "merchant-42",
    },
    json={"name": "Acme"},
)
r.raise_for_status()  # 401 / 403 from A2
```

Same idea works from `fetch` in the browser or Node `axios` / `undici`.

### Mapping annotations → gRPC (cheat sheet)

| Java annotation intent | Sidecar RPC |
|------------------------|-------------|
| `@A2Protected` / AuthN filter | `Authenticate` |
| `@A2Authorize` / roles on protected | `Authorize` |
| `@A2Token` / issue | `IssueToken` |
| `@A2Rotate` | `RotateToken` |
| `@A2Revoke` | `RevokeToken` |
| Introspection | `Introspect` |
| `@A2InstantCredentials` | `IssueToken` with type `TEMPORARY` / claims (`aud`, `token_use`, …) |

---

## Node / TypeScript / React + sidecar how-to

**Yes.** Node.js, TypeScript, and React applications can use A2 in two ways:

| Approach | Best for | How |
|----------|----------|-----|
| **A. gRPC sidecar** | Node/TS **backends**, BFF, NestJS, Next.js API routes, workers | Talk to `A2Service` on port `50051` |
| **B. HTTP client** | **React browser** apps, any SPA | Call your Spring/Quarkus API; A2 enforces policy server-side. Do **not** expose the sidecar to the public internet without auth/mTLS. |

Browsers generally should **not** open a raw gRPC channel to the sidecar (CORS, secrets, network topology). Prefer: React → your BFF (Node or Java) → sidecar or annotated Java services.

### 1. Start the sidecar

```bash
# After building a2-sidecar (requires protoc)
mvn -pl a2-sidecar -am package -DskipTests
java -jar a2-sidecar/target/a2-sidecar-1.0.0.jar --port 50051
```

Health check with [grpcurl](https://github.com/fullstorydev/grpcurl):

```bash
grpcurl -plaintext localhost:50051 list
grpcurl -plaintext -d '{"protocol":"JWT","credentials":"<token>"}' \
  localhost:50051 a2.A2Service/Authenticate
```

### 2. Generate Node / TypeScript stubs from `a2.proto`

Proto path: [`a2-sidecar/src/main/proto/a2.proto`](a2-sidecar/src/main/proto/a2.proto)

**Option A — classic `@grpc/grpc-js` + `grpc-tools`**

```bash
npm install @grpc/grpc-js @grpc/proto-loader
# optional codegen:
npm install -D grpc-tools
npx grpc_tools_node_protoc \
  --js_out=import_style=commonjs,binary:./generated \
  --grpc_out=grpc_js:./generated \
  -I a2-sidecar/src/main/proto \
  a2-sidecar/src/main/proto/a2.proto
```

**Option B — load proto at runtime (simple for Node/TS)**

```typescript
// a2Client.ts
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import path from "path";

const PROTO = path.join(__dirname, "../a2-sidecar/src/main/proto/a2.proto");

const packageDefinition = protoLoader.loadSync(PROTO, {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true,
});

const proto = grpc.loadPackageDefinition(packageDefinition) as any;
const A2Service = proto.a2.A2Service;

export function createA2Client(address = "localhost:50051") {
  return new A2Service(address, grpc.credentials.createInsecure());
}
```

For production, use TLS: `grpc.credentials.createSsl(...)` and never expose an insecure sidecar publicly.

### 3. Authenticate & authorize from TypeScript (Node / Nest / Next API route)

```typescript
import { createA2Client } from "./a2Client";

const client = createA2Client(process.env.A2_SIDECAR ?? "localhost:50051");

function authenticateJwt(token: string): Promise<{
  principalId: string;
  roles: string[];
  permissions: string[];
}> {
  return new Promise((resolve, reject) => {
    client.Authenticate(
      {
        protocol: "JWT",
        credentials: token,
        headers: { authorization: `Bearer ${token}` },
      },
      (err: Error | null, resp: any) => {
        if (err) return reject(err);
        if (!resp.success) return reject(new Error(resp.error || "auth failed"));
        resolve({
          principalId: resp.principal_id,
          roles: resp.roles || [],
          permissions: resp.permissions || [],
        });
      }
    );
  });
}

function authorize(
  principalId: string,
  requiredRoles: string[],
  requiredPermissions: string[] = []
): Promise<void> {
  return new Promise((resolve, reject) => {
    client.Authorize(
      {
        principal_id: principalId,
        required_roles: requiredRoles,
        required_permissions: requiredPermissions,
        require_all: false,
        protocol: "JWT",
      },
      (err: Error | null, resp: any) => {
        if (err) return reject(err);
        if (!resp.allowed) return reject(new Error(resp.reason || "forbidden"));
        resolve();
      }
    );
  });
}

// Express / Nest middleware style
export async function requireAdmin(req: any, res: any, next: any) {
  try {
    const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
    const auth = await authenticateJwt(token);
    await authorize(auth.principalId, ["admin"]);
    req.a2 = auth;
    next();
  } catch (e: any) {
    res.status(401).json({ error: e.message });
  }
}
```

### 4. Issue / revoke tokens from Node (mirror of `@A2Token` / `@A2Revoke`)

```typescript
function issueTempToken(principalId: string, audience: string): Promise<string> {
  return new Promise((resolve, reject) => {
    client.IssueToken(
      {
        type: "TEMPORARY",
        principal_id: principalId,
        scopes: ["payment:charge"],
        ttl_seconds: 3600,
        protocol: "JWT",
        claims: { aud: audience, token_use: "instant_service" },
      },
      (err: Error | null, resp: any) => {
        if (err || !resp.success) return reject(err || new Error(resp.error));
        resolve(resp.token);
      }
    );
  });
}
```

### 5. React (browser) — recommended pattern

React runs in the browser. Treat A2 like any other backend security layer:

1. User signs in via your IdP (OIDC) or your API issues a session/JWT.
2. React stores the token (httpOnly cookie preferred, or memory + refresh).
3. Every API call sends `Authorization: Bearer …` (or `X-API-Key`) to **your** backend.
4. Backend is either:
   - **Java** with `@A2Protected` / `@A2Authorize`, or  
   - **Node BFF** that calls the **sidecar** before serving data.

```tsx
// React — call your API, not the sidecar directly
async function loadOrders(accessToken: string) {
  const res = await fetch("https://api.example.com/orders", {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "X-Merchant-Id": "merchant-42", // multi-tenant optional
    },
  });
  if (res.status === 401 || res.status === 403) {
    throw new Error("A2 denied this request");
  }
  return res.json();
}
```

Optional: a thin Next.js **Route Handler** that uses the sidecar so the browser never sees gRPC:

```typescript
// app/api/whoami/route.ts (Next.js)
import { createA2Client } from "@/lib/a2Client";

export async function GET(request: Request) {
  const token = request.headers.get("authorization")?.replace(/^Bearer\s+/i, "") ?? "";
  const client = createA2Client(process.env.A2_SIDECAR!);

  const auth = await new Promise<any>((resolve, reject) => {
    client.Authenticate(
      { protocol: "JWT", credentials: token },
      (err: Error | null, resp: any) => (err ? reject(err) : resolve(resp))
    );
  });

  if (!auth.success) {
    return Response.json({ error: auth.error }, { status: 401 });
  }
  return Response.json({
    id: auth.principal_id,
    roles: auth.roles,
  });
}
```

### 6. Docker-style layout

```yaml
# docker-compose excerpt
services:
  a2-sidecar:
    image: your-registry/a2-sidecar:1.0.0
    ports: ["50051:50051"]
    # configure providers via env / mounted config as you extend the server

  node-bff:
    build: ./bff
    environment:
      A2_SIDECAR: a2-sidecar:50051
    depends_on: [a2-sidecar]
```

### Python quick reminder

```bash
python -m grpc_tools.protoc -I a2-sidecar/src/main/proto \
  --python_out=. --grpc_python_out=. a2.proto
```

Same RPCs as TypeScript (`Authenticate`, `Authorize`, `IssueToken`, …).

---

## gRPC sidecar reference

```bash
java -jar a2-sidecar/target/a2-sidecar-1.0.0.jar --port 50051
```

| RPC | Purpose |
|-----|---------|
| `Authenticate` | Validate credentials for a protocol |
| `Authorize` | Roles / permissions check |
| `IssueToken` | Mint token (incl. temp / assumed / impersonation claims) |
| `RotateToken` | Rotate |
| `RevokeToken` | Revoke one or all for principal |
| `Introspect` | Active token metadata |

**Messages** (see `a2.proto`): `AuthRequest` (`protocol`, `credentials`, `headers`), `AuthorizeRequest` (`principal_id`, `required_roles`, `required_permissions`, `require_all`), `TokenRequest` (`type`, `principal_id`, `scopes`, `ttl_seconds`, `claims`, `protocol`).

```bash
grpcurl -plaintext -d '{
  "protocol": "JWT",
  "credentials": "<token>"
}' localhost:50051 a2.A2Service/Authenticate
```

Deployment options:

| Mode | When |
|------|------|
| Sidecar per pod | Lowest latency; each workload has local A2 |
| Shared A2 service | Central policy/providers; many languages call one endpoint |
| Embedded JVM | Spring/Quarkus app with annotations — no separate process |

---

## Testing notes

| Area | What CI / unit tests cover | What they do **not** cover |
|------|----------------------------|----------------------------|
| API Key, JWT | Real providers, in-memory keys/HMAC | — |
| OIDC | Discovery JSON parse, PKCE URL | Live Okta/Auth0 HTTP |
| SSO factory | Issuer templates, non-null providers | Live IdP token validation |
| Auth pipeline | Extractor → authenticator → interceptor (stubs OK) | Full browser login |
| Instant credentials | SERVICE / ASSUME_ROLE / IMPERSONATE, TTL cap | Cloud STS/IAM APIs |

For live Okta/Entra, use tenant secrets in a private job or WireMock JWKS/token fixtures.

---

## Quality — SonarLint & SonarQube

| | **SonarLint** (IDE) | **SonarQube / SonarCloud** (CI) |
|--|---------------------|--------------------------------|
| When | As you type | Every push / PR |
| Setup | VS Code / IntelliJ extension | Secret `SONAR_TOKEN` |
| Repo config | `.vscode/settings.json` | Job in `.github/workflows/ci.yml` |

Without a Sonar token, CI still runs **SpotBugs + PMD** (`static-analysis` profile).

```bash
export SONAR_TOKEN=...
mvn -Psonar clean verify org.sonarsource.scanner.maven:sonar-maven-plugin:sonar
mvn -Pstatic-analysis verify -DskipTests
```

---

## Build

```bash
mvn -B clean verify -pl '!a2-sidecar'   # sidecar needs protoc binary
mvn -Prelease clean deploy             # Maven Central (manual)
```

Modules: `a2-annotations`, `a2-spi`, `a2-core`, `a2-providers/*`, `a2-spring-boot-starter`, `a2-quarkus-extension`, `a2-sidecar`, `a2-examples`.

Maven coordinates use **`com.futureim.a2`**. See [docs/MAVEN_CENTRAL.md](docs/MAVEN_CENTRAL.md).

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).

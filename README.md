# A2 — Annotation-driven Identity & Access Management

[![CI](https://github.com/futureimadmin/A2/actions/workflows/ci.yml/badge.svg)](https://github.com/futureimadmin/A2/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**A2** ("Auth Anywhere") unifies OAuth2, OIDC, SAML, Kerberos, API Keys, JWT and more behind a single annotation model. Issue, rotate, and revoke tokens; enforce AuthN/AuthZ; assume roles and impersonate — without locking into one IdP or protocol.

```java
@A2Protected(protocols = {Protocol.OIDC, Protocol.JWT}, roles = {"user"})
@A2Authorize(permissions = {"order:read"})
public class OrderService { ... }
```

---

## Table of contents

1. [Quick start](#quick-start)
2. [Annotations overview](#annotations-overview)
3. [How to use — JWT](#how-to-use--jwt)
4. [How to use — OIDC](#how-to-use--oidc)
5. [How to use — OAuth2](#how-to-use--oauth2)
6. [How to use — SAML](#how-to-use--saml)
7. [How to use — API Key](#how-to-use--api-key)
8. [How to use — Kerberos](#how-to-use--kerberos)
9. [How to use — Assume Role & Impersonation](#how-to-use--assume-role--impersonation)
10. [How to use — Service-to-service credentials](#how-to-use--service-to-service-credentials)
11. [Token lifecycle (issue / rotate / revoke)](#token-lifecycle-issue--rotate--revoke)
12. [Token stores](#token-stores)
13. [Spring Boot](#spring-boot)
14. [Quarkus](#quarkus)
15. [gRPC sidecar (multi-language)](#grpc-sidecar-multi-language)
16. [Quality — SonarLint & SonarQube](#quality--sonarlint--sonarqube)
17. [Build & publish](#build--publish)
18. [License](#license)

---

## Quick start

```xml
<!-- Core + annotations -->
<dependency>
  <groupId>io.a2</groupId>
  <artifactId>a2-core</artifactId>
  <version>0.1.0-SNAPSHOT</version>
</dependency>
<!-- Pick providers you need -->
<dependency>
  <groupId>io.a2</groupId>
  <artifactId>a2-provider-jwt</artifactId>
  <version>0.1.0-SNAPSHOT</version>
</dependency>
```

```java
import io.a2.core.A2Runtime;
import io.a2.provider.jwt.JwtProtocolProvider;

// Register providers once at startup
A2Runtime.get().register(new JwtProtocolProvider());
```

Protect a method or class:

```java
@A2Protected(protocols = Protocol.JWT, roles = {"admin"})
public void deleteUser(String id) { ... }
```

---

## Annotations overview

| Annotation | Purpose |
|------------|--------|
| `@A2Protected` | Require authentication (and optional roles/permissions/protocols) |
| `@A2Authenticate` | Explicit AuthN entry point |
| `@A2Authorize` | Fine-grained AuthZ (roles, permissions, attributes, policy) |
| `@A2Token` | Token issuance policy (type, TTL, rotate, scopes, claims) |
| `@A2Rotate` | Rotate token on method invocation |
| `@A2Revoke` | Revoke token(s) |
| `@A2AssumeRole` | Issue short-lived assumed-role credential |
| `@A2Impersonate` | Impersonate another principal (audited) |
| `@A2ServiceCredential` / `@A2TemporaryCredential` | S2S credentials (max 1 hour) |
| `@A2Principal` / `@A2Context` | Inject current principal / security context |

`Protocol` enum: `JWT`, `OIDC`, `OAUTH2`, `SAML`, `KERBEROS`, `API_KEY`, `MTLS`, `TLS`, `BASIC`, `SSO`, `CUSTOM`.

---

## How to use — JWT

**Provider:** `a2-provider-jwt` (Nimbus). Supports **HS256** and **RS256**.

### Setup

```java
// HS256
JwtProtocolProvider jwt = new JwtProtocolProvider(
    "your-secret-at-least-32-bytes-long!!!!!!!!",
    "https://issuer.example.com",
    tokenStore);   // TokenStore optional but recommended

// RS256
JwtProtocolProvider jwtRs = new JwtProtocolProvider(rsaPrivateKey, rsaPublicKey,
    "https://issuer.example.com", tokenStore);

A2Runtime.get().register(jwt);
```

### Protect endpoints

```java
@A2Protected(protocols = Protocol.JWT, roles = {"user"})
@A2Authorize(permissions = {"order:read"})
public Order getOrder(String id) { ... }
```

Client sends: `Authorization: Bearer <jwt>`.

### Issue a token (programmatic)

```java
TokenResult result = jwt.issueToken(TokenRequest.builder()
    .principalId("alice")
    .type(TokenType.ACCESS)
    .ttlSeconds(3600)
    .scopes(List.of("openid", "profile"))
    .claim("roles", List.of("user"))
    .build());

String accessToken = result.token().orElseThrow();
```

### Annotation-driven token policy

```java
@A2Token(type = TokenType.ACCESS, ttlSeconds = 3600, rotate = true,
         scopes = {"openid", "profile"})
public TokenResponse login(LoginRequest req) { ... }
```

---

## How to use — OIDC

**Provider:** `a2-provider-oidc`. Discovery (`.well-known/openid-configuration`), JWKS validation, Auth Code + PKCE.

### Setup with discovery

```java
OidcDiscoveryClient discovery = new OidcDiscoveryClient();
OidcDiscoveryDocument doc = discovery.discover("https://login.example.com");
// or discover("https://login.example.com/.well-known/openid-configuration")

OidcProtocolProvider oidc = new OidcProtocolProvider(doc, clientId, clientSecret, tokenStore);
A2Runtime.get().register(oidc);
```

### Protect with OIDC

```java
@A2Protected(protocols = Protocol.OIDC, roles = {"customer"})
public void placeOrder(Order order) { ... }
```

Client sends access/ID token as Bearer. A2 validates signature via JWKS, issuer, expiry, and audience.

### Browser login (Auth Code + PKCE)

```java
OidcAuthCodeFlow flow = new OidcAuthCodeFlow(doc, "my-client",
    "https://app.example.com/callback");

// 1. Redirect user
OidcAuthCodeFlow.AuthRedirect redirect = flow.start("openid profile email");
// response.sendRedirect(redirect.authorizationUrl());

// 2. On callback: exchange code
OidcAuthCodeFlow.TokenExchangeRequest tx =
    flow.prepareTokenExchange(code, state);
// POST tx.formBody() to tx.tokenEndpoint()
```

### Mixed OIDC + JWT

```java
@A2Protected(protocols = {Protocol.OIDC, Protocol.JWT})
public class ApiGateway { ... }
```

---

## How to use — OAuth2

OAuth2 resource-server style (validate access tokens). For full authorization-server flows, prefer OIDC provider + token endpoint of your IdP.

```java
@A2Protected(protocols = Protocol.OAUTH2, permissions = {"api:write"})
@A2Token(scopes = {"orders.write"}, ttlSeconds = 1800)
public void updateOrder(...) { ... }
```

Register the same OIDC/JWT provider configured against your OAuth2 issuer; A2 treats `OAUTH2` and `OIDC` as compatible when the token is a JWT validated via discovery/JWKS.

---

## How to use — SAML

**Provider:** `a2-provider-saml`. Assertion validation (issuer, audience, conditions, signature), metadata, Single Logout, encrypted assertions (OpenSAML-ready).

### Setup from IdP metadata

```java
SamlProtocolProvider saml = OpenSamlSupport.providerFromMetadata(
    "https://sp.example.com",                    // SP entity ID
    "https://sp.example.com/acs",                // ACS URL
    "https://idp.example.com/metadata"           // IdP metadata URL
);
A2Runtime.get().register(saml);
```

Or manually:

```java
SamlProtocolProvider saml = new SamlProtocolProvider(
    spEntityId, idpSsoUrl, acsUrl, idpSloUrl, idpIssuer, idpCert);
```

### Protect with SAML

```java
@A2Protected(protocols = Protocol.SAML, roles = {"employee"})
public void internalReport() { ... }
```

ACS handler validates `SAMLResponse` (Base64 or XML):

```java
AuthResult result = saml.authenticate(AuthRequest.builder()
    .protocol(Protocol.SAML)
    .credentials(samlResponseB64)
    .build());
```

### AuthnRequest & Single Logout

```java
String authnRequestXml = saml.buildAuthnRequest(relayState);
String logoutRequestXml = saml.initiateLogout(nameId, sessionIndex);
String logoutResponseXml = saml.buildLogoutResponse(inResponseTo, true);
```

### Encrypted assertions

```java
if (OpenSamlSupport.containsEncryptedAssertion(xml)) {
    Optional<String> plain = OpenSamlSupport.decryptAssertion(xml, spPrivateKey);
}
```

Optional: add `org.opensaml:opensaml-saml-impl:5.1.3` for full OpenSAML 5.x. See [docs/OPENSAML_AND_METADATA.md](docs/OPENSAML_AND_METADATA.md).

---

## How to use — API Key

**Provider:** `a2-provider-apikey`. Simple key → principal mapping; good for CLIs, webhooks, and internal tools.

### Setup

```java
ApiKeyProtocolProvider apiKeys = new ApiKeyProtocolProvider();
A2Runtime.get().register(apiKeys);
```

### Protect with API key

```java
@A2Protected(protocols = Protocol.API_KEY, permissions = {"webhook:ingest"})
public void handleWebhook(Payload body) { ... }
```

Clients send the key via `Authorization: ApiKey <key>` or `X-API-Key: <key>`.

### Combined with JWT for public vs machine traffic

```java
@A2Protected(protocols = {Protocol.JWT, Protocol.API_KEY})
public class HybridApi { ... }
```

---

## How to use — Kerberos

**Provider:** `a2-provider-kerberos` (GSS-API / SPNEGO).

### Setup

```java
KerberosProtocolProvider kerberos = new KerberosProtocolProvider(
    "HTTP/app.example.com@EXAMPLE.COM",
    "/etc/krb5.keytab"
);
A2Runtime.get().register(kerberos);
```

### Protect with Kerberos / SPNEGO

```java
@A2Protected(protocols = Protocol.KERBEROS, roles = {"domain-user"})
public void intranetOnly() { ... }
```

---

## How to use — Assume Role & Impersonation

```java
@A2AssumeRole(role = "billing-admin", ttlSeconds = 3600)
public void runBillingJob() { ... }

@A2Impersonate(requirePermission = "impersonate")
public void supportAsUser(String targetUserId, String ticketId) { ... }
```

---

## How to use — Service-to-service credentials

Temporary credentials are **hard-capped at 1 hour**.

```java
@A2ServiceCredential(audience = "orders-service", ttlSeconds = 3600)
public void callOrdersApi() { ... }
```

---

## Token lifecycle (issue / rotate / revoke)

```java
@A2Token(type = TokenType.ACCESS, ttlSeconds = 3600, rotate = true)
public TokenResponse login(...) { ... }

@A2Rotate
public TokenResponse refresh(String oldToken) { ... }

@A2Revoke
public void logout() { ... }
```

---

## Token stores

```java
TokenStore store = TokenStoreFactory.create("redis", Map.of("redisCommands", cmds));
```

| Type | Config key |
|------|------------|
| `memory` | — |
| `jdbc` | `dataSource` |
| `redis` / `valkey` | `redisCommands` |
| `vault` / `tmvault` / `openbao` | `vaultClient` |
| `gcp-secretmanager` | `gcpSecretClient` |
| `aws-secretsmanager` | `awsSecretsClient` |
| `azure-keyvault` | `azureKeyVaultClient` |

Details: [docs/TOKEN_STORES.md](docs/TOKEN_STORES.md).

---

## Spring Boot

```xml
<dependency>
  <groupId>io.a2</groupId>
  <artifactId>a2-spring-boot-starter</artifactId>
  <version>0.1.0-SNAPSHOT</version>
</dependency>
```

---

## Quarkus

```xml
<dependency>
  <groupId>io.a2</groupId>
  <artifactId>a2-quarkus-extension</artifactId>
  <version>0.1.0-SNAPSHOT</version>
</dependency>
```

See [docs/NATIVE_IMAGE.md](docs/NATIVE_IMAGE.md).

---

## gRPC sidecar (multi-language)

Run `a2-sidecar` next to non-Java services; call AuthN/AuthZ/token APIs over gRPC.

---

## Quality — SonarLint & SonarQube

Both are supported:

| | **SonarLint** (IDE) | **SonarQube / SonarCloud** (CI) |
|--|---------------------|--------------------------------|
| When | As you type | Every push / PR |
| Setup | VS Code / IntelliJ extension | Secret `SONAR_TOKEN` |
| Repo config | `.vscode/settings.json`, `extensions.json` | Job `SonarQube Analysis` |

Without a Sonar token, CI still runs **SpotBugs + PMD** (`static-analysis` profile).

Full guide: **[docs/SONAR.md](docs/SONAR.md)**

```bash
# Local SonarCloud/SQ analysis
export SONAR_TOKEN=...
mvn -Psonar clean verify sonar:sonar

# Local SpotBugs + PMD (no server)
mvn -Pstatic-analysis verify -DskipTests
```

---

## Build & publish

```bash
mvn clean verify
```

Maven Central (manual only):

```bash
mvn -Prelease clean deploy
```

See [docs/MAVEN_CENTRAL.md](docs/MAVEN_CENTRAL.md). Status: [docs/STATUS.md](docs/STATUS.md).

---

## License

Apache License 2.0

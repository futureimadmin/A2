# A2 Design Overview

## Problem

The IAM landscape is fragmented:

- OAuth2, OIDC, SAML, Kerberos, API Keys, mTLS, JWT, SSO products…
- Each has different APIs, token formats, and lifecycle rules.
- Switching protocols or providers usually means rewriting security code.

## Solution

**Annotations first, protocols second.**

Developers declare *what* security they need:

```java
@A2Protected(roles = "admin", protocols = {OIDC, OAUTH2})
@A2Authorize(permissions = "order:write")
@A2Token(type = ACCESS, rotate = true)
```

The runtime + SPI decide *how* (which provider, which token format, etc.).

## Architecture Layers

```
┌─────────────────────────────────────────┐
│  Application code (annotations only)    │
├─────────────────────────────────────────┤
│  A2 Interceptor / Runtime               │
├─────────────────────────────────────────┤
│  SPI (ProtocolProvider, TokenService)   │
├─────────────────────────────────────────┤
│  Concrete providers (OIDC, SAML, …)     │
└─────────────────────────────────────────┘
```

## Why Java first?

- Mature annotation & reflection model.
- Excellent existing ecosystem (Spring Security, pac4j, Keycloak adapters).
- Easy to expose the same contract over gRPC/REST for other languages.

## Multi-language vision

1. Keep annotation names + semantics identical across languages.
2. Publish the SPI as a language-neutral OpenAPI / protobuf definition.
3. Provide thin SDKs that talk to a central A2 sidecar or embed the runtime.

## Token Lifecycle as a First-Class Concern

Most frameworks treat tokens as opaque strings.
A2 elevates them:

- Issue, rotate, revoke are explicit operations.
- Annotations drive the lifecycle declaratively.
- Audit-friendly (reason, principal, timestamp).

## Extensibility

- New protocols = new `ProtocolProvider`.
- New policy engines = implement `authorize(...)` or plug a PolicyEngine SPI.
- New token stores = replace `TokenService`.

## Non-goals (v0.1)

- Full IdP server (use Keycloak, Ory, Zitadel…).
- UI / admin console.
- Heavy cryptography (delegate to proven libraries).

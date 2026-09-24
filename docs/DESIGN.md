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
│  (Spring AOP / Quarkus CDI / manual)    │
├─────────────────────────────────────────┤
│  SPI (ProtocolProvider, TokenService)   │
├─────────────────────────────────────────┤
│  Concrete providers                     │
│  JWT | API-Key | OIDC | SAML | Kerberos │
└─────────────────────────────────────────┘

          ┌──────────────────┐
          │  gRPC Sidecar    │  ← any language
          └──────────────────┘
```

## Implemented Components

| Component | Status | Notes |
|-----------|--------|-------|
| Core annotations + SPI | Done | Language-independent contract |
| JWT / API-Key providers | Done | Full lifecycle |
| OIDC / OAuth2 provider | Done | Introspection + local JWT fallback |
| SAML 2.0 provider | Done | AuthnRequest + ACS scaffold |
| Kerberos / SPNEGO provider | Done | GSS-ready scaffold |
| Annotation processor | Done | Compile-time validation |
| Spring Boot starter | Done | Auto-config + AOP aspect |
| Quarkus extension | Done | CDI interceptor + config |
| gRPC Sidecar | Done | Multi-language AuthN/AuthZ/Token API |

## Why Java first?

- Mature annotation & reflection model.
- Excellent existing ecosystem (Spring Security, pac4j, Keycloak adapters).
- Easy to expose the same contract over gRPC for other languages.

## Multi-language vision (realized)

1. Annotation names + semantics identical across languages (documented in `ANNOTATION_CONTRACT.md`).
2. SPI exposed as protobuf (`a2-sidecar/src/main/proto/a2.proto`).
3. Thin clients in any language call the sidecar; heavy lifting stays in the Java runtime (or future native ports).

## Token Lifecycle as a First-Class Concern

- Issue, rotate, revoke are explicit operations.
- Annotations drive the lifecycle declaratively.
- Audit-friendly (reason, principal, timestamp).

## Extensibility

- New protocols = new `ProtocolProvider`.
- New policy engines = implement `authorize(...)` or plug a PolicyEngine SPI.
- New token stores = replace `TokenService`.

## Non-goals (still)

- Full IdP server (use Keycloak, Ory, Zitadel…).
- UI / admin console.
- Heavy cryptography (delegate to proven libraries).

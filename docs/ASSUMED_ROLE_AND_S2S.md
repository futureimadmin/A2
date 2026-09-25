# Assumed Role, Impersonation & Service-to-Service Credentials

## Overview

A2 provides first-class support for three related patterns:

| Pattern | Annotation / API | Default TTL | Use case |
|---------|------------------|-------------|----------|
| **Service Credential** | `@A2ServiceCredential` | 1 hour | Machine-to-machine calls |
| **Assume Role** | `@A2AssumeRole` / `ImpersonationService.assumeRole` | 1 hour (hard cap) | Temporary elevation for a specific role |
| **Impersonation** | `@A2Impersonate` / `ImpersonationService.impersonate` | 1 hour | Support / admin acting as a user |

All issued tokens are persisted via `TokenStore` and carry audit claims.

## Service-to-Service (S2S) Temporary Credentials

```java
@A2ServiceCredential(
    audience = "billing-service",
    scopes = {"billing:write"},
    ttlSeconds = 3600   // max 1 hour
)
public String obtainS2SToken() { ... }
```

Or programmatically:

```java
tokenService.issue(TokenRequest.builder()
    .principalId("service-order")
    .ttlSeconds(3600)
    .scopes("s2s", "billing:write")
    .claims(Map.of("token_use", "service_credential", "aud", "billing-service"))
    .build());
```

## Assume Role

```java
@A2AssumeRole(role = "billing-admin", ttlSeconds = 3600, sessionName = "order-flow")
public void chargeCustomer(String orderId) { ... }
```

```java
TokenResult result = impersonationService.assumeRole(
    callerPrincipal,
    "billing-admin",
    3600,
    "order-to-billing"
);
```

The resulting token contains:

- `assumed_role`
- `original_principal`
- `session_name`
- `token_use = assumed_role`

## Impersonation

```java
@A2Impersonate(targetPrincipalParam = "customerId", ttlSeconds = 1800)
public void viewAsCustomer(String customerId, String reason) { ... }
```

Requirements:

- Caller must possess role `admin` **or** permission `impersonate`.
- A non-blank `reason` is mandatory (audit).

Claims on the token:

- `impersonated_by`
- `impersonation_reason`
- `token_use = impersonation`

## Persistent Token Store

```java
TokenStore store = new InMemoryTokenStore();          // dev / single node
// or
TokenStore store = new JdbcTokenStore(dataSource);    // production

JwtProtocolProvider jwt = new JwtProtocolProvider(secret, issuer, store);
runtime.setTokenService(new PersistentTokenService(store));
```

Schema for JDBC is documented in `JdbcTokenStore`.

## Security Notes

- S2S and AssumeRole TTLs are **hard-capped at 3600 seconds**.
- Every assume / impersonate operation is written to the TokenStore for audit & revocation.
- Impersonation always requires an explicit reason.
- Original principal is recoverable via `ImpersonationService.getOriginalPrincipal(ctx)`.

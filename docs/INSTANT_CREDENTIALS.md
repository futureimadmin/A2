# A2 Instant Credentials

Unified short-lived credentials (hard max **1 hour**), cloud-agnostic.

| Mode | Cloud analogy | Required fields |
|------|---------------|-----------------|
| `SERVICE` | S2S / workload identity | `audience`, optional `scopes` |
| `ASSUME_ROLE` | AWS STS AssumeRole | `role`, optional `sessionName` |
| `IMPERSONATE` | GCP SA impersonation | **source** = caller, **target** = `targetPrincipal` / param |

## Annotation

```java
@A2InstantCredentials(mode = InstantMode.SERVICE, audience = "payment-service",
        scopes = {"payment:charge"}, ttlSeconds = 3600)
public TokenResult paymentToken() { ... }

@A2InstantCredentials(mode = InstantMode.ASSUME_ROLE, role = "billing-admin",
        sessionName = "nightly-job")
public TokenResult assumeBilling() { ... }

// GCP-style: source SA = authenticated caller, target SA = method arg
@A2InstantCredentials(mode = InstantMode.IMPERSONATE,
        targetPrincipalParam = "targetSa", reason = "batch-job")
public TokenResult asTarget(String targetSa) { ... }
```

## Runtime

- `InstantCredentialsService` / `DefaultInstantCredentialsService`
- Interceptor handles `@A2InstantCredentials` before the method body
- Claims: `a2.instant.mode`, `a2.instant.token`, `a2.instant.token_id`, `a2.instant.expires_at`

## Aliases (still supported)

- `@A2AssumeRole` → ASSUME_ROLE
- `@A2Impersonate` → IMPERSONATE (source → target)
- `@A2TemporaryCredential` / `@A2ServiceCredential` → SERVICE

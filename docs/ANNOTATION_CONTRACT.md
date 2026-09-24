# A2 Annotation Contract

This document defines the **language-independent contract** of A2 annotations.
Any language port must honour the same semantics.

## Core Annotations

| Annotation | Target | Semantics |
|------------|--------|-----------|
| `A2Protected` | Type, Method | Requires authentication. Optional roles, permissions, allowed protocols. |
| `A2Authenticate` | Type, Method | Explicit AuthN; can force re-auth and select preferred protocol. |
| `A2Authorize` | Type, Method | Fine-grained AuthZ after AuthN (RBAC / permissions / simple ABAC). |
| `A2Token` | Type, Method | Declares token issuance policy (type, TTL, rotate, revoke, scopes, claims). |
| `A2Rotate` | Method | Force rotation of specified token types on successful exit. |
| `A2Revoke` | Method | Revoke token(s) on successful exit (current or all-for-principal). |
| `A2Principal` | Parameter | Inject current authenticated principal. |
| `A2Context` | Parameter | Inject full SecurityContext. |
| `A2Protocol` | Type, Method | Pin a concrete protocol provider. |

## Protocol Enumeration

`OAUTH2 | OIDC | SAML | SSO | KERBEROS | API_KEY | MTLS | TLS | JWT | BASIC | CUSTOM`

## Token Types

`ACCESS | REFRESH | ID | API_KEY | SESSION | CUSTOM`

## Evaluation Order

1. Resolve `@A2Protected` / `@A2Authenticate` → perform AuthN if needed.
2. Establish `SecurityContext`.
3. Evaluate `@A2Authorize` (and roles/permissions from `@A2Protected`).
4. Invoke target.
5. On success: process `@A2Token`, `@A2Rotate`, `@A2Revoke`.

## SPI Contract

Every protocol implements:

```
authenticate(AuthRequest) → AuthResult
issueToken(TokenRequest) → TokenResult
rotateToken(TokenRequest) → TokenResult
revokeToken(RevokeRequest)
authorize(AuthorizationContext) → boolean
```

This contract is intentionally minimal so it can be re-implemented in Go, Python, TypeScript, Rust, etc.

# A2 HTTP security — AuthN filter, 401/403, CORS

## Request pipeline

```
Browser / client
    │
    ▼
CORS filter (OPTIONS → 200, no AuthN)
    │
    ▼
AuthN filter  →  CredentialExtractor → ProtocolProvider(s) → A2Runtime.setContext
    │
    ▼
@A2Protected / @A2Authorize aspect  →  AuthZ (roles / permissions)
    │
    ▼
Controller method
```

## Typed exceptions → HTTP status

| Exception | HTTP | When |
|-----------|------|------|
| `A2AuthenticationException` | **401** | Missing/invalid credentials, protocol not allowed |
| `A2AuthorizationException` | **403** | Authenticated but missing role/permission for *this* resource |

## Multi-protocol `@A2Protected`

Filter picks protocol from headers; aspect checks established context protocol is allowed.

## Resource-level AuthZ

User with only `resource1:read` → resource1 OK, resource2 → **403**.

## Spring / Quarkus

Both ship AuthN filter, exception → 401/403 JSON, and CORS/OPTIONS handling by default.

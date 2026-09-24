# A2 — Annotation-driven Identity & Access Management

**A2** ("Auth Anywhere") is an open-source, annotation-first Identity & Access Management framework.

It unifies the fragmented world of **OAuth2, OIDC, SAML, SSO, Kerberos, IAM, API Keys, mTLS/TLS** behind a single, declarative, annotation-based programming model.

> **Goal**: Write security once with annotations. Switch protocols, providers or languages without rewriting business code.

```java
@A2Protected(roles = {"admin", "user"}, protocols = {Protocol.OIDC, Protocol.OAUTH2})
@A2Token(type = TokenType.ACCESS, rotate = true, revokeOnLogout = true)
public class OrderService {
    @A2Authorize(permissions = {"order:read", "order:write"})
    public Order getOrder(String id) { ... }
}
```

## Why A2?

| Problem | A2 Solution |
|---------|-------------|
| Too many protocols (OAuth2, SAML, OIDC, Kerberos…) | Single annotation model + pluggable Protocol SPI |
| Token lifecycle is complex (issue / rotate / revoke) | `@A2Token`, `@A2Rotate`, `@A2Revoke` |
| AuthN vs AuthZ mixed | Clear separation: `@A2Authenticate` + `@A2Authorize` |
| Language lock-in | Core is Java; annotation contract + SPI designed for multi-language interop |
| Hard to test / mock security | Annotation processor + runtime interceptor + test support |

## Core Concepts

### 1. Annotations (the heart of A2)

| Annotation | Purpose |
|------------|---------|
| `@A2Protected` | Declares a class/method requires authentication |
| `@A2Authenticate` | Explicit AuthN requirement + allowed protocols |
| `@A2Authorize` | Fine-grained AuthZ (roles, permissions, ABAC attributes) |
| `@A2Token` | Token type, claims, rotation & revocation policy |
| `@A2Rotate` | Force token rotation |
| `@A2Revoke` | Revoke token(s) on method exit or condition |
| `@A2Principal` | Inject current authenticated principal |
| `@A2Context` | Inject security context (claims, session, etc.) |
| `@A2Protocol` | Select / configure a specific protocol provider |

### 2. Protocol SPI

Any protocol is just an implementation of:

```java
public interface ProtocolProvider {
    Protocol id();
    AuthResult authenticate(AuthRequest request);
    TokenResult issueToken(TokenRequest request);
    TokenResult rotateToken(TokenRequest request);
    void revokeToken(RevokeRequest request);
    boolean authorize(AuthorizationContext ctx);
}
```

Built-in providers (extensible):
- `OAuth2Provider`
- `OidcProvider`
- `SamlProvider`
- `ApiKeyProvider`
- `MtlsProvider`
- `KerberosProvider` (experimental)
- `JwtProvider` (for pure JWT)

### 3. Token Lifecycle

A2 treats tokens as first-class citizens:

- **Issue** – via `@A2Token` or programmatic `TokenService`
- **Rotate** – automatic or explicit `@A2Rotate`
- **Revoke** – `@A2Revoke`, logout hooks, or admin API
- **Introspect** – standard + custom claims

### 4. Language Independence

While the reference implementation is **Java**, the design is language-agnostic:

- Annotation names and semantics are documented as a **contract**
- SPI is pure interfaces + JSON/YAML configuration
- Future ports (Go, Python, TypeScript, Rust) can implement the same contract
- Cross-language via gRPC / REST sidecar possible

## Quick Start (Java)

```xml
<dependency>
  <groupId>io.a2</groupId>
  <artifactId>a2-core</artifactId>
  <version>0.1.0-SNAPSHOT</version>
</dependency>
```

```java
@A2Protected(protocols = Protocol.OIDC)
public class MyApi {

    @A2Authorize(roles = "user")
    public String hello(@A2Principal Principal p) {
        return "Hello " + p.getName();
    }
}
```

Configure providers in `a2.yml` or programmatically.

## Project Structure

```
A2/
├── a2-annotations/          # Pure annotation definitions (zero deps)
├── a2-spi/                  # ProtocolProvider, TokenService, etc.
├── a2-core/                 # Runtime interceptor, annotation processor, default providers
├── a2-providers/            # Concrete protocol implementations
│   ├── oauth2/
│   ├── oidc/
│   ├── saml/
│   └── ...
├── a2-examples/             # Spring Boot, Quarkus, plain Java examples
└── docs/                    # Design docs, annotation contract, multi-language guide
```

## Status

**v0.1.0-SNAPSHOT** — Core annotations, SPI, basic OAuth2/OIDC/JWT providers, token lifecycle, Java runtime.

Roadmap:
- [ ] Full SAML 2.0 provider
- [ ] Kerberos / SPNEGO
- [ ] Annotation processor (compile-time validation)
- [ ] Spring Boot / Quarkus starters
- [ ] Go & TypeScript reference ports
- [ ] Policy-as-code integration (OPA / Cerbos)

## License

Apache License 2.0

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Issues and PRs welcome.

---

**A2** — Auth Anywhere. Annotations first. Protocols second.

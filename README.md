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
| Language lock-in | Core is Java; annotation contract + gRPC sidecar for multi-language |
| Hard to test / mock security | Annotation processor + runtime interceptor + test support |

## Features (v0.1)

- **Annotations** – `@A2Protected`, `@A2Authenticate`, `@A2Authorize`, `@A2Token`, `@A2Rotate`, `@A2Revoke`, `@A2Principal`, `@A2Context`, `@A2Protocol`
- **Providers** – JWT, API-Key, **OIDC/OAuth2**, **SAML 2.0**, **Kerberos/SPNEGO**
- **Token lifecycle** – issue / rotate / revoke / introspect
- **Compile-time checks** – `a2-processor`
- **Spring Boot starter** – auto-config + AOP interceptor
- **Quarkus extension** – CDI interceptor + config
- **gRPC Sidecar** – language-agnostic AuthN/AuthZ/Token API (Go, Python, Node, Rust, …)

## Quick Start (Java)

```xml
<dependency>
  <groupId>io.a2</groupId>
  <artifactId>a2-spring-boot-starter</artifactId>
  <version>0.1.0-SNAPSHOT</version>
</dependency>
```

```yaml
# application.yml
a2:
  providers:
    jwt: true
    oidc: true
  oidc:
    issuer: https://keycloak.example.com/realms/myrealm
    client-id: my-app
```

```java
@A2Protected(protocols = Protocol.OIDC)
@RestController
public class MyApi {
    @A2Authorize(roles = "user")
    @GetMapping("/hello")
    public String hello(@A2Principal Principal p) {
        return "Hello " + p.getName();
    }
}
```

## Multi-language via Sidecar

```bash
# start the sidecar
java -jar a2-sidecar.jar --port 50051
```

Any language can call the gRPC service defined in `a2-sidecar/src/main/proto/a2.proto`:

- `Authenticate`
- `Authorize`
- `IssueToken` / `RotateToken` / `RevokeToken`
- `Introspect`

## Project Structure

```
A2/
├── a2-annotations/          # Pure annotation definitions (zero deps)
├── a2-spi/                  # ProtocolProvider, TokenService, models
├── a2-core/                 # Runtime, interceptor, defaults
├── a2-processor/            # Compile-time annotation validation
├── a2-providers/
│   ├── a2-provider-jwt/
│   ├── a2-provider-apikey/
│   ├── a2-provider-oidc/    # OIDC + OAuth2
│   ├── a2-provider-saml/    # SAML 2.0
│   └── a2-provider-kerberos/# Kerberos / SPNEGO
├── a2-spring-boot-starter/  # Spring Boot auto-config + AOP
├── a2-quarkus-extension/    # Quarkus CDI extension
├── a2-sidecar/              # gRPC sidecar for multi-language
├── a2-examples/
└── docs/
```

## License

Apache License 2.0

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

**A2** — Auth Anywhere. Annotations first. Protocols second.

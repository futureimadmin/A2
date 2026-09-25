# A2 — Annotation-driven Identity & Access Management

**A2** ("Auth Anywhere") is an open-source, annotation-first Identity & Access Management framework.

It unifies **OAuth2, OIDC, SAML, SSO, Kerberos, API Keys, mTLS** behind a single declarative model and adds first-class support for **Assumed Role**, **Impersonation**, and **1-hour Service-to-Service credentials**.

```java
@A2Protected(roles = {"admin"}, protocols = {Protocol.OIDC, Protocol.JWT})
@A2AssumeRole(role = "billing-admin", ttlSeconds = 3600)
public class OrderService { ... }
```

## Features

| Area | Capability |
|------|------------|
| **Protocols** | JWT (Nimbus), OIDC/OAuth2, SAML 2.0 (OpenSAML-ready), Kerberos/SPNEGO (GSS-API), API-Key |
| **Token lifecycle** | Issue / Rotate / Revoke / Introspect |
| **Persistence** | `TokenStore` SPI – InMemory + JDBC |
| **S2S credentials** | `@A2ServiceCredential` – hard-capped at **1 hour** |
| **Assume Role** | `@A2AssumeRole` + `ImpersonationService.assumeRole` |
| **Impersonation** | `@A2Impersonate` + audit reason required |
| **Compile-time** | Annotation processor |
| **Frameworks** | Spring Boot starter, Quarkus extension |
| **Multi-language** | gRPC Sidecar |

## Quick Start

```xml
<dependency>
  <groupId>io.a2</groupId>
  <artifactId>a2-spring-boot-starter</artifactId>
  <version>0.1.0-SNAPSHOT</version>
</dependency>
```

```yaml
a2:
  providers:
    jwt: true
    oidc: true
  oidc:
    issuer: https://keycloak.example.com/realms/myrealm
```

## Service-to-Service (1 hour credentials)

```java
@A2ServiceCredential(audience = "billing-service", scopes = {"billing:write"}, ttlSeconds = 3600)
public String obtainS2SToken() { ... }
```

## Assume Role

```java
@A2AssumeRole(role = "billing-admin", ttlSeconds = 3600, sessionName = "order-flow")
public void chargeCustomer(String orderId) { ... }
```

## Impersonation

```java
@A2Impersonate(targetPrincipalParam = "customerId", ttlSeconds = 1800)
public void viewAsCustomer(String customerId, String reason) { ... }
```

## Persistent Token Store

```java
TokenStore store = new JdbcTokenStore(dataSource);   // or InMemoryTokenStore
JwtProtocolProvider jwt = new JwtProtocolProvider(secret, issuer, store);
runtime.setTokenService(new PersistentTokenService(store));
```

## Project Structure

```
A2/
├── a2-annotations/          # including @A2AssumeRole, @A2Impersonate, @A2ServiceCredential
├── a2-spi/                  # TokenStore, ImpersonationService
├── a2-core/                 # PersistentTokenService, DefaultImpersonationService, stores
├── a2-providers/
│   ├── a2-provider-jwt/     # Nimbus JOSE + JWT
│   ├── a2-provider-oidc/
│   ├── a2-provider-saml/    # OpenSAML-ready scaffold
│   └── a2-provider-kerberos/# Java GSS-API
├── a2-spring-boot-starter/
├── a2-quarkus-extension/
├── a2-sidecar/              # gRPC multi-language
└── docs/
    ├── ASSUMED_ROLE_AND_S2S.md
    └── ...
```

## License

Apache License 2.0

---

**A2** — Auth Anywhere. Annotations first. Protocols second.

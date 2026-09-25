# A2 — Annotation-driven Identity & Access Management

**A2** ("Auth Anywhere") unifies OAuth2, OIDC, SAML, Kerberos, API Keys behind annotations, with Assume Role, Impersonation, and multi-backend token stores.

```java
@A2Protected(protocols = {Protocol.OIDC, Protocol.JWT})
@A2AssumeRole(role = "billing-admin", ttlSeconds = 3600)
public class OrderService { ... }
```

## Features

| Area | Capability |
|------|------------|
| **Protocols** | JWT (HS256/RS256 Nimbus), OIDC Discovery + JWKS, SAML assertion validation, Kerberos/GSS, API-Key |
| **Token stores** | InMemory, JDBC, **Redis/Valkey**, **Vault/TMVault/OpenBao**, **GCP Secret Manager** |
| **S2S / Assume / Impersonate** | 1h credentials, `@A2AssumeRole`, `@A2Impersonate` |
| **Frameworks** | Spring Boot starter, Quarkus extension, gRPC sidecar |
| **CI** | GitHub Actions (Java 17/21) — ready |
| **Publish** | Maven Central profile — ready, not auto-published |

## Token stores

```java
TokenStore store = TokenStoreFactory.create("redis", Map.of("redisCommands", cmds));
// memory | jdbc | redis | valkey | vault | tmvault | openbao | gcp-secretmanager
```

See [docs/TOKEN_STORES.md](docs/TOKEN_STORES.md).

## Build

```bash
mvn clean verify
```

## Maven Central (when ready)

```bash
mvn -Prelease clean deploy   # signs + uploads; autoPublish=false
```

See [docs/MAVEN_CENTRAL.md](docs/MAVEN_CENTRAL.md).

## Status

See [docs/STATUS.md](docs/STATUS.md) for done vs deferred.

## License

Apache License 2.0

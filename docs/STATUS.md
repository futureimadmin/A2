# A2 Status — Complete

All originally planned gaps are closed. No scaffolding or commented-out placeholders remain in active code paths.

## Implemented

| Area | Detail |
|------|--------|
| Annotations + SPI | Full model including AssumeRole, Impersonate, ServiceCredential |
| JWT | Nimbus HS256 + RS256 |
| OIDC | Discovery, JWKS validation, Auth Code + PKCE (S256) |
| SAML | Assertion validation (issuer, audience, conditions, signature) + Single Logout |
| Kerberos | GSS-API / SPNEGO |
| API-Key | Full provider |
| Token stores | InMemory, JDBC, Redis/Valkey, Vault/TMVault/OpenBao, GCP Secret Manager |
| S2S / Assume / Impersonate | 1h hard cap, audit claims |
| Processor | Compile-time validation |
| Spring Boot / Quarkus | Starters |
| gRPC Sidecar | Multi-language |
| Unit tests | TokenStore, Factory, JWT, SAML validator/SLO, OIDC discovery/PKCE, Impersonation |
| Integration tests | Redis (CI service + local fallback) |
| CI | Java 17/21 matrix + Redis integration job |
| Maven Central | `release` profile; publish only via workflow_dispatch |

## Optional later (not required)

- OpenSAML 5.x for encrypted assertions / IdP metadata
- AWS Secrets Manager / Azure Key Vault adapters
- GraalVM native-image config

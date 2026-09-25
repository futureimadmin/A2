# A2 Status

## Complete

- [x] Annotation model + SPI
- [x] JWT HS256 + RS256 (Nimbus)
- [x] OIDC Discovery + JWKS validation
- [x] OIDC Authorization Code + PKCE (S256)
- [x] SAML assertion validation (issuer, audience, conditions, signature)
- [x] SAML Single Logout (LogoutRequest / LogoutResponse)
- [x] Kerberos / GSS-API
- [x] API-Key provider
- [x] Token stores: InMemory, JDBC, Redis/Valkey, Vault/TMVault/OpenBao, GCP Secret Manager
- [x] S2S 1h credentials, Assume Role, Impersonation
- [x] Annotation processor
- [x] Spring Boot starter + Quarkus extension
- [x] gRPC Sidecar
- [x] Unit tests (TokenStore, JWT, SAML, OIDC Discovery/PKCE, Impersonation, Factory)
- [x] Integration tests (Redis — real service in CI, in-memory fallback locally)
- [x] GitHub Actions CI: build matrix Java 17/21 + Redis integration job
- [x] Maven Central release profile (manual workflow_dispatch only)

## Optional future enhancements (not blockers)

- OpenSAML 5.x for encrypted assertions / metadata interchange
- AWS Secrets Manager / Azure Key Vault token store adapters
- Native image (GraalVM) config for Quarkus

# A2 Status — What's Done / Pending

## Done

- [x] Annotation model + SPI
- [x] JWT HS256 + RS256 (Nimbus)
- [x] OIDC Discovery + JWKS validation
- [x] SAML assertion validation (issuer, audience, conditions, signature)
- [x] Kerberos / GSS-API
- [x] API-Key provider
- [x] Token stores: InMemory, JDBC, Redis/Valkey, Vault/TMVault/OpenBao, GCP Secret Manager
- [x] S2S 1h credentials, Assume Role, Impersonation
- [x] Annotation processor
- [x] Spring Boot starter + Quarkus extension
- [x] gRPC Sidecar
- [x] GitHub Actions CI (build matrix Java 17/21) — ready, runs on push/PR
- [x] Maven Central release profile — ready, not auto-published
- [x] Unit tests (TokenStore, JWT provider)

## Intentionally deferred

- [ ] Full OpenSAML 5.x (encrypted assertions, metadata) — JDK XML-DSig is in place
- [ ] SAML Single Logout binding
- [ ] OIDC full Auth Code + PKCE browser redirect helper
- [ ] Redis/Vault Testcontainers integration tests in CI (scaffold commented)
- [ ] Actual `mvn deploy` to Central (manual when ready)

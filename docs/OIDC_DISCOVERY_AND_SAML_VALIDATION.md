# OIDC Discovery & SAML Assertion Validation

## Package Structure

```
io.a2.provider.oidc/
├── OidcDiscoveryClient.java      # Fetches & caches /.well-known/openid-configuration
├── OidcDiscoveryDocument.java    # Typed discovery model
└── OidcProtocolProvider.java     # Full OIDC provider using discovery + JWKS

io.a2.provider.saml/
├── SamlAssertionValidator.java   # Issuer, Audience, Conditions, Signature, NameID
└── SamlProtocolProvider.java     # SP-side provider wiring the validator
```

All packages follow standard Maven layout:
`src/main/java/io/a2/provider/<protocol>/`.

---

## OIDC Discovery Protocol

Implements [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html).

### Flow

1. `OidcDiscoveryClient.discover(issuer)` → `GET <issuer>/.well-known/openid-configuration`
2. Parse required fields (`issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri`, …)
3. Cache document (default TTL 1 hour)
4. Fetch JWKS from `jwks_uri`
5. Build Nimbus `JWTProcessor` with `JWSVerificationKeySelector`
6. On `authenticate()`: validate JWT signature + issuer + expiry via JWKS; fallback to token introspection

### Usage

```java
OidcProtocolProvider oidc = new OidcProtocolProvider(
    "https://keycloak.example.com/realms/myrealm",
    "my-client",
    "secret",
    null   // discovery URI derived from issuer
);

// Eager discovery (optional)
OidcDiscoveryDocument doc = oidc.ensureDiscovered();
System.out.println(doc.getTokenEndpoint());
System.out.println(doc.getJwksUri());
```

Configuration via system properties / Spring:

```
a2.oidc.issuer=https://...
a2.oidc.client-id=...
a2.oidc.client-secret=...
a2.oidc.discovery-uri=   # optional override
```

---

## SAML Assertion Validation

`SamlAssertionValidator` performs the checks required by SAML Core:

| Check | Spec reference |
|-------|----------------|
| Well-formed Assertion | SAML Core 2.0 |
| **Issuer** match | §2.3.3 |
| **AudienceRestriction** | §2.5.1.4 – Audience must include SP entityID |
| **Conditions** NotBefore / NotOnOrAfter | §2.5.1 – with configurable clock skew (default 120s) |
| **NameID** present | §2.2 |
| **Attribute** extraction | §2.7.3 |
| **XML Signature** (optional) | XML-DSig via JDK `XMLSignatureFactory` + IdP X.509 cert |

### Usage

```java
// With IdP certificate for signature validation
SamlProtocolProvider saml = SamlProtocolProvider.withIdpCertificate(
    "https://sp.example.com",           // SP entity ID (audience)
    "https://idp.example.com/sso",
    "https://sp.example.com/acs",
    "https://idp.example.com",          // expected Issuer
    idpCertPem                          // PEM string
);

AuthResult result = saml.authenticate(AuthRequest.builder()
    .protocol(Protocol.SAML)
    .credentials(base64SamlResponse)
    .build());
```

### Security notes

- XXE protection enabled on the DocumentBuilder.
- Signature validation is **skipped with a warning** when no IdP certificate is configured – always supply one in production.
- Clock skew is configurable (constructor argument).

### OpenSAML

The current implementation uses the JDK XML Digital Signature API and careful parsing so the module stays lightweight. For full OpenSAML 5.x integration (metadata, complex bindings, encrypted assertions), add:

```xml
<dependency>
  <groupId>org.opensaml</groupId>
  <artifactId>opensaml-saml-impl</artifactId>
  <version>5.1.3</version>
</dependency>
```

and replace the internals of `SamlAssertionValidator` while keeping the same public API.

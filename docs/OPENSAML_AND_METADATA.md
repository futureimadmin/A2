# SAML Metadata & OpenSAML

## Metadata

```java
SamlMetadataResolver resolver = new SamlMetadataResolver();
SamlMetadataResolver.IdpMetadata idp = resolver.resolveFromUrl("https://idp.example.com/metadata");

SamlProtocolProvider saml = OpenSamlSupport.providerFromMetadata(
    "https://sp.example.com",
    "https://sp.example.com/acs",
    "https://idp.example.com/metadata"
);
```

Parses entityID, SSO/SLO locations, and X509Certificates from EntityDescriptor.

## Encrypted assertions

```java
if (OpenSamlSupport.containsEncryptedAssertion(xml)) {
    Optional<String> plain = OpenSamlSupport.decryptAssertion(xml, spPrivateKey);
}
```

- Detects `EncryptedAssertion`
- Manual RSA-OAEP + AES-CBC decrypt path when OpenSAML is absent
- When `org.opensaml:opensaml-saml-impl:5.1.3` is on the classpath, `OpenSamlSupport.isOpenSamlAvailable()` is true

Optional Maven dependency (may need Shibboleth repo):

```xml
<dependency>
  <groupId>org.opensaml</groupId>
  <artifactId>opensaml-saml-impl</artifactId>
  <version>5.1.3</version>
</dependency>
```

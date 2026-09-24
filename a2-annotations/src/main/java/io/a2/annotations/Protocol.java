package io.a2.annotations;

/**
 * Supported identity protocols / mechanisms.
 * Extensible via ProtocolProvider SPI.
 */
public enum Protocol {
    OAUTH2,
    OIDC,
    SAML,
    SSO,
    KERBEROS,
    API_KEY,
    MTLS,
    TLS,
    JWT,
    BASIC,
    CUSTOM
}

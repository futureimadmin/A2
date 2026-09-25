package io.a2.provider.oidc;

import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Parsed OpenID Connect Discovery document
 * (https://openid.net/specs/openid-connect-discovery-1_0.html).
 */
public final class OidcDiscoveryDocument {

    private final String issuer;
    private final URI authorizationEndpoint;
    private final URI tokenEndpoint;
    private final URI userInfoEndpoint;
    private final URI jwksUri;
    private final URI revocationEndpoint;
    private final URI introspectionEndpoint;
    private final URI endSessionEndpoint;
    private final List<String> scopesSupported;
    private final List<String> responseTypesSupported;
    private final List<String> subjectTypesSupported;
    private final List<String> idTokenSigningAlgValuesSupported;
    private final List<String> tokenEndpointAuthMethodsSupported;
    private final List<String> claimsSupported;
    private final Map<String, Object> raw;

    private OidcDiscoveryDocument(Builder b) {
        this.issuer = Objects.requireNonNull(b.issuer, "issuer");
        this.authorizationEndpoint = b.authorizationEndpoint;
        this.tokenEndpoint = b.tokenEndpoint;
        this.userInfoEndpoint = b.userInfoEndpoint;
        this.jwksUri = b.jwksUri;
        this.revocationEndpoint = b.revocationEndpoint;
        this.introspectionEndpoint = b.introspectionEndpoint;
        this.endSessionEndpoint = b.endSessionEndpoint;
        this.scopesSupported = b.scopesSupported != null ? List.copyOf(b.scopesSupported) : List.of();
        this.responseTypesSupported = b.responseTypesSupported != null ? List.copyOf(b.responseTypesSupported) : List.of();
        this.subjectTypesSupported = b.subjectTypesSupported != null ? List.copyOf(b.subjectTypesSupported) : List.of();
        this.idTokenSigningAlgValuesSupported = b.idTokenSigningAlgValuesSupported != null
                ? List.copyOf(b.idTokenSigningAlgValuesSupported) : List.of();
        this.tokenEndpointAuthMethodsSupported = b.tokenEndpointAuthMethodsSupported != null
                ? List.copyOf(b.tokenEndpointAuthMethodsSupported) : List.of();
        this.claimsSupported = b.claimsSupported != null ? List.copyOf(b.claimsSupported) : List.of();
        this.raw = b.raw != null ? Map.copyOf(b.raw) : Map.of();
    }

    public String getIssuer() { return issuer; }
    public URI getAuthorizationEndpoint() { return authorizationEndpoint; }
    public URI getTokenEndpoint() { return tokenEndpoint; }
    public URI getUserInfoEndpoint() { return userInfoEndpoint; }
    public URI getJwksUri() { return jwksUri; }
    public URI getRevocationEndpoint() { return revocationEndpoint; }
    public URI getIntrospectionEndpoint() { return introspectionEndpoint; }
    public URI getEndSessionEndpoint() { return endSessionEndpoint; }
    public List<String> getScopesSupported() { return scopesSupported; }
    public List<String> getResponseTypesSupported() { return responseTypesSupported; }
    public List<String> getSubjectTypesSupported() { return subjectTypesSupported; }
    public List<String> getIdTokenSigningAlgValuesSupported() { return idTokenSigningAlgValuesSupported; }
    public List<String> getTokenEndpointAuthMethodsSupported() { return tokenEndpointAuthMethodsSupported; }
    public List<String> getClaimsSupported() { return claimsSupported; }
    public Map<String, Object> getRaw() { return raw; }

    public static Builder builder() { return new Builder(); }

    public static final class Builder {
        private String issuer;
        private URI authorizationEndpoint;
        private URI tokenEndpoint;
        private URI userInfoEndpoint;
        private URI jwksUri;
        private URI revocationEndpoint;
        private URI introspectionEndpoint;
        private URI endSessionEndpoint;
        private List<String> scopesSupported;
        private List<String> responseTypesSupported;
        private List<String> subjectTypesSupported;
        private List<String> idTokenSigningAlgValuesSupported;
        private List<String> tokenEndpointAuthMethodsSupported;
        private List<String> claimsSupported;
        private Map<String, Object> raw;

        public Builder issuer(String v) { this.issuer = v; return this; }
        public Builder authorizationEndpoint(URI v) { this.authorizationEndpoint = v; return this; }
        public Builder tokenEndpoint(URI v) { this.tokenEndpoint = v; return this; }
        public Builder userInfoEndpoint(URI v) { this.userInfoEndpoint = v; return this; }
        public Builder jwksUri(URI v) { this.jwksUri = v; return this; }
        public Builder revocationEndpoint(URI v) { this.revocationEndpoint = v; return this; }
        public Builder introspectionEndpoint(URI v) { this.introspectionEndpoint = v; return this; }
        public Builder endSessionEndpoint(URI v) { this.endSessionEndpoint = v; return this; }
        public Builder scopesSupported(List<String> v) { this.scopesSupported = v; return this; }
        public Builder responseTypesSupported(List<String> v) { this.responseTypesSupported = v; return this; }
        public Builder subjectTypesSupported(List<String> v) { this.subjectTypesSupported = v; return this; }
        public Builder idTokenSigningAlgValuesSupported(List<String> v) { this.idTokenSigningAlgValuesSupported = v; return this; }
        public Builder tokenEndpointAuthMethodsSupported(List<String> v) { this.tokenEndpointAuthMethodsSupported = v; return this; }
        public Builder claimsSupported(List<String> v) { this.claimsSupported = v; return this; }
        public Builder raw(Map<String, Object> v) { this.raw = v; return this; }

        public OidcDiscoveryDocument build() { return new OidcDiscoveryDocument(this); }
    }
}

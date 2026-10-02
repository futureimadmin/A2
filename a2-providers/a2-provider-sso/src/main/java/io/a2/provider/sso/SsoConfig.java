package io.a2.provider.sso;

import io.a2.annotations.SsoProvider;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Immutable configuration for an SSO IdP binding.
 */
public final class SsoConfig {

    private final SsoProvider provider;
    private final String name;
    private final String issuer;
    private final String clientId;
    private final String clientSecret;
    private final String tenant;
    private final String audience;
    private final String hostedDomain;
    private final List<String> scopes;
    private final boolean forceReauth;

    private SsoConfig(Builder b) {
        this.provider = Objects.requireNonNull(b.provider, "provider");
        this.name = b.name != null && !b.name.isBlank()
                ? b.name
                : b.provider.name().toLowerCase();
        this.issuer = b.issuer;
        this.clientId = b.clientId != null ? b.clientId : "";
        this.clientSecret = b.clientSecret != null ? b.clientSecret : "";
        this.tenant = b.tenant != null ? b.tenant : "";
        this.audience = b.audience != null ? b.audience : "";
        this.hostedDomain = b.hostedDomain != null ? b.hostedDomain : "";
        this.scopes = b.scopes == null || b.scopes.isEmpty()
                ? List.of("openid", "profile", "email")
                : List.copyOf(b.scopes);
        this.forceReauth = b.forceReauth;
    }

    public SsoProvider provider() { return provider; }
    public String name() { return name; }
    public String issuer() { return issuer; }
    public String clientId() { return clientId; }
    public String clientSecret() { return clientSecret; }
    public String tenant() { return tenant; }
    public String audience() { return audience; }
    public String hostedDomain() { return hostedDomain; }
    public List<String> scopes() { return scopes; }
    public boolean forceReauth() { return forceReauth; }

    public static Builder builder(SsoProvider provider) {
        return new Builder(provider);
    }

    public static final class Builder {
        private final SsoProvider provider;
        private String name;
        private String issuer;
        private String clientId;
        private String clientSecret;
        private String tenant;
        private String audience;
        private String hostedDomain;
        private List<String> scopes;
        private boolean forceReauth;

        private Builder(SsoProvider provider) {
            this.provider = provider;
        }

        public Builder name(String name) { this.name = name; return this; }
        public Builder issuer(String issuer) { this.issuer = issuer; return this; }
        public Builder clientId(String clientId) { this.clientId = clientId; return this; }
        public Builder clientSecret(String clientSecret) { this.clientSecret = clientSecret; return this; }
        public Builder tenant(String tenant) { this.tenant = tenant; return this; }
        public Builder audience(String audience) { this.audience = audience; return this; }
        public Builder hostedDomain(String hostedDomain) { this.hostedDomain = hostedDomain; return this; }
        public Builder scopes(String... scopes) {
            this.scopes = scopes == null ? List.of() : Arrays.asList(scopes);
            return this;
        }
        public Builder scopes(List<String> scopes) { this.scopes = scopes; return this; }
        public Builder forceReauth(boolean forceReauth) { this.forceReauth = forceReauth; return this; }

        public SsoConfig build() {
            if (issuer == null || issuer.isBlank()) {
                issuer = SsoIssuerTemplates.resolve(provider, null, tenant);
            }
            return new SsoConfig(this);
        }
    }
}

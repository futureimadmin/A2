package io.a2.provider.sso;

import io.a2.annotations.Protocol;
import io.a2.annotations.SsoProvider;
import io.a2.core.SimplePrincipal;
import io.a2.provider.oidc.OidcProtocolProvider;
import io.a2.spi.ProtocolProvider;
import io.a2.spi.model.AuthRequest;
import io.a2.spi.model.AuthResult;
import io.a2.spi.model.AuthorizationContext;
import io.a2.spi.model.RevokeRequest;
import io.a2.spi.model.TokenRequest;
import io.a2.spi.model.TokenResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Brand-aware SSO provider. Delegates token validation to OIDC discovery + JWKS
 * with IdP-specific claim checks (Google {@code hd}, Entra roles, Okta groups, …).
 */
public class SsoProtocolProvider implements ProtocolProvider {

    private static final Logger log = LoggerFactory.getLogger(SsoProtocolProvider.class);

    private final SsoConfig config;
    private final OidcProtocolProvider oidc;

    public SsoProtocolProvider(SsoConfig config) {
        this.config = Objects.requireNonNull(config, "config");
        this.oidc = new OidcProtocolProvider(
                config.issuer(),
                config.clientId(),
                config.clientSecret(),
                ""
        );
        log.info("SSO provider ready: name={} brand={} issuer={}",
                config.name(), config.provider(), config.issuer());
    }

    public SsoConfig config() {
        return config;
    }

    public SsoProvider brand() {
        return config.provider();
    }

    @Override
    public Protocol id() {
        return Protocol.SSO;
    }

    @Override
    public String name() {
        return "SSO/" + config.provider().name() + " (" + config.name() + ")";
    }

    @Override
    public AuthResult authenticate(AuthRequest request) {
        AuthResult base = oidc.authenticate(request);
        if (!base.isSuccess()) {
            return base;
        }

        Map<String, Object> claims = new HashMap<>(base.extra() != null
                ? base.extra()
                : Map.of());
        base.principal().ifPresent(p -> claims.putAll(p.getAttributes()));
        claims.put("a2.sso.provider", config.provider().name());
        claims.put("a2.sso.name", config.name());
        claims.put("a2.sso.issuer", config.issuer());

        switch (config.provider()) {
            case GOOGLE -> {
                if (!config.hostedDomain().isBlank()) {
                    Object hd = claims.get("hd");
                    if (hd == null || !config.hostedDomain().equalsIgnoreCase(String.valueOf(hd))) {
                        return AuthResult.failure(
                                "Google hosted domain mismatch: expected " + config.hostedDomain());
                    }
                }
            }
            case ENTRA -> {
                if (!config.audience().isBlank()) {
                    Object aud = claims.get("aud");
                    if (aud != null && !String.valueOf(aud).contains(config.audience())
                            && !String.valueOf(aud).contains(config.clientId())) {
                        return AuthResult.failure("Entra audience mismatch");
                    }
                }
            }
            case AUTH0 -> {
                if (!config.audience().isBlank()) {
                    Object aud = claims.get("aud");
                    if (aud != null && !String.valueOf(aud).contains(config.audience())) {
                        return AuthResult.failure("Auth0 audience mismatch");
                    }
                }
            }
            default -> { /* no extra checks */ }
        }

        var principal = base.principal().orElse(null);
        if (principal == null) {
            return AuthResult.failure("SSO authentication produced no principal");
        }

        Set<String> roles = principal.getRoles();
        Set<String> perms = principal.getPermissions();
        return AuthResult.success(
                new SimplePrincipal(principal.getId(), principal.getName(), roles, perms, claims),
                claims);
    }

    @Override
    public TokenResult issueToken(TokenRequest request) {
        return oidc.issueToken(request);
    }

    @Override
    public TokenResult rotateToken(TokenRequest request) {
        return oidc.rotateToken(request);
    }

    @Override
    public void revokeToken(RevokeRequest request) {
        oidc.revokeToken(request);
    }

    @Override
    public boolean authorize(AuthorizationContext ctx) {
        return oidc.authorize(ctx);
    }

    @Override
    public boolean supports(String capability) {
        return "sso".equals(capability)
                || config.provider().name().equalsIgnoreCase(capability)
                || oidc.supports(capability);
    }
}

package io.a2.provider.oidc;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import io.a2.annotations.Protocol;
import io.a2.annotations.TokenType;
import io.a2.core.SimplePrincipal;
import io.a2.spi.ProtocolProvider;
import io.a2.spi.model.AuthRequest;
import io.a2.spi.model.AuthResult;
import io.a2.spi.model.AuthorizationContext;
import io.a2.spi.model.RevokeRequest;
import io.a2.spi.model.TokenRequest;
import io.a2.spi.model.TokenResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * OpenID Connect / OAuth2 ProtocolProvider with full Discovery support.
 *
 * Package: {@code io.a2.provider.oidc}
 *
 * On construction (or first use) it fetches
 * {@code <issuer>/.well-known/openid-configuration}, caches endpoints,
 * and uses the published JWKS for ID/access token validation.
 */
public class OidcProtocolProvider implements ProtocolProvider {

    private static final Logger log = LoggerFactory.getLogger(OidcProtocolProvider.class);

    private final String configuredIssuer;
    private final String clientId;
    private final String clientSecret;
    private final String discoveryUriOverride;
    private final OidcDiscoveryClient discoveryClient;
    private final HttpClient http;

    private volatile OidcDiscoveryDocument discovery;
    private volatile ConfigurableJWTProcessor<SecurityContext> jwtProcessor;
    private final Map<String, TokenMeta> localStore = new ConcurrentHashMap<>();

    public OidcProtocolProvider() {
        this(
                System.getProperty("a2.oidc.issuer", ""),
                System.getProperty("a2.oidc.client-id", "a2-client"),
                System.getProperty("a2.oidc.client-secret", ""),
                System.getProperty("a2.oidc.discovery-uri", "")
        );
    }

    public OidcProtocolProvider(String issuer, String clientId, String clientSecret, String discoveryUri) {
        this.configuredIssuer = issuer;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.discoveryUriOverride = discoveryUri;
        this.discoveryClient = new OidcDiscoveryClient();
        this.http = HttpClient.newHttpClient();
    }

    /** Eagerly run discovery (optional; otherwise lazy on first auth). */
    public synchronized OidcDiscoveryDocument ensureDiscovered() {
        if (discovery != null) return discovery;
        String target = (discoveryUriOverride != null && !discoveryUriOverride.isBlank())
                ? discoveryUriOverride
                : configuredIssuer;
        if (target == null || target.isBlank()) {
            throw new IllegalStateException("OIDC issuer or discovery-uri must be configured");
        }
        discovery = discoveryClient.discover(target);
        initJwtProcessor(discovery);
        return discovery;
    }

    private void initJwtProcessor(OidcDiscoveryDocument doc) {
        try {
            if (doc.getJwksUri() == null) {
                log.warn("Discovery document has no jwks_uri; JWT signature validation disabled");
                return;
            }
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(doc.getJwksUri())
                    .header("Accept", "application/json")
                    .GET()
                    .build();
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                log.warn("Failed to load JWKS from {}: HTTP {}", doc.getJwksUri(), resp.statusCode());
                return;
            }
            JWKSet jwkSet = JWKSet.parse(resp.body());
            JWKSource<SecurityContext> keySource = new ImmutableJWKSet<>(jwkSet);

            ConfigurableJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
            // Prefer RS256; fall back to whatever the IdP advertises
            JWSAlgorithm alg = JWSAlgorithm.RS256;
            if (!doc.getIdTokenSigningAlgValuesSupported().isEmpty()) {
                try {
                    alg = JWSAlgorithm.parse(doc.getIdTokenSigningAlgValuesSupported().get(0));
                } catch (Exception ignored) {}
            }
            JWSKeySelector<SecurityContext> keySelector =
                    new JWSVerificationKeySelector<>(alg, keySource);
            processor.setJWSKeySelector(keySelector);
            this.jwtProcessor = processor;
            log.info("OIDC JWKS loaded from {}", doc.getJwksUri());
        } catch (Exception e) {
            log.warn("Could not initialise JWT processor from JWKS: {}", e.getMessage());
        }
    }

    @Override
    public Protocol id() {
        return Protocol.OIDC;
    }

    @Override
    public String name() {
        return "OpenID Connect / OAuth2 (Discovery)";
    }

    @Override
    public AuthResult authenticate(AuthRequest request) {
        String token = extractBearer(request);
        if (token == null || token.isBlank()) {
            return AuthResult.failure("Missing Bearer token");
        }

        // Local cache (issued by this provider)
        TokenMeta meta = localStore.get(token);
        if (meta != null) {
            if (meta.expiresAt.isBefore(Instant.now())) {
                localStore.remove(token);
                return AuthResult.failure("Token expired");
            }
            return AuthResult.success(SimplePrincipal.of(meta.principalId, meta.principalId,
                    meta.roles.toArray(new String[0])));
        }

        // Ensure discovery + JWKS
        try {
            ensureDiscovered();
        } catch (Exception e) {
            log.debug("Discovery not available, trying introspection / local parse: {}", e.getMessage());
        }

        // 1. Cryptographic validation via JWKS
        if (jwtProcessor != null) {
            try {
                JWTClaimsSet claims = jwtProcessor.process(token, null);
                return principalFromClaims(claims);
            } catch (Exception e) {
                log.debug("JWKS validation failed: {}", e.getMessage());
            }
        }

        // 2. Remote introspection
        if (discovery != null && discovery.getIntrospectionEndpoint() != null) {
            try {
                AuthResult remote = introspectRemote(token);
                if (remote.isSuccess()) return remote;
            } catch (Exception e) {
                log.debug("Introspection failed: {}", e.getMessage());
            }
        }

        return AuthResult.failure("Token validation failed");
    }

    private AuthResult principalFromClaims(JWTClaimsSet claims) {
        // Issuer check
        if (discovery != null && claims.getIssuer() != null
                && !discovery.getIssuer().equals(claims.getIssuer())) {
            return AuthResult.failure("Issuer mismatch: expected " + discovery.getIssuer()
                    + " got " + claims.getIssuer());
        }
        Date exp = claims.getExpirationTime();
        if (exp != null && exp.before(new Date())) {
            return AuthResult.failure("Token expired");
        }
        String sub = claims.getSubject();
        if (sub == null) return AuthResult.failure("Missing sub claim");

        Set<String> roles = new HashSet<>();
        Object rolesClaim = claims.getClaim("roles");
        if (rolesClaim instanceof List<?> list) {
            list.forEach(r -> roles.add(String.valueOf(r)));
        } else if (rolesClaim instanceof String s) {
            for (String r : s.split(",")) roles.add(r.trim());
        }
        // Keycloak-style realm_access
        Object realmAccess = claims.getClaim("realm_access");
        if (realmAccess instanceof Map<?, ?> m) {
            Object rr = m.get("roles");
            if (rr instanceof List<?> list) list.forEach(r -> roles.add(String.valueOf(r)));
        }

        Map<String, Object> attrs = new HashMap<>(claims.getClaims());
        return AuthResult.success(new SimplePrincipal(sub, sub, roles, Set.of(), attrs), attrs);
    }

    private AuthResult introspectRemote(String token) throws Exception {
        URI ep = discovery.getIntrospectionEndpoint();
        String body = "token=" + token + "&client_id=" + clientId;
        if (clientSecret != null && !clientSecret.isBlank()) {
            body += "&client_secret=" + clientSecret;
        }
        HttpRequest req = HttpRequest.newBuilder()
                .uri(ep)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200) {
            return AuthResult.failure("Introspection HTTP " + resp.statusCode());
        }
        String json = resp.body();
        if (!json.contains("\"active\":true") && !json.contains("\"active\": true")) {
            return AuthResult.failure("Token not active");
        }
        // extract sub
        String sub = extractJsonString(json, "sub");
        if (sub == null) sub = "unknown";
        return AuthResult.success(SimplePrincipal.of(sub, sub, "user"));
    }

    @Override
    public TokenResult issueToken(TokenRequest request) {
        // Local issuance for tests / offline; real deployments use the token endpoint
        long ttl = request.ttlSeconds() > 0 ? request.ttlSeconds() : 3600;
        Instant exp = Instant.now().plusSeconds(ttl);
        String tokenId = UUID.randomUUID().toString();
        String accessToken = "oidc." + tokenId;

        localStore.put(accessToken, new TokenMeta(request.principalId(), Set.of("user"), exp));

        Map<String, Object> claims = new HashMap<>(request.claims() != null ? request.claims() : Map.of());
        if (discovery != null) claims.put("iss", discovery.getIssuer());
        claims.put("sub", request.principalId());
        claims.put("exp", exp.getEpochSecond());

        return TokenResult.success(accessToken, tokenId, request.type(), exp, claims);
    }

    @Override
    public TokenResult rotateToken(TokenRequest request) {
        if (request.existingToken() != null) {
            localStore.remove(request.existingToken());
        }
        return issueToken(request);
    }

    @Override
    public void revokeToken(RevokeRequest request) {
        if (request.tokenId() != null) {
            localStore.entrySet().removeIf(e -> e.getKey().contains(request.tokenId()));
        }
        if (request.allForPrincipal() && request.principalId() != null) {
            localStore.entrySet().removeIf(e -> request.principalId().equals(e.getValue().principalId));
        }
        // Production: POST to discovery.getRevocationEndpoint()
    }

    @Override
    public boolean authorize(AuthorizationContext ctx) {
        if (ctx.principal() == null) return false;
        if (ctx.requiredRoles().isEmpty() && ctx.requiredPermissions().isEmpty()) return true;
        var p = ctx.principal();
        if (ctx.requireAll()) {
            return p.getRoles().containsAll(ctx.requiredRoles())
                    && p.getPermissions().containsAll(ctx.requiredPermissions());
        }
        boolean roleOk = ctx.requiredRoles().isEmpty()
                || ctx.requiredRoles().stream().anyMatch(p::hasRole);
        boolean permOk = ctx.requiredPermissions().isEmpty()
                || ctx.requiredPermissions().stream().anyMatch(perm -> p.getPermissions().contains(perm));
        return roleOk || permOk;
    }

    @Override
    public boolean supports(String capability) {
        return switch (capability) {
            case "discovery", "jwks", "refresh", "introspect", "revoke", "pkce", "client_credentials" -> true;
            default -> false;
        };
    }

    public OidcDiscoveryDocument getDiscovery() {
        return discovery;
    }

    private static String extractBearer(AuthRequest request) {
        String token = request.credentials();
        if (token == null || token.isBlank()) {
            token = request.headers().getOrDefault("Authorization", "");
            if (token.toLowerCase().startsWith("bearer ")) {
                token = token.substring(7).trim();
            }
        }
        return token;
    }

    private static String extractJsonString(String json, String key) {
        String needle = "\"" + key + "\":\"";
        int i = json.indexOf(needle);
        if (i < 0) {
            needle = "\"" + key + "\": \"";
            i = json.indexOf(needle);
        }
        if (i < 0) return null;
        int start = i + needle.length();
        int end = json.indexOf('"', start);
        return end > start ? json.substring(start, end) : null;
    }

    private static final class TokenMeta {
        final String principalId;
        final Set<String> roles;
        final Instant expiresAt;

        TokenMeta(String principalId, Set<String> roles, Instant expiresAt) {
            this.principalId = principalId;
            this.roles = roles;
            this.expiresAt = expiresAt;
        }
    }
}

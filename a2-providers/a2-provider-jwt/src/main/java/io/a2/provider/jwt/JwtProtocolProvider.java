package io.a2.provider.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.a2.annotations.Protocol;
import io.a2.annotations.TokenType;
import io.a2.core.SimplePrincipal;
import io.a2.spi.ProtocolProvider;
import io.a2.spi.TokenStore;
import io.a2.spi.model.AuthRequest;
import io.a2.spi.model.AuthResult;
import io.a2.spi.model.AuthorizationContext;
import io.a2.spi.model.RevokeRequest;
import io.a2.spi.model.TokenRequest;
import io.a2.spi.model.TokenResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Production-grade JWT provider powered by Nimbus JOSE + JWT.
 * Supports HS256 (symmetric) out of the box; extend for RS256/ES256 by injecting a JWK.
 */
public class JwtProtocolProvider implements ProtocolProvider {

    private static final Logger log = LoggerFactory.getLogger(JwtProtocolProvider.class);

    private final byte[] sharedSecret;
    private final String issuer;
    private final TokenStore tokenStore; // optional persistent store

    public JwtProtocolProvider() {
        this(System.getProperty("a2.jwt.secret", "a2-dev-secret-change-me-must-be-at-least-32-bytes-long!!"),
                System.getProperty("a2.jwt.issuer", "https://a2.local"),
                null);
    }

    public JwtProtocolProvider(String secret, String issuer, TokenStore tokenStore) {
        this.sharedSecret = secret.getBytes(StandardCharsets.UTF_8);
        this.issuer = issuer;
        this.tokenStore = tokenStore;
        if (this.sharedSecret.length < 32) {
            throw new IllegalArgumentException("JWT secret must be at least 32 bytes for HS256");
        }
    }

    @Override
    public Protocol id() {
        return Protocol.JWT;
    }

    @Override
    public AuthResult authenticate(AuthRequest request) {
        String token = request.credentials();
        if (token == null || token.isBlank()) {
            token = request.headers().getOrDefault("Authorization", "");
            if (token.toLowerCase().startsWith("bearer ")) {
                token = token.substring(7).trim();
            }
        }
        if (token == null || token.isBlank()) {
            return AuthResult.failure("Missing Bearer token");
        }

        // Check persistent revoke list first
        if (tokenStore != null) {
            var stored = tokenStore.findByTokenValue(token);
            if (stored.isEmpty()) {
                // not in store – still try cryptographic validation (stateless mode)
            } else if (stored.get().revoked()) {
                return AuthResult.failure("Token revoked");
            }
        }

        try {
            SignedJWT jwt = SignedJWT.parse(token);
            if (!jwt.verify(new MACVerifier(sharedSecret))) {
                return AuthResult.failure("Invalid signature");
            }
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            Date exp = claims.getExpirationTime();
            if (exp != null && exp.before(new Date())) {
                return AuthResult.failure("Token expired");
            }
            String sub = claims.getSubject();
            if (sub == null) {
                return AuthResult.failure("Missing subject");
            }

            Set<String> roles = new HashSet<>();
            Object rolesClaim = claims.getClaim("roles");
            if (rolesClaim instanceof List<?> list) {
                list.forEach(r -> roles.add(String.valueOf(r)));
            } else if (rolesClaim instanceof String s) {
                for (String r : s.split(",")) roles.add(r.trim());
            }

            Set<String> perms = new HashSet<>();
            Object permsClaim = claims.getClaim("permissions");
            if (permsClaim instanceof List<?> list) {
                list.forEach(p -> perms.add(String.valueOf(p)));
            }

            Map<String, Object> attrs = new HashMap<>(claims.getClaims());
            SimplePrincipal principal = new SimplePrincipal(sub, sub, roles, perms, attrs);
            return AuthResult.success(principal, attrs);
        } catch (Exception e) {
            log.debug("JWT validation failed: {}", e.getMessage());
            return AuthResult.failure("JWT validation failed: " + e.getMessage());
        }
    }

    @Override
    public TokenResult issueToken(TokenRequest request) {
        try {
            long ttl = request.ttlSeconds() > 0 ? request.ttlSeconds() : 3600;
            Instant now = Instant.now();
            Instant exp = now.plusSeconds(ttl);
            String jti = UUID.randomUUID().toString();

            JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                    .subject(request.principalId())
                    .issuer(issuer)
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(exp))
                    .jwtID(jti);

            if (request.scopes() != null && !request.scopes().isEmpty()) {
                builder.claim("scope", String.join(" ", request.scopes()));
            }
            if (request.claims() != null) {
                request.claims().forEach(builder::claim);
            }

            SignedJWT jwt = new SignedJWT(
                    new JWSHeader(JWSAlgorithm.HS256),
                    builder.build()
            );
            jwt.sign(new MACSigner(sharedSecret));
            String serialized = jwt.serialize();

            if (tokenStore != null) {
                tokenStore.save(new TokenStore.TokenRecord(
                        jti, serialized, request.type() != null ? request.type() : TokenType.ACCESS,
                        request.principalId(), issuer, now, exp, false,
                        request.claims() != null ? (String) request.claims().get("assumed_role") : null,
                        request.claims() != null ? (String) request.claims().get("impersonated_by") : null,
                        request.claims() != null ? request.claims() : Map.of()
                ));
            }

            return TokenResult.success(serialized, jti,
                    request.type() != null ? request.type() : TokenType.ACCESS,
                    exp, request.claims());
        } catch (JOSEException e) {
            return TokenResult.failure("Failed to sign JWT: " + e.getMessage());
        }
    }

    @Override
    public TokenResult rotateToken(TokenRequest request) {
        if (request.existingToken() != null && tokenStore != null) {
            tokenStore.findByTokenValue(request.existingToken())
                    .ifPresent(r -> tokenStore.revoke(r.tokenId()));
        }
        return issueToken(request);
    }

    @Override
    public void revokeToken(RevokeRequest request) {
        if (tokenStore == null) return;
        if (request.tokenId() != null) {
            tokenStore.revoke(request.tokenId());
        }
        if (request.allForPrincipal() && request.principalId() != null) {
            tokenStore.revokeAllForPrincipal(request.principalId());
        }
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
            case "jwt", "hs256", "rotate", "revoke", "introspect" -> true;
            default -> false;
        };
    }
}

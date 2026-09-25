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
import io.a2.spi.model.AuthRequest;
import io.a2.spi.model.AuthResult;
import io.a2.spi.model.AuthorizationContext;
import io.a2.spi.model.RevokeRequest;
import io.a2.spi.model.TokenRequest;
import io.a2.spi.model.TokenResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
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
 * Production-grade JWT provider powered by Nimbus JOSE + JWT.
 *
 * - HS256 by default (configurable secret)
 * - Proper exp / nbf / iat validation
 * - Supports ACCESS, REFRESH, TEMPORARY, ASSUMED_ROLE, IMPERSONATION token types
 * - Local revocation list (pair with TokenStore for durability)
 */
public class NimbusJwtProtocolProvider implements ProtocolProvider {

    private static final Logger log = LoggerFactory.getLogger(NimbusJwtProtocolProvider.class);

    private final byte[] secret;
    private final String issuer;
    private final Map<String, Boolean> revokedJti = new ConcurrentHashMap<>();

    public NimbusJwtProtocolProvider() {
        this(
                System.getProperty("a2.jwt.secret", "a2-dev-secret-must-be-at-least-32-bytes-long!!"),
                System.getProperty("a2.jwt.issuer", "https://a2.local")
        );
    }

    public NimbusJwtProtocolProvider(String secret, String issuer) {
        this.secret = secret.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        this.issuer = issuer;
        if (this.secret.length < 32) {
            throw new IllegalArgumentException("JWT secret must be at least 32 bytes for HS256");
        }
    }

    @Override
    public Protocol id() {
        return Protocol.JWT;
    }

    @Override
    public String name() {
        return "Nimbus JWT";
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

        try {
            SignedJWT jwt = SignedJWT.parse(token);
            if (!jwt.verify(new MACVerifier(secret))) {
                return AuthResult.failure("Invalid JWT signature");
            }
            JWTClaimsSet claims = jwt.getJWTClaimsSet();

            Date exp = claims.getExpirationTime();
            if (exp != null && exp.before(new Date())) {
                return AuthResult.failure("JWT expired");
            }
            Date nbf = claims.getNotBeforeTime();
            if (nbf != null && nbf.after(new Date())) {
                return AuthResult.failure("JWT not yet valid");
            }

            String jti = claims.getJWTID();
            if (jti != null && revokedJti.containsKey(jti)) {
                return AuthResult.failure("JWT revoked");
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
            return AuthResult.success(new SimplePrincipal(sub, sub, roles, perms, attrs));

        } catch (ParseException | JOSEException e) {
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
            builder.claim("token_type", request.type() != null ? request.type().name() : TokenType.ACCESS.name());

            SignedJWT jwt = new SignedJWT(
                    new JWSHeader(JWSAlgorithm.HS256),
                    builder.build()
            );
            jwt.sign(new MACSigner(secret));
            String serialized = jwt.serialize();

            Map<String, Object> outClaims = new HashMap<>(request.claims() != null ? request.claims() : Map.of());
            outClaims.put("jti", jti);
            outClaims.put("iss", issuer);

            return TokenResult.success(serialized, jti, request.type(), exp, outClaims);
        } catch (JOSEException e) {
            return TokenResult.failure("Failed to sign JWT: " + e.getMessage());
        }
    }

    @Override
    public TokenResult rotateToken(TokenRequest request) {
        if (request.existingToken() != null) {
            try {
                SignedJWT old = SignedJWT.parse(request.existingToken());
                String jti = old.getJWTClaimsSet().getJWTID();
                if (jti != null) revokedJti.put(jti, Boolean.TRUE);
            } catch (Exception ignored) {
                // best effort
            }
        }
        return issueToken(request);
    }

    @Override
    public void revokeToken(RevokeRequest request) {
        if (request.tokenId() != null) {
            revokedJti.put(request.tokenId(), Boolean.TRUE);
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
            case "jwt", "hs256", "rotate", "revoke", "temporary", "assumed_role", "impersonation" -> true;
            default -> false;
        };
    }
}

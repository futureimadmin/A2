package io.a2.provider.jwt;

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

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Minimal JWT-style provider for demonstration and testing.
 * Production use should integrate a proper JWT library (Nimbus, jjwt, etc.).
 *
 * Token format (simplified): header.payload.signature where payload is base64(principalId:roles:exp)
 */
public class JwtProtocolProvider implements ProtocolProvider {

    private final Map<String, Boolean> revoked = new ConcurrentHashMap<>();
    private final String secret; // in real life use proper key management

    public JwtProtocolProvider() {
        this("a2-dev-secret-change-me");
    }

    public JwtProtocolProvider(String secret) {
        this.secret = secret;
    }

    @Override
    public Protocol id() {
        return Protocol.JWT;
    }

    @Override
    public AuthResult authenticate(AuthRequest request) {
        String token = request.credentials();
        if (token == null || token.isBlank()) {
            return AuthResult.failure("Missing token");
        }
        try {
            String[] parts = token.split("\\.");
            if (parts.length < 2) {
                return AuthResult.failure("Malformed token");
            }
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            String[] fields = payload.split(":");
            if (fields.length < 3) {
                return AuthResult.failure("Invalid payload");
            }
            String principalId = fields[0];
            String rolesCsv = fields[1];
            long exp = Long.parseLong(fields[2]);
            if (Instant.now().getEpochSecond() > exp) {
                return AuthResult.failure("Token expired");
            }
            if (revoked.containsKey(token)) {
                return AuthResult.failure("Token revoked");
            }
            Set<String> roles = rolesCsv.isEmpty() ? Set.of() : Set.of(rolesCsv.split(","));
            return AuthResult.success(SimplePrincipal.of(principalId, principalId, roles.toArray(new String[0])));
        } catch (Exception e) {
            return AuthResult.failure("Token validation failed: " + e.getMessage());
        }
    }

    @Override
    public TokenResult issueToken(TokenRequest request) {
        long ttl = request.ttlSeconds() > 0 ? request.ttlSeconds() : 3600;
        long exp = Instant.now().getEpochSecond() + ttl;
        String roles = String.join(",", request.claims().getOrDefault("roles", "").toString());
        // simplistic; real JWT would use proper claims
        String payload = request.principalId() + ":" + roles + ":" + exp;
        String encoded = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payload.getBytes(StandardCharsets.UTF_8));
        String token = "eyJhbGciOiJub25lIn0." + encoded + ".sig"; // header.payload.sig
        String tokenId = UUID.randomUUID().toString();
        return TokenResult.success(token, tokenId, request.type(), Instant.ofEpochSecond(exp));
    }

    @Override
    public TokenResult rotateToken(TokenRequest request) {
        if (request.existingToken() != null) {
            revoked.put(request.existingToken(), Boolean.TRUE);
        }
        return issueToken(request);
    }

    @Override
    public void revokeToken(RevokeRequest request) {
        if (request.tokenId() != null) {
            // we store full token in this simple impl; production would map id -> token
            revoked.put(request.tokenId(), Boolean.TRUE);
        }
    }

    @Override
    public boolean authorize(AuthorizationContext ctx) {
        if (ctx.requiredRoles().isEmpty() && ctx.requiredPermissions().isEmpty()) {
            return true;
        }
        var principal = ctx.principal();
        if (principal == null) return false;
        if (ctx.requireAll()) {
            return principal.getRoles().containsAll(ctx.requiredRoles())
                    && principal.getPermissions().containsAll(ctx.requiredPermissions());
        }
        boolean roleOk = ctx.requiredRoles().isEmpty()
                || ctx.requiredRoles().stream().anyMatch(principal::hasRole);
        boolean permOk = ctx.requiredPermissions().isEmpty()
                || ctx.requiredPermissions().stream().anyMatch(p -> principal.getPermissions().contains(p));
        return roleOk || permOk;
    }
}

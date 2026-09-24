package io.a2.provider.apikey;

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

import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Simple API-Key provider.
 * In production, keys should be stored hashed and associated with principals/roles.
 */
public class ApiKeyProtocolProvider implements ProtocolProvider {

    private final Map<String, KeyRecord> keys = new ConcurrentHashMap<>();

    public ApiKeyProtocolProvider() {
        // demo key
        keys.put("a2-demo-key-12345",
                new KeyRecord("demo-user", Set.of("user"), Set.of("api:read"), true));
    }

    public void registerKey(String key, String principalId, Set<String> roles, Set<String> permissions) {
        keys.put(key, new KeyRecord(principalId, roles, permissions, true));
    }

    @Override
    public Protocol id() {
        return Protocol.API_KEY;
    }

    @Override
    public AuthResult authenticate(AuthRequest request) {
        String key = request.credentials();
        if (key == null) {
            key = request.headers().getOrDefault("X-API-Key",
                    request.headers().get("Authorization"));
        }
        if (key == null || key.isBlank()) {
            return AuthResult.failure("Missing API key");
        }
        if (key.toLowerCase().startsWith("bearer ")) {
            key = key.substring(7).trim();
        }
        KeyRecord rec = keys.get(key);
        if (rec == null || !rec.active) {
            return AuthResult.failure("Invalid or revoked API key");
        }
        return AuthResult.success(new SimplePrincipal(rec.principalId, rec.principalId,
                rec.roles, rec.permissions, Map.of()));
    }

    @Override
    public TokenResult issueToken(TokenRequest request) {
        // API keys are long-lived; we still support issuance for uniformity
        String key = "a2key." + UUID.randomUUID();
        keys.put(key, new KeyRecord(request.principalId(),
                Set.of(), Set.of(), true));
        return TokenResult.success(key, key, TokenType.API_KEY,
                Instant.now().plusSeconds(request.ttlSeconds() > 0 ? request.ttlSeconds() : 31536000L));
    }

    @Override
    public TokenResult rotateToken(TokenRequest request) {
        if (request.existingToken() != null) {
            KeyRecord old = keys.get(request.existingToken());
            if (old != null) {
                old.active = false;
            }
        }
        return issueToken(request);
    }

    @Override
    public void revokeToken(RevokeRequest request) {
        if (request.tokenId() != null) {
            KeyRecord rec = keys.get(request.tokenId());
            if (rec != null) {
                rec.active = false;
            }
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

    private static final class KeyRecord {
        final String principalId;
        final Set<String> roles;
        final Set<String> permissions;
        volatile boolean active;

        KeyRecord(String principalId, Set<String> roles, Set<String> permissions, boolean active) {
            this.principalId = principalId;
            this.roles = roles;
            this.permissions = permissions;
            this.active = active;
        }
    }
}

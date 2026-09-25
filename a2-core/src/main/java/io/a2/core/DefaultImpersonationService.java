package io.a2.core;

import io.a2.annotations.TokenType;
import io.a2.spi.ImpersonationService;
import io.a2.spi.Principal;
import io.a2.spi.SecurityContext;
import io.a2.spi.TokenStore;
import io.a2.spi.TokenService;
import io.a2.spi.model.TokenRequest;
import io.a2.spi.model.TokenResult;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Default implementation of Assumed Role + Impersonation.
 * Issues short-lived tokens (hard-capped at 1 hour for S2S).
 */
public class DefaultImpersonationService implements ImpersonationService {

    public static final long MAX_S2S_TTL_SECONDS = 3600L;

    private final TokenService tokenService;
    private final TokenStore tokenStore;

    public DefaultImpersonationService(TokenService tokenService, TokenStore tokenStore) {
        this.tokenService = tokenService;
        this.tokenStore = tokenStore;
    }

    @Override
    public TokenResult assumeRole(Principal caller, String role, long ttlSeconds, String sessionName) {
        if (caller == null) {
            return TokenResult.failure("Caller principal required");
        }
        // In production: check that caller is allowed to assume this role (policy / IAM)
        long ttl = Math.min(ttlSeconds > 0 ? ttlSeconds : MAX_S2S_TTL_SECONDS, MAX_S2S_TTL_SECONDS);

        Map<String, Object> claims = new HashMap<>();
        claims.put("assumed_role", role);
        claims.put("original_principal", caller.getId());
        claims.put("session_name", sessionName != null ? sessionName : UUID.randomUUID().toString());
        claims.put("token_use", "assumed_role");

        TokenRequest req = TokenRequest.builder()
                .type(TokenType.ACCESS)
                .principalId(caller.getId() + ":assumed:" + role)
                .ttlSeconds(ttl)
                .claims(claims)
                .scopes("assumed-role", role)
                .build();

        TokenResult result = tokenService.issue(req);
        if (result.isSuccess() && tokenStore != null) {
            tokenStore.save(new TokenStore.TokenRecord(
                    result.tokenId().orElseThrow(),
                    result.token().orElseThrow(),
                    TokenType.ACCESS,
                    caller.getId(),
                    "a2",
                    Instant.now(),
                    result.expiresAt().orElse(Instant.now().plusSeconds(ttl)),
                    false,
                    role,
                    null,
                    claims
            ));
        }
        return result;
    }

    @Override
    public TokenResult impersonate(Principal caller, String targetPrincipalId, long ttlSeconds, String reason) {
        if (caller == null) {
            return TokenResult.failure("Caller principal required");
        }
        if (reason == null || reason.isBlank()) {
            return TokenResult.failure("Impersonation requires a non-blank reason for audit");
        }
        // Production: verify caller has "impersonate" permission and is not already impersonating
        if (!caller.hasRole("admin") && !caller.getPermissions().contains("impersonate")) {
            return TokenResult.failure("Caller lacks impersonate permission");
        }

        long ttl = Math.min(ttlSeconds > 0 ? ttlSeconds : MAX_S2S_TTL_SECONDS, MAX_S2S_TTL_SECONDS);

        Map<String, Object> claims = new HashMap<>();
        claims.put("impersonated_by", caller.getId());
        claims.put("impersonation_reason", reason);
        claims.put("token_use", "impersonation");

        TokenRequest req = TokenRequest.builder()
                .type(TokenType.ACCESS)
                .principalId(targetPrincipalId)
                .ttlSeconds(ttl)
                .claims(claims)
                .scopes("impersonation")
                .build();

        TokenResult result = tokenService.issue(req);
        if (result.isSuccess() && tokenStore != null) {
            tokenStore.save(new TokenStore.TokenRecord(
                    result.tokenId().orElseThrow(),
                    result.token().orElseThrow(),
                    TokenType.ACCESS,
                    targetPrincipalId,
                    "a2",
                    Instant.now(),
                    result.expiresAt().orElse(Instant.now().plusSeconds(ttl)),
                    false,
                    null,
                    caller.getId(),
                    claims
            ));
        }
        return result;
    }

    @Override
    public boolean isAssumedOrImpersonated(SecurityContext ctx) {
        if (ctx == null || !ctx.isAuthenticated()) return false;
        Map<String, Object> claims = ctx.claims();
        return claims.containsKey("assumed_role") || claims.containsKey("impersonated_by");
    }

    @Override
    public Principal getOriginalPrincipal(SecurityContext ctx) {
        if (ctx == null) return null;
        Map<String, Object> claims = ctx.claims();
        if (claims.containsKey("original_principal")) {
            String id = String.valueOf(claims.get("original_principal"));
            return SimplePrincipal.of(id, id);
        }
        if (claims.containsKey("impersonated_by")) {
            String id = String.valueOf(claims.get("impersonated_by"));
            return SimplePrincipal.of(id, id);
        }
        return ctx.principal().orElse(null);
    }
}

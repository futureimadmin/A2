package io.a2.core;

import io.a2.annotations.Protocol;
import io.a2.annotations.TokenType;
import io.a2.spi.AssumeRoleService;
import io.a2.spi.TokenService;
import io.a2.spi.TokenStore;
import io.a2.spi.model.AssumeRoleRequest;
import io.a2.spi.model.StoredToken;
import io.a2.spi.model.TokenRequest;
import io.a2.spi.model.TokenResult;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Default implementation of AssumeRole / Impersonation / Temporary credentials.
 * Issues short-lived tokens (default 1 hour) and records them in the TokenStore.
 */
public class DefaultAssumeRoleService implements AssumeRoleService {

    private final TokenService tokenService;
    private final TokenStore tokenStore;

    public DefaultAssumeRoleService(TokenService tokenService, TokenStore tokenStore) {
        this.tokenService = tokenService;
        this.tokenStore = tokenStore;
    }

    @Override
    public TokenResult assumeRole(AssumeRoleRequest request) {
        if (request.requireDelegationPermission()) {
            // In a full system we would check that caller has "sts:AssumeRole" or similar.
            // Here we record the intent; policy engines can plug in later.
        }

        long ttl = request.durationSeconds() > 0 ? request.durationSeconds() : 3600;
        Instant exp = Instant.now().plusSeconds(ttl);

        Map<String, Object> claims = new HashMap<>();
        claims.put("assumed_role", request.role());
        claims.put("caller", request.callerPrincipalId());
        claims.put("session_name", request.sessionName() != null ? request.sessionName() : "a2-session");
        if (!request.policies().isEmpty()) {
            claims.put("policies", String.join(",", request.policies()));
        }

        // The effective principal becomes role@assumed
        String effectivePrincipal = request.role() + "@assumed";

        TokenResult issued = tokenService.issue(TokenRequest.builder()
                .type(TokenType.ASSUMED_ROLE)
                .principalId(effectivePrincipal)
                .ttlSeconds(ttl)
                .protocol(Protocol.JWT)
                .claims(claims)
                .build());

        if (issued.isSuccess()) {
            StoredToken stored = StoredToken.builder()
                    .tokenId(issued.tokenId().orElse(UUID.randomUUID().toString()))
                    .rawToken(issued.token().orElse(null))
                    .type(TokenType.ASSUMED_ROLE)
                    .principalId(effectivePrincipal)
                    .protocol(Protocol.JWT)
                    .issuedAt(Instant.now())
                    .expiresAt(exp)
                    .claims(claims)
                    .sessionName(request.sessionName())
                    .build();
            tokenStore.save(stored);
        }
        return issued;
    }

    @Override
    public TokenResult impersonate(String callerPrincipalId, String targetPrincipalId,
                                   long durationSeconds, String reason) {
        long ttl = durationSeconds > 0 ? durationSeconds : 3600;
        Instant exp = Instant.now().plusSeconds(ttl);

        Map<String, Object> claims = new HashMap<>();
        claims.put("impersonator", callerPrincipalId);
        claims.put("impersonated", targetPrincipalId);
        claims.put("reason", reason != null ? reason : "impersonation");

        TokenResult issued = tokenService.issue(TokenRequest.builder()
                .type(TokenType.IMPERSONATION)
                .principalId(targetPrincipalId)
                .ttlSeconds(ttl)
                .protocol(Protocol.JWT)
                .claims(claims)
                .build());

        if (issued.isSuccess()) {
            StoredToken stored = StoredToken.builder()
                    .tokenId(issued.tokenId().orElse(UUID.randomUUID().toString()))
                    .rawToken(issued.token().orElse(null))
                    .type(TokenType.IMPERSONATION)
                    .principalId(targetPrincipalId)
                    .protocol(Protocol.JWT)
                    .issuedAt(Instant.now())
                    .expiresAt(exp)
                    .claims(claims)
                    .build();
            tokenStore.save(stored);
        }
        return issued;
    }

    @Override
    public TokenResult issueTemporaryCredential(String principalId, String audience,
                                                long durationSeconds, String... scopes) {
        long ttl = durationSeconds > 0 ? durationSeconds : 3600; // default 1 hour
        if (ttl > 12 * 3600) {
            ttl = 12 * 3600; // hard cap 12h
        }
        Instant exp = Instant.now().plusSeconds(ttl);

        Map<String, Object> claims = new HashMap<>();
        claims.put("aud", audience != null ? audience : "");
        claims.put("token_use", "temporary");
        if (scopes != null && scopes.length > 0) {
            claims.put("scope", String.join(" ", scopes));
        }

        TokenResult issued = tokenService.issue(TokenRequest.builder()
                .type(TokenType.TEMPORARY)
                .principalId(principalId)
                .ttlSeconds(ttl)
                .protocol(Protocol.JWT)
                .scopes(scopes)
                .claims(claims)
                .build());

        if (issued.isSuccess()) {
            StoredToken stored = StoredToken.builder()
                    .tokenId(issued.tokenId().orElse(UUID.randomUUID().toString()))
                    .rawToken(issued.token().orElse(null))
                    .type(TokenType.TEMPORARY)
                    .principalId(principalId)
                    .protocol(Protocol.JWT)
                    .issuedAt(Instant.now())
                    .expiresAt(exp)
                    .claims(claims)
                    .audience(audience)
                    .build();
            tokenStore.save(stored);
        }
        return issued;
    }
}

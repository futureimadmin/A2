package io.a2.core;

import io.a2.annotations.InstantMode;
import io.a2.annotations.Protocol;
import io.a2.annotations.TokenType;
import io.a2.spi.AssumeRoleService;
import io.a2.spi.InstantCredentialsService;
import io.a2.spi.TokenService;
import io.a2.spi.TokenStore;
import io.a2.spi.model.AssumeRoleRequest;
import io.a2.spi.model.InstantCredentialsRequest;
import io.a2.spi.model.TokenRequest;
import io.a2.spi.model.TokenResult;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/** Default InstantCredentialsService: hard-caps TTL at 1 hour; dispatches by InstantMode. */
public class DefaultInstantCredentialsService implements InstantCredentialsService {

    private final TokenService tokenService;
    private final TokenStore tokenStore;
    private final AssumeRoleService assumeRoleService;

    public DefaultInstantCredentialsService(TokenService tokenService, TokenStore tokenStore) {
        this(tokenService, tokenStore, new DefaultAssumeRoleService(tokenService, tokenStore));
    }

    public DefaultInstantCredentialsService(TokenService tokenService, TokenStore tokenStore,
                                            AssumeRoleService assumeRoleService) {
        this.tokenService = Objects.requireNonNull(tokenService);
        this.tokenStore = Objects.requireNonNull(tokenStore);
        this.assumeRoleService = Objects.requireNonNull(assumeRoleService);
    }

    @Override
    public TokenResult issue(InstantCredentialsRequest request) {
        Objects.requireNonNull(request, "request");
        long ttl = Math.min(
                request.ttlSeconds() > 0 ? request.ttlSeconds() : InstantCredentialsRequest.MAX_TTL_SECONDS,
                InstantCredentialsRequest.MAX_TTL_SECONDS);

        return switch (request.mode()) {
            case ASSUME_ROLE -> issueAssumeRole(request, ttl);
            case IMPERSONATE -> issueImpersonate(request, ttl);
            case SERVICE -> issueService(request, ttl);
        };
    }

    private TokenResult issueAssumeRole(InstantCredentialsRequest request, long ttl) {
        if (request.role() == null || request.role().isBlank()) {
            return TokenResult.failure("ASSUME_ROLE requires role");
        }
        AssumeRoleRequest arr = AssumeRoleRequest.builder()
                .callerPrincipalId(request.callerPrincipalId())
                .role(request.role())
                .durationSeconds(ttl)
                .sessionName(request.sessionName().isBlank() ? "a2-instant" : request.sessionName())
                .policies(request.scopes().toArray(String[]::new))
                .build();
        return assumeRoleService.assumeRole(arr);
    }

    private TokenResult issueImpersonate(InstantCredentialsRequest request, long ttl) {
        String target = request.targetPrincipalId();
        if (target == null || target.isBlank()) {
            return TokenResult.failure(
                    "IMPERSONATE requires targetPrincipal (source=caller, target=SA/principal)");
        }
        String reason = request.reason().isBlank() ? "a2-instant-impersonation" : request.reason();
        return assumeRoleService.impersonate(
                request.callerPrincipalId(), target, ttl, reason);
    }

    private TokenResult issueService(InstantCredentialsRequest request, long ttl) {
        Instant exp = Instant.now().plusSeconds(ttl);
        Map<String, Object> claims = new HashMap<>();
        claims.put("token_use", "instant_service");
        claims.put("a2.instant.mode", InstantMode.SERVICE.name());
        claims.put("aud", request.audience() != null ? request.audience() : "");
        claims.put("caller", request.callerPrincipalId());
        if (!request.scopes().isEmpty()) {
            claims.put("scope", String.join(" ", request.scopes()));
        }

        TokenResult issued = tokenService.issue(TokenRequest.builder()
                .type(TokenType.TEMPORARY)
                .principalId(request.callerPrincipalId())
                .ttlSeconds(ttl)
                .protocol(Protocol.JWT)
                .scopes(request.scopes().toArray(String[]::new))
                .claims(claims)
                .build());

        if (issued.isSuccess()) {
            tokenStore.save(new TokenStore.TokenRecord(
                    issued.tokenId().orElse(UUID.randomUUID().toString()),
                    issued.token().orElse(null),
                    TokenType.TEMPORARY,
                    request.callerPrincipalId(),
                    request.audience(),
                    Instant.now(),
                    exp,
                    false,
                    null,
                    null,
                    claims));
        }
        return issued;
    }
}

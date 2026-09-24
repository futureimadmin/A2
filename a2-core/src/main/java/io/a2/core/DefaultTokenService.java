package io.a2.core;

import io.a2.annotations.Protocol;
import io.a2.annotations.TokenType;
import io.a2.spi.ProtocolProvider;
import io.a2.spi.TokenService;
import io.a2.spi.model.RevokeRequest;
import io.a2.spi.model.TokenRequest;
import io.a2.spi.model.TokenResult;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Simple in-memory TokenService for development and testing.
 * Production deployments should replace this with a persistent / distributed store
 * or delegate to a concrete ProtocolProvider (e.g. OIDC provider).
 */
public class DefaultTokenService implements TokenService {

    private final Map<String, TokenResult> store = new ConcurrentHashMap<>();
    private final Map<String, String> principalIndex = new ConcurrentHashMap<>(); // tokenId -> principalId

    @Override
    public TokenResult issue(TokenRequest request) {
        Protocol protocol = request.protocol() != null ? request.protocol() : Protocol.JWT;
        Optional<ProtocolProvider> provider = A2Runtime.get().provider(protocol);
        if (provider.isPresent()) {
            return provider.get().issueToken(request);
        }
        // Fallback: simple opaque token
        String tokenId = UUID.randomUUID().toString();
        String token = "a2." + tokenId;
        TokenResult result = TokenResult.success(token, tokenId, request.type(),
                java.time.Instant.now().plusSeconds(request.ttlSeconds() > 0 ? request.ttlSeconds() : 3600),
                request.claims());
        store.put(tokenId, result);
        if (request.principalId() != null) {
            principalIndex.put(tokenId, request.principalId());
        }
        return result;
    }

    @Override
    public TokenResult rotate(TokenRequest request) {
        if (request.existingToken() != null) {
            // naive: revoke old, issue new
            introspect(request.existingToken()).ifPresent(old ->
                    old.tokenId().ifPresent(this::revoke));
        }
        return issue(request);
    }

    @Override
    public void revoke(String tokenId) {
        store.remove(tokenId);
        principalIndex.remove(tokenId);
    }

    @Override
    public void revokeAllForPrincipal(String principalId) {
        principalIndex.entrySet().stream()
                .filter(e -> principalId.equals(e.getValue()))
                .map(Map.Entry::getKey)
                .forEach(this::revoke);
    }

    @Override
    public Optional<TokenResult> introspect(String token) {
        if (token == null) return Optional.empty();
        String id = token.startsWith("a2.") ? token.substring(3) : token;
        return Optional.ofNullable(store.get(id));
    }
}

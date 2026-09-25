package io.a2.core.store;

import io.a2.annotations.TokenType;
import io.a2.spi.TokenStore;
import io.a2.spi.model.StoredToken;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Thread-safe in-memory TokenStore. Suitable for single-node / test use.
 * For production use JdbcTokenStore or a Redis-backed implementation.
 */
public class InMemoryTokenStore implements TokenStore {

    private final Map<String, StoredToken> byId = new ConcurrentHashMap<>();
    private final Map<String, String> rawToId = new ConcurrentHashMap<>();

    @Override
    public void save(StoredToken token) {
        byId.put(token.tokenId(), token);
        if (token.rawToken() != null) {
            rawToId.put(token.rawToken(), token.tokenId());
        }
    }

    @Override
    public Optional<StoredToken> findById(String tokenId) {
        return Optional.ofNullable(byId.get(tokenId));
    }

    @Override
    public Optional<StoredToken> findByRawToken(String rawToken) {
        String id = rawToId.get(rawToken);
        return id == null ? Optional.empty() : findById(id);
    }

    @Override
    public List<StoredToken> findByPrincipal(String principalId) {
        return byId.values().stream()
                .filter(t -> principalId.equals(t.principalId()))
                .collect(Collectors.toList());
    }

    @Override
    public List<StoredToken> findByPrincipalAndType(String principalId, TokenType type) {
        return byId.values().stream()
                .filter(t -> principalId.equals(t.principalId()) && type == t.type())
                .collect(Collectors.toList());
    }

    @Override
    public void revoke(String tokenId) {
        StoredToken existing = byId.get(tokenId);
        if (existing != null) {
            StoredToken revoked = existing.toBuilder().revoked(true).build();
            byId.put(tokenId, revoked);
        }
    }

    @Override
    public void revokeAllForPrincipal(String principalId) {
        findByPrincipal(principalId).forEach(t -> revoke(t.tokenId()));
    }

    @Override
    public void revokeExpired(Instant before) {
        byId.values().stream()
                .filter(t -> t.expiresAt() != null && t.expiresAt().isBefore(before))
                .forEach(t -> revoke(t.tokenId()));
    }
}

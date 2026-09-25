package io.a2.core.store;

import io.a2.spi.TokenStore;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Thread-safe in-memory TokenStore. Suitable for single-node / tests.
 * For production use JdbcTokenStore or a Redis-backed implementation.
 */
public class InMemoryTokenStore implements TokenStore {

    private final Map<String, TokenRecord> byId = new ConcurrentHashMap<>();
    private final Map<String, String> valueToId = new ConcurrentHashMap<>();

    @Override
    public void save(TokenRecord record) {
        byId.put(record.tokenId(), record);
        valueToId.put(record.tokenValue(), record.tokenId());
    }

    @Override
    public Optional<TokenRecord> findById(String tokenId) {
        return Optional.ofNullable(byId.get(tokenId))
                .filter(r -> !r.revoked())
                .filter(r -> r.expiresAt().isAfter(Instant.now()));
    }

    @Override
    public Optional<TokenRecord> findByTokenValue(String tokenValue) {
        String id = valueToId.get(tokenValue);
        if (id == null) return Optional.empty();
        return findById(id);
    }

    @Override
    public List<TokenRecord> findByPrincipal(String principalId) {
        return byId.values().stream()
                .filter(r -> principalId.equals(r.principalId()))
                .filter(r -> !r.revoked())
                .filter(r -> r.expiresAt().isAfter(Instant.now()))
                .collect(Collectors.toList());
    }

    @Override
    public void revoke(String tokenId) {
        TokenRecord existing = byId.get(tokenId);
        if (existing != null) {
            byId.put(tokenId, new TokenRecord(
                    existing.tokenId(), existing.tokenValue(), existing.type(),
                    existing.principalId(), existing.issuer(), existing.issuedAt(),
                    existing.expiresAt(), true, existing.assumedRole(),
                    existing.impersonatedBy(), existing.claims()));
        }
    }

    @Override
    public void revokeAllForPrincipal(String principalId) {
        byId.values().stream()
                .filter(r -> principalId.equals(r.principalId()))
                .forEach(r -> revoke(r.tokenId()));
    }

    @Override
    public int purgeExpired() {
        Instant now = Instant.now();
        List<String> expired = byId.values().stream()
                .filter(r -> r.expiresAt().isBefore(now) || r.revoked())
                .map(TokenRecord::tokenId)
                .toList();
        expired.forEach(id -> {
            TokenRecord r = byId.remove(id);
            if (r != null) valueToId.remove(r.tokenValue());
        });
        return expired.size();
    }
}

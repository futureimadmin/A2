package io.a2.spi;

import io.a2.annotations.TokenType;
import io.a2.spi.model.StoredToken;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Persistent (or durable) storage for issued tokens.
 * Implementations: in-memory, JDBC, Redis, etc.
 */
public interface TokenStore {

    void save(StoredToken token);

    Optional<StoredToken> findById(String tokenId);

    Optional<StoredToken> findByRawToken(String rawToken);

    List<StoredToken> findByPrincipal(String principalId);

    List<StoredToken> findByPrincipalAndType(String principalId, TokenType type);

    void revoke(String tokenId);

    void revokeAllForPrincipal(String principalId);

    void revokeExpired(Instant before);

    /** Delete tokens that have been expired longer than the given retention. */
    default void purge(Instant olderThan) {
        revokeExpired(olderThan);
    }
}

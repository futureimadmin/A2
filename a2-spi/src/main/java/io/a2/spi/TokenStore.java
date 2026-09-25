package io.a2.spi;

import io.a2.annotations.TokenType;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Persistent (or distributed) token storage SPI.
 * Implementations: InMemory, JDBC, Redis, etc.
 */
public interface TokenStore {

    void save(TokenRecord record);

    Optional<TokenRecord> findById(String tokenId);

    Optional<TokenRecord> findByTokenValue(String tokenValue);

    List<TokenRecord> findByPrincipal(String principalId);

    void revoke(String tokenId);

    void revokeAllForPrincipal(String principalId);

    /** Delete expired tokens (housekeeping). */
    int purgeExpired();

    record TokenRecord(
            String tokenId,
            String tokenValue,
            TokenType type,
            String principalId,
            String issuer,
            Instant issuedAt,
            Instant expiresAt,
            boolean revoked,
            String assumedRole,          // null if none
            String impersonatedBy,       // principal who assumed / impersonated
            java.util.Map<String, Object> claims
    ) {}
}

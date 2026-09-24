package io.a2.spi.model;

import io.a2.annotations.TokenType;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;

public final class TokenResult {

    private final boolean success;
    private final String token;
    private final String tokenId;
    private final TokenType type;
    private final Instant expiresAt;
    private final Map<String, Object> claims;
    private final String error;

    private TokenResult(boolean success, String token, String tokenId, TokenType type,
                        Instant expiresAt, Map<String, Object> claims, String error) {
        this.success = success;
        this.token = token;
        this.tokenId = tokenId;
        this.type = type;
        this.expiresAt = expiresAt;
        this.claims = claims == null ? Collections.emptyMap() : Map.copyOf(claims);
        this.error = error;
    }

    public static TokenResult success(String token, String tokenId, TokenType type, Instant expiresAt) {
        return new TokenResult(true, token, tokenId, type, expiresAt, null, null);
    }

    public static TokenResult success(String token, String tokenId, TokenType type,
                                      Instant expiresAt, Map<String, Object> claims) {
        return new TokenResult(true, token, tokenId, type, expiresAt, claims, null);
    }

    public static TokenResult failure(String error) {
        return new TokenResult(false, null, null, null, null, null, error);
    }

    public boolean isSuccess() { return success; }
    public Optional<String> token() { return Optional.ofNullable(token); }
    public Optional<String> tokenId() { return Optional.ofNullable(tokenId); }
    public Optional<TokenType> type() { return Optional.ofNullable(type); }
    public Optional<Instant> expiresAt() { return Optional.ofNullable(expiresAt); }
    public Map<String, Object> claims() { return claims; }
    public Optional<String> error() { return Optional.ofNullable(error); }
}

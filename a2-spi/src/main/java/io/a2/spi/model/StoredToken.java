package io.a2.spi.model;

import io.a2.annotations.Protocol;
import io.a2.annotations.TokenType;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;

/**
 * Durable representation of an issued token.
 */
public final class StoredToken {

    private final String tokenId;
    private final String rawToken;          // may be hashed in production stores
    private final TokenType type;
    private final String principalId;
    private final Protocol protocol;
    private final Instant issuedAt;
    private final Instant expiresAt;
    private final Map<String, Object> claims;
    private final boolean revoked;
    private final String parentTokenId;     // for rotated / assumed / impersonated tokens
    private final String audience;
    private final String sessionName;       // assume-role session name

    private StoredToken(Builder b) {
        this.tokenId = Objects.requireNonNull(b.tokenId);
        this.rawToken = b.rawToken;
        this.type = b.type;
        this.principalId = b.principalId;
        this.protocol = b.protocol;
        this.issuedAt = b.issuedAt != null ? b.issuedAt : Instant.now();
        this.expiresAt = b.expiresAt;
        this.claims = b.claims == null ? Collections.emptyMap() : Map.copyOf(b.claims);
        this.revoked = b.revoked;
        this.parentTokenId = b.parentTokenId;
        this.audience = b.audience;
        this.sessionName = b.sessionName;
    }

    public String tokenId() { return tokenId; }
    public String rawToken() { return rawToken; }
    public TokenType type() { return type; }
    public String principalId() { return principalId; }
    public Protocol protocol() { return protocol; }
    public Instant issuedAt() { return issuedAt; }
    public Instant expiresAt() { return expiresAt; }
    public Map<String, Object> claims() { return claims; }
    public boolean revoked() { return revoked; }
    public String parentTokenId() { return parentTokenId; }
    public String audience() { return audience; }
    public String sessionName() { return sessionName; }

    public boolean isExpired() {
        return expiresAt != null && Instant.now().isAfter(expiresAt);
    }

    public boolean isActive() {
        return !revoked && !isExpired();
    }

    public static Builder builder() { return new Builder(); }

    public Builder toBuilder() {
        return new Builder()
                .tokenId(tokenId)
                .rawToken(rawToken)
                .type(type)
                .principalId(principalId)
                .protocol(protocol)
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .claims(claims)
                .revoked(revoked)
                .parentTokenId(parentTokenId)
                .audience(audience)
                .sessionName(sessionName);
    }

    public static final class Builder {
        private String tokenId;
        private String rawToken;
        private TokenType type;
        private String principalId;
        private Protocol protocol;
        private Instant issuedAt;
        private Instant expiresAt;
        private Map<String, Object> claims;
        private boolean revoked;
        private String parentTokenId;
        private String audience;
        private String sessionName;

        public Builder tokenId(String v) { this.tokenId = v; return this; }
        public Builder rawToken(String v) { this.rawToken = v; return this; }
        public Builder type(TokenType v) { this.type = v; return this; }
        public Builder principalId(String v) { this.principalId = v; return this; }
        public Builder protocol(Protocol v) { this.protocol = v; return this; }
        public Builder issuedAt(Instant v) { this.issuedAt = v; return this; }
        public Builder expiresAt(Instant v) { this.expiresAt = v; return this; }
        public Builder claims(Map<String, Object> v) { this.claims = v; return this; }
        public Builder revoked(boolean v) { this.revoked = v; return this; }
        public Builder parentTokenId(String v) { this.parentTokenId = v; return this; }
        public Builder audience(String v) { this.audience = v; return this; }
        public Builder sessionName(String v) { this.sessionName = v; return this; }
        public StoredToken build() { return new StoredToken(this); }
    }
}

package io.a2.spi.model;

import io.a2.annotations.Protocol;
import io.a2.annotations.TokenType;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public final class TokenRequest {

    private final TokenType type;
    private final String principalId;
    private final List<String> scopes;
    private final Map<String, Object> claims;
    private final long ttlSeconds;
    private final Protocol protocol;
    private final String existingToken;   // for rotate

    private TokenRequest(Builder b) {
        this.type = b.type;
        this.principalId = b.principalId;
        this.scopes = b.scopes == null ? Collections.emptyList() : List.copyOf(b.scopes);
        this.claims = b.claims == null ? Collections.emptyMap() : Map.copyOf(b.claims);
        this.ttlSeconds = b.ttlSeconds;
        this.protocol = b.protocol;
        this.existingToken = b.existingToken;
    }

    public TokenType type() { return type; }
    public String principalId() { return principalId; }
    public List<String> scopes() { return scopes; }
    public Map<String, Object> claims() { return claims; }
    public long ttlSeconds() { return ttlSeconds; }
    public Protocol protocol() { return protocol; }
    public String existingToken() { return existingToken; }

    public static Builder builder() { return new Builder(); }

    public static final class Builder {
        private TokenType type = TokenType.ACCESS;
        private String principalId;
        private List<String> scopes;
        private Map<String, Object> claims;
        private long ttlSeconds;
        private Protocol protocol;
        private String existingToken;

        public Builder type(TokenType t) { this.type = t; return this; }
        public Builder principalId(String id) { this.principalId = id; return this; }
        public Builder scopes(String... s) { this.scopes = Arrays.asList(s); return this; }
        public Builder scopes(List<String> s) { this.scopes = s; return this; }
        public Builder claims(Map<String, Object> c) { this.claims = c; return this; }
        public Builder ttlSeconds(long t) { this.ttlSeconds = t; return this; }
        public Builder protocol(Protocol p) { this.protocol = p; return this; }
        public Builder existingToken(String t) { this.existingToken = t; return this; }
        public TokenRequest build() { return new TokenRequest(this); }
    }
}

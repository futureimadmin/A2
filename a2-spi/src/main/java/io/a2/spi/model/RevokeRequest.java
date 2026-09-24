package io.a2.spi.model;

import io.a2.annotations.TokenType;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public final class RevokeRequest {

    private final String tokenId;
    private final String principalId;
    private final List<TokenType> types;
    private final boolean allForPrincipal;
    private final String reason;

    private RevokeRequest(Builder b) {
        this.tokenId = b.tokenId;
        this.principalId = b.principalId;
        this.types = b.types == null ? Collections.emptyList() : List.copyOf(b.types);
        this.allForPrincipal = b.allForPrincipal;
        this.reason = b.reason;
    }

    public String tokenId() { return tokenId; }
    public String principalId() { return principalId; }
    public List<TokenType> types() { return types; }
    public boolean allForPrincipal() { return allForPrincipal; }
    public String reason() { return reason; }

    public static Builder builder() { return new Builder(); }

    public static final class Builder {
        private String tokenId;
        private String principalId;
        private List<TokenType> types;
        private boolean allForPrincipal;
        private String reason = "explicit";

        public Builder tokenId(String id) { this.tokenId = id; return this; }
        public Builder principalId(String id) { this.principalId = id; return this; }
        public Builder types(TokenType... t) { this.types = Arrays.asList(t); return this; }
        public Builder allForPrincipal(boolean v) { this.allForPrincipal = v; return this; }
        public Builder reason(String r) { this.reason = r; return this; }
        public RevokeRequest build() { return new RevokeRequest(this); }
    }
}

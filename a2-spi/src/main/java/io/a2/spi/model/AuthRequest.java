package io.a2.spi.model;

import io.a2.annotations.Protocol;

import java.util.Collections;
import java.util.Map;

public final class AuthRequest {

    private final Protocol protocol;
    private final String credentials;          // password, assertion, ticket, api-key, etc.
    private final Map<String, String> headers;
    private final Map<String, Object> attributes;

    private AuthRequest(Builder b) {
        this.protocol = b.protocol;
        this.credentials = b.credentials;
        this.headers = b.headers == null ? Collections.emptyMap() : Map.copyOf(b.headers);
        this.attributes = b.attributes == null ? Collections.emptyMap() : Map.copyOf(b.attributes);
    }

    public Protocol protocol() { return protocol; }
    public String credentials() { return credentials; }
    public Map<String, String> headers() { return headers; }
    public Map<String, Object> attributes() { return attributes; }

    public static Builder builder() { return new Builder(); }

    public static final class Builder {
        private Protocol protocol;
        private String credentials;
        private Map<String, String> headers;
        private Map<String, Object> attributes;

        public Builder protocol(Protocol p) { this.protocol = p; return this; }
        public Builder credentials(String c) { this.credentials = c; return this; }
        public Builder headers(Map<String, String> h) { this.headers = h; return this; }
        public Builder attributes(Map<String, Object> a) { this.attributes = a; return this; }
        public AuthRequest build() { return new AuthRequest(this); }
    }
}

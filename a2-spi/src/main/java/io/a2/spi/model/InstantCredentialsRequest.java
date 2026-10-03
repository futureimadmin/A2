package io.a2.spi.model;

import io.a2.annotations.InstantMode;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/** Request to issue A2 instant (short-lived, ≤ 1h) credentials. */
public final class InstantCredentialsRequest {

    public static final long MAX_TTL_SECONDS = 3600L;

    private final InstantMode mode;
    private final String callerPrincipalId;
    private final String role;
    private final String targetPrincipalId;
    private final String audience;
    private final List<String> scopes;
    private final String sessionName;
    private final String reason;
    private final long ttlSeconds;

    private InstantCredentialsRequest(Builder b) {
        this.mode = Objects.requireNonNull(b.mode, "mode");
        this.callerPrincipalId = Objects.requireNonNull(b.callerPrincipalId, "callerPrincipalId");
        this.role = b.role != null ? b.role : "";
        this.targetPrincipalId = b.targetPrincipalId != null ? b.targetPrincipalId : "";
        this.audience = b.audience != null ? b.audience : "";
        this.scopes = b.scopes == null ? Collections.emptyList() : List.copyOf(b.scopes);
        this.sessionName = b.sessionName != null ? b.sessionName : "";
        this.reason = b.reason != null ? b.reason : "";
        long ttl = b.ttlSeconds > 0 ? b.ttlSeconds : MAX_TTL_SECONDS;
        this.ttlSeconds = Math.min(ttl, MAX_TTL_SECONDS);
    }

    public InstantMode mode() { return mode; }
    public String callerPrincipalId() { return callerPrincipalId; }
    public String role() { return role; }
    public String targetPrincipalId() { return targetPrincipalId; }
    public String audience() { return audience; }
    public List<String> scopes() { return scopes; }
    public String sessionName() { return sessionName; }
    public String reason() { return reason; }
    public long ttlSeconds() { return ttlSeconds; }

    public static Builder builder(InstantMode mode) { return new Builder(mode); }

    public static final class Builder {
        private final InstantMode mode;
        private String callerPrincipalId;
        private String role;
        private String targetPrincipalId;
        private String audience;
        private List<String> scopes;
        private String sessionName;
        private String reason;
        private long ttlSeconds = MAX_TTL_SECONDS;

        private Builder(InstantMode mode) { this.mode = mode; }

        public Builder callerPrincipalId(String v) { this.callerPrincipalId = v; return this; }
        public Builder role(String v) { this.role = v; return this; }
        public Builder targetPrincipalId(String v) { this.targetPrincipalId = v; return this; }
        public Builder audience(String v) { this.audience = v; return this; }
        public Builder scopes(String... v) {
            this.scopes = v == null ? List.of() : Arrays.asList(v);
            return this;
        }
        public Builder scopes(List<String> v) { this.scopes = v; return this; }
        public Builder sessionName(String v) { this.sessionName = v; return this; }
        public Builder reason(String v) { this.reason = v; return this; }
        public Builder ttlSeconds(long v) { this.ttlSeconds = v; return this; }

        public InstantCredentialsRequest build() { return new InstantCredentialsRequest(this); }
    }
}

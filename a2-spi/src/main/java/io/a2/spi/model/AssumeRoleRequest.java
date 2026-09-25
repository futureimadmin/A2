package io.a2.spi.model;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public final class AssumeRoleRequest {

    private final String callerPrincipalId;
    private final String role;
    private final long durationSeconds;
    private final String sessionName;
    private final List<String> policies;
    private final boolean requireDelegationPermission;

    private AssumeRoleRequest(Builder b) {
        this.callerPrincipalId = b.callerPrincipalId;
        this.role = b.role;
        this.durationSeconds = b.durationSeconds > 0 ? b.durationSeconds : 3600;
        this.sessionName = b.sessionName;
        this.policies = b.policies == null ? Collections.emptyList() : List.copyOf(b.policies);
        this.requireDelegationPermission = b.requireDelegationPermission;
    }

    public String callerPrincipalId() { return callerPrincipalId; }
    public String role() { return role; }
    public long durationSeconds() { return durationSeconds; }
    public String sessionName() { return sessionName; }
    public List<String> policies() { return policies; }
    public boolean requireDelegationPermission() { return requireDelegationPermission; }

    public static Builder builder() { return new Builder(); }

    public static final class Builder {
        private String callerPrincipalId;
        private String role;
        private long durationSeconds = 3600;
        private String sessionName;
        private List<String> policies;
        private boolean requireDelegationPermission = true;

        public Builder callerPrincipalId(String v) { this.callerPrincipalId = v; return this; }
        public Builder role(String v) { this.role = v; return this; }
        public Builder durationSeconds(long v) { this.durationSeconds = v; return this; }
        public Builder sessionName(String v) { this.sessionName = v; return this; }
        public Builder policies(String... v) { this.policies = Arrays.asList(v); return this; }
        public Builder requireDelegationPermission(boolean v) { this.requireDelegationPermission = v; return this; }
        public AssumeRoleRequest build() { return new AssumeRoleRequest(this); }
    }
}

package io.a2.spi.model;

import io.a2.spi.Principal;
import io.a2.spi.SecurityContext;

import java.util.Collections;
import java.util.Set;

public final class AuthorizationContext {

    private final SecurityContext securityContext;
    private final Set<String> requiredRoles;
    private final Set<String> requiredPermissions;
    private final boolean requireAll;
    private final String policy;

    public AuthorizationContext(SecurityContext securityContext,
                                Set<String> requiredRoles,
                                Set<String> requiredPermissions,
                                boolean requireAll,
                                String policy) {
        this.securityContext = securityContext;
        this.requiredRoles = requiredRoles == null ? Collections.emptySet() : Set.copyOf(requiredRoles);
        this.requiredPermissions = requiredPermissions == null ? Collections.emptySet() : Set.copyOf(requiredPermissions);
        this.requireAll = requireAll;
        this.policy = policy;
    }

    public SecurityContext securityContext() { return securityContext; }
    public Principal principal() { return securityContext.principal().orElse(null); }
    public Set<String> requiredRoles() { return requiredRoles; }
    public Set<String> requiredPermissions() { return requiredPermissions; }
    public boolean requireAll() { return requireAll; }
    public String policy() { return policy; }
}

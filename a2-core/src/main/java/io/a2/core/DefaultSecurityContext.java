package io.a2.core;

import io.a2.annotations.Protocol;
import io.a2.spi.Principal;
import io.a2.spi.SecurityContext;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public final class DefaultSecurityContext implements SecurityContext {

    private final Principal principal;
    private final Protocol protocol;
    private final Set<String> roles;
    private final Set<String> permissions;
    private final Map<String, Object> claims;
    private final String tokenId;

    public DefaultSecurityContext(Principal principal, Protocol protocol,
                                  Set<String> roles, Set<String> permissions,
                                  Map<String, Object> claims, String tokenId) {
        this.principal = principal;
        this.protocol = protocol != null ? protocol : Protocol.CUSTOM;
        this.roles = roles == null ? Collections.emptySet() : Set.copyOf(roles);
        this.permissions = permissions == null ? Collections.emptySet() : Set.copyOf(permissions);
        this.claims = claims == null ? Collections.emptyMap() : Map.copyOf(claims);
        this.tokenId = tokenId;
    }

    public static DefaultSecurityContext of(Principal p, Protocol protocol) {
        return new DefaultSecurityContext(p, protocol,
                p.getRoles(), p.getPermissions(), p.getAttributes(), null);
    }

    @Override public Optional<Principal> principal() { return Optional.ofNullable(principal); }
    @Override public Protocol protocol() { return protocol; }
    @Override public Set<String> roles() { return roles; }
    @Override public Set<String> permissions() { return permissions; }
    @Override public Map<String, Object> claims() { return claims; }
    @Override public Optional<String> tokenId() { return Optional.ofNullable(tokenId); }
    @Override public boolean isAuthenticated() { return principal != null; }
}

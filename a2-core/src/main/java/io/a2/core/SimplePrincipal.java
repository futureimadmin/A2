package io.a2.core;

import io.a2.spi.Principal;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public final class SimplePrincipal implements Principal {

    private final String id;
    private final String name;
    private final Set<String> roles;
    private final Set<String> permissions;
    private final Map<String, Object> attributes;

    public SimplePrincipal(String id, String name, Set<String> roles,
                           Set<String> permissions, Map<String, Object> attributes) {
        this.id = Objects.requireNonNull(id);
        this.name = name != null ? name : id;
        this.roles = roles == null ? Collections.emptySet() : Set.copyOf(roles);
        this.permissions = permissions == null ? Collections.emptySet() : Set.copyOf(permissions);
        this.attributes = attributes == null ? Collections.emptyMap() : Map.copyOf(attributes);
    }

    public static SimplePrincipal of(String id, String name, String... roles) {
        return new SimplePrincipal(id, name, Set.of(roles), Set.of(), Map.of());
    }

    @Override public String getId() { return id; }
    @Override public String getName() { return name; }
    @Override public Set<String> getRoles() { return roles; }
    @Override public Set<String> getPermissions() { return permissions; }
    @Override public Map<String, Object> getAttributes() { return attributes; }
}

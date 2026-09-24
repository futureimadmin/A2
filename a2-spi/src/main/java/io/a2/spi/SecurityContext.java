package io.a2.spi;

import io.a2.annotations.Protocol;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Immutable snapshot of the current security state.
 * Injected via {@code @A2Context}.
 */
public interface SecurityContext {

    Optional<Principal> principal();

    Protocol protocol();

    Set<String> roles();

    Set<String> permissions();

    Map<String, Object> claims();

    Optional<String> tokenId();

    boolean isAuthenticated();

    default boolean hasRole(String role) {
        return roles().contains(role);
    }

    default boolean hasPermission(String permission) {
        return permissions().contains(permission);
    }

    static SecurityContext anonymous() {
        return new SecurityContext() {
            @Override public Optional<Principal> principal() { return Optional.empty(); }
            @Override public Protocol protocol() { return Protocol.CUSTOM; }
            @Override public Set<String> roles() { return Collections.emptySet(); }
            @Override public Set<String> permissions() { return Collections.emptySet(); }
            @Override public Map<String, Object> claims() { return Collections.emptyMap(); }
            @Override public Optional<String> tokenId() { return Optional.empty(); }
            @Override public boolean isAuthenticated() { return false; }
        };
    }
}

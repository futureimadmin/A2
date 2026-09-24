package io.a2.spi;

import java.util.Map;
import java.util.Set;

/**
 * Authenticated identity.
 */
public interface Principal {

    String getId();

    String getName();

    Set<String> getRoles();

    Set<String> getPermissions();

    Map<String, Object> getAttributes();

    default boolean hasRole(String role) {
        return getRoles().contains(role);
    }
}

package io.a2.spi.model;

import io.a2.spi.Principal;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;

public final class AuthResult {

    private final boolean success;
    private final Principal principal;
    private final String error;
    private final Map<String, Object> extra;

    private AuthResult(boolean success, Principal principal, String error, Map<String, Object> extra) {
        this.success = success;
        this.principal = principal;
        this.error = error;
        this.extra = extra == null ? Collections.emptyMap() : Map.copyOf(extra);
    }

    public static AuthResult success(Principal p) {
        return new AuthResult(true, p, null, null);
    }

    public static AuthResult success(Principal p, Map<String, Object> extra) {
        return new AuthResult(true, p, null, extra);
    }

    public static AuthResult failure(String error) {
        return new AuthResult(false, null, error, null);
    }

    public boolean isSuccess() { return success; }
    public Optional<Principal> principal() { return Optional.ofNullable(principal); }
    public Optional<String> error() { return Optional.ofNullable(error); }
    public Map<String, Object> extra() { return extra; }
}

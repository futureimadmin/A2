package io.a2.core.exception;

/**
 * Authorization (AuthZ) failed — caller is authenticated but lacks roles/permissions
 * for the requested resource. Maps to HTTP 403 Forbidden.
 */
public class A2AuthorizationException extends A2SecurityException {

    public A2AuthorizationException(String message) {
        super("forbidden", message);
    }

    public A2AuthorizationException(String errorCode, String message) {
        super(errorCode, message);
    }

    @Override
    public int httpStatus() {
        return 403;
    }

    public static A2AuthorizationException insufficientPrivileges() {
        return new A2AuthorizationException("insufficient_privileges", "Insufficient privileges");
    }

    public static A2AuthorizationException missingRoles() {
        return new A2AuthorizationException("missing_roles", "Missing required roles");
    }

    public static A2AuthorizationException missingPermissions() {
        return new A2AuthorizationException("missing_permissions", "Missing required permissions");
    }

    public static A2AuthorizationException deniedByProvider() {
        return new A2AuthorizationException("authorization_denied", "Authorization denied by provider");
    }
}

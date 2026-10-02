package io.a2.core.exception;

/**
 * Authentication (AuthN) failed — missing/invalid credentials or protocol mismatch
 * before a trusted identity is established. Maps to HTTP 401 Unauthorized.
 */
public class A2AuthenticationException extends A2SecurityException {

    public A2AuthenticationException(String message) {
        super("unauthorized", message);
    }

    public A2AuthenticationException(String errorCode, String message) {
        super(errorCode, message);
    }

    @Override
    public int httpStatus() {
        return 401;
    }

    public static A2AuthenticationException required() {
        return new A2AuthenticationException("authentication_required", "Authentication required");
    }

    public static A2AuthenticationException invalid(String detail) {
        return new A2AuthenticationException("invalid_credentials",
                detail != null ? detail : "Invalid or expired credentials");
    }

    public static A2AuthenticationException protocolNotAllowed(String protocol) {
        return new A2AuthenticationException("protocol_not_allowed",
                "Protocol not allowed: " + protocol);
    }
}

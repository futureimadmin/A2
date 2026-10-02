package io.a2.core.exception;

/**
 * Base runtime exception for A2 security failures.
 * Framework integrations map subclasses to HTTP 401 / 403.
 */
public class A2SecurityException extends RuntimeException {

    private final String errorCode;

    public A2SecurityException(String errorCode, String message) {
        super(message);
        this.errorCode = errorCode != null ? errorCode : "security_error";
    }

    public A2SecurityException(String errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode != null ? errorCode : "security_error";
    }

    public String getErrorCode() {
        return errorCode;
    }

    /** HTTP status this failure should map to (401 or 403). */
    public int httpStatus() {
        return 403;
    }
}

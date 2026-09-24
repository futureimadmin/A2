package io.a2.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Declares token issuance / management policy for a method or class.
 *
 * <pre>
 * {@literal @}A2Token(type = TokenType.ACCESS, rotate = true, ttlSeconds = 3600)
 * public TokenResponse login(...) { ... }
 * </pre>
 */
@Documented
@Inherited
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
public @interface A2Token {

    TokenType type() default TokenType.ACCESS;

    /** Time-to-live in seconds. 0 = provider default. */
    long ttlSeconds() default 0;

    /** Automatically rotate on use / near expiry. */
    boolean rotate() default false;

    /** Revoke previous token when a new one is issued. */
    boolean revokePrevious() default true;

    /** Revoke on logout / session end. */
    boolean revokeOnLogout() default true;

    /** Extra claims to include (key=value pairs). */
    String[] claims() default {};

    /** Scopes (OAuth2/OIDC style). */
    String[] scopes() default {};
}

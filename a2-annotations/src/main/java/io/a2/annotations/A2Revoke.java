package io.a2.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Revokes one or more tokens when the annotated method completes.
 * Useful for logout endpoints or privilege-escalation flows.
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD})
public @interface A2Revoke {

    TokenType[] types() default {TokenType.ACCESS, TokenType.REFRESH, TokenType.SESSION};

    /** Revoke all tokens for the principal (not just the current one). */
    boolean allForPrincipal() default false;

    /** Optional reason recorded in the audit log. */
    String reason() default "explicit-revoke";
}

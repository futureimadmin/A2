package io.a2.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Forces token rotation when the annotated method completes successfully.
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD})
public @interface A2Rotate {

    TokenType[] types() default {TokenType.ACCESS, TokenType.REFRESH};

    /** If true, also revoke the old token. */
    boolean revokeOld() default true;
}

package io.a2.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Declares that the annotated method performs (or requires) an AssumeRole operation.
 * The runtime will issue short-lived (default 1h) credentials for the target role.
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD})
public @interface A2AssumeRole {

    /** Role name or ARN-style identifier to assume. */
    String role();

    /** Maximum lifetime in seconds (hard-capped at 3600 for S2S). */
    long ttlSeconds() default 3600;

    /** Optional session name for audit trails. */
    String sessionName() default "";

    /** Extra permissions granted only for this session. */
    String[] sessionPermissions() default {};
}

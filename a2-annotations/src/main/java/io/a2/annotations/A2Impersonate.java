package io.a2.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a method that initiates user impersonation.
 * Requires the caller to hold an "impersonate" permission.
 * Always audited.
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD})
public @interface A2Impersonate {

    /** Parameter name (or SpEL) that holds the target principal id. */
    String targetPrincipalParam() default "targetUserId";

    /** Lifetime of the impersonation token (seconds). */
    long ttlSeconds() default 3600;

    /** Mandatory reason is expected as a method parameter named "reason" or via this attribute. */
    String reason() default "";
}

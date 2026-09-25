package io.a2.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Impersonate another principal for the duration of the method.
 * Useful for admin tools, support desks, or service-to-service calls
 * that need to act "as" a user.
 *
 * <pre>
 * {@literal @}A2Impersonate(principalId = "#userId", durationSeconds = 3600)
 * public void actAsUser(String userId) { ... }
 * </pre>
 *
 * SpEL-style expressions are supported for principalId when used with Spring.
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD})
public @interface A2Impersonate {

    /** Target principal ID (or SpEL expression). */
    String principalId();

    /** How long the impersonation token is valid (seconds). Default 1 hour. */
    long durationSeconds() default 3600;

    /** Reason recorded in the audit log. */
    String reason() default "impersonation";

    /** If true, the caller must hold an explicit "impersonate" permission. */
    boolean requirePermission() default true;
}

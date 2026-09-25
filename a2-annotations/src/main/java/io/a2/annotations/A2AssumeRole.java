package io.a2.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Declares that the annotated method should run under an assumed role
 * (temporary elevated or delegated identity).
 *
 * <pre>
 * {@literal @}A2AssumeRole(role = "admin-temp", durationSeconds = 3600)
 * public void privilegedOperation() { ... }
 * </pre>
 *
 * The runtime issues a short-lived token / security context for the target role
 * and restores the original context after the method completes.
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
public @interface A2AssumeRole {

    /** Role (or role ARN / name) to assume. */
    String role();

    /** How long the assumed credentials remain valid (seconds). Default 1 hour. */
    long durationSeconds() default 3600;

    /** Optional external ID / session name for audit. */
    String sessionName() default "";

    /** Optional policy/permission boundary applied to the assumed session. */
    String[] policies() default {};

    /** If true, the original principal must already possess permission to assume this role. */
    boolean requireDelegationPermission() default true;
}

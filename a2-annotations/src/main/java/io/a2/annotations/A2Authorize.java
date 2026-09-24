package io.a2.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Fine-grained authorization (AuthZ).
 * Evaluated after successful authentication.
 *
 * Supports RBAC, permission-based and simple ABAC via attributes.
 */
@Documented
@Inherited
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
public @interface A2Authorize {

    /** Required roles. */
    String[] roles() default {};

    /** Required permissions (e.g. "order:read"). */
    String[] permissions() default {};

    /** If true, all roles/permissions must match. */
    boolean requireAll() default false;

    /** Simple attribute expressions (e.g. "department=engineering"). */
    String[] attributes() default {};

    /** Custom policy name (resolved by PolicyEngine SPI). */
    String policy() default "";
}

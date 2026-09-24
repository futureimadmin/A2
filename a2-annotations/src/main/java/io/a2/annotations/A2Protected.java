package io.a2.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a class or method as requiring authentication.
 * This is the primary entry-point annotation for A2 security.
 *
 * <pre>
 * {@literal @}A2Protected(roles = {"user"}, protocols = {Protocol.OIDC, Protocol.OAUTH2})
 * public class OrderController { ... }
 * </pre>
 */
@Documented
@Inherited
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
public @interface A2Protected {

    /** Required roles (OR semantics unless requireAllRoles=true). */
    String[] roles() default {};

    /** Required permissions. */
    String[] permissions() default {};

    /** Allowed protocols. Empty = any registered provider. */
    Protocol[] protocols() default {};

    /** If true, all listed roles must be present. */
    boolean requireAllRoles() default false;

    /** Optional realm / tenant. */
    String realm() default "";

    /** Whether anonymous access is allowed (default false). */
    boolean allowAnonymous() default false;
}

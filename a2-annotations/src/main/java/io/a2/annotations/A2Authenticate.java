package io.a2.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Explicit authentication requirement.
 * Can be used alone or together with {@link A2Protected}.
 */
@Documented
@Inherited
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
public @interface A2Authenticate {

    /** Allowed protocols for this AuthN. */
    Protocol[] protocols() default {};

    /** Preferred protocol when multiple are available. */
    Protocol preferred() default Protocol.OIDC;

    /** Force re-authentication even if a valid session exists. */
    boolean force() default false;

    /** Optional authentication scheme name (e.g. "Bearer", "Basic"). */
    String scheme() default "";
}

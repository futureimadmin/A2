package io.a2.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Issues a short-lived service-to-service credential (default TTL = 1 hour).
 * Intended for machine identities / workload identity flows.
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD})
public @interface A2ServiceCredential {

    /** Audience / target service. */
    String audience() default "";

    /** Scopes granted to the temporary credential. */
    String[] scopes() default {};

    /** Lifetime in seconds (max 3600). */
    long ttlSeconds() default 3600;
}

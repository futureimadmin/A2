package io.a2.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * A2 unified short-lived credentials (max 1 hour).
 * <p>
 * One annotation for the three common patterns:
 * <ul>
 *   <li><b>ASSUME_ROLE</b> — AWS-style: elevate to a role for a session</li>
 *   <li><b>IMPERSONATE</b> — GCP-style: source SA (caller) → target SA/principal</li>
 *   <li><b>SERVICE</b> — S2S / workload: temp token for an audience</li>
 * </ul>
 *
 * Existing {@link A2AssumeRole}, {@link A2Impersonate}, {@link A2TemporaryCredential}
 * and {@link A2ServiceCredential} remain as specialized aliases of the same engine.
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD})
public @interface A2InstantCredentials {

    /** Issuance mode. */
    InstantMode mode() default InstantMode.SERVICE;

    /** Role name or ARN-style id (required for {@link InstantMode#ASSUME_ROLE}). */
    String role() default "";

    /** Target principal / SA id (for {@link InstantMode#IMPERSONATE}). */
    String targetPrincipal() default "";

    /** Method parameter name that holds the target principal (GCP-style target SA). */
    String targetPrincipalParam() default "targetPrincipal";

    /** Audience / target service (for {@link InstantMode#SERVICE}). */
    String audience() default "";

    /** Scopes granted on the temporary credential. */
    String[] scopes() default {};

    /** Session name for audit (ASSUME_ROLE). */
    String sessionName() default "";

    /** Audit reason (IMPERSONATE). May also be a method param named {@code reason}. */
    String reason() default "";

    /** Requested lifetime in seconds. Default 3600. Values above 3600 are clamped. */
    long ttlSeconds() default 3600;

    /** Attach issued token metadata to security context claims ({@code a2.instant.*}). */
    boolean attachToContext() default true;
}

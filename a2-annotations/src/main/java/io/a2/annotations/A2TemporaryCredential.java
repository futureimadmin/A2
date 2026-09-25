package io.a2.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Requests issuance of a temporary credential (service-to-service)
 * valid for a limited time (default 1 hour).
 *
 * Typical use: a service obtains a short-lived token to call another service
 * without long-lived secrets.
 *
 * <pre>
 * {@literal @}A2TemporaryCredential(audience = "payment-service", durationSeconds = 3600)
 * public TokenResult getPaymentToken() { ... }
 * </pre>
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD})
public @interface A2TemporaryCredential {

    /** Intended audience / service name. */
    String audience() default "";

    /** Validity in seconds. Default 3600 (1 hour). Max recommended 12h. */
    long durationSeconds() default 3600;

    /** Scopes granted to the temporary credential. */
    String[] scopes() default {};

    /** Extra claims embedded in the token. */
    String[] claims() default {};

    /** Token type to issue. */
    TokenType type() default TokenType.ACCESS;
}

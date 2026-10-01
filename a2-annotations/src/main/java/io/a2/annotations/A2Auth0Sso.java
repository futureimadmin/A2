package io.a2.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * SSO via Auth0.
 * Issuer preset: {@code https://{domain}}.
 *
 * <pre>
 * {@literal @}A2Auth0Sso(domain = "myapp.us.auth0.com", clientId = "…",
 *         roles = {"user"})
 * public class Auth0App { … }
 * </pre>
 */
@Documented
@Inherited
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
@A2Sso(provider = SsoProvider.AUTH0)
public @interface A2Auth0Sso {

    /** Auth0 tenant domain, e.g. {@code myapp.us.auth0.com}. */
    String domain() default "";

    String clientId() default "";

    String clientSecret() default "";

    /** API audience (resource server identifier). */
    String audience() default "";

    String[] roles() default {};

    String[] permissions() default {};

    String[] scopes() default {"openid", "profile", "email"};

    String configKey() default "a2.sso.auth0";

    boolean forceReauth() default false;
}

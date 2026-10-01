package io.a2.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * SSO via Okta.
 * Issuer preset: {@code https://{domain}.okta.com} or custom Okta org URL.
 *
 * <pre>
 * {@literal @}A2OktaSso(domain = "mycompany.okta.com", clientId = "0oa…",
 *         roles = {"Everyone"})
 * public class OktaProtectedService { … }
 * </pre>
 */
@Documented
@Inherited
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
@A2Sso(provider = SsoProvider.OKTA)
public @interface A2OktaSso {

    /**
     * Okta org domain, e.g. {@code mycompany.okta.com} or {@code mycompany.oktapreview.com}.
     * Used to build issuer {@code https://{domain}}.
     */
    String domain() default "";

    /**
     * Full issuer override (Auth Server), e.g.
     * {@code https://mycompany.okta.com/oauth2/default}.
     */
    String issuer() default "";

    String clientId() default "";

    String clientSecret() default "";

    /** Okta authorization server id (default {@code default}). */
    String authorizationServerId() default "default";

    String[] roles() default {};

    String[] permissions() default {};

    String[] scopes() default {"openid", "profile", "email"};

    String configKey() default "a2.sso.okta";

    boolean forceReauth() default false;
}

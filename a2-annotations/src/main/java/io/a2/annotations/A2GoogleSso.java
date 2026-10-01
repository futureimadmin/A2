package io.a2.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * SSO via Google / Gmail / Google Workspace.
 * Issuer preset: {@code https://accounts.google.com}.
 *
 * <pre>
 * {@literal @}A2GoogleSso(clientId = "….apps.googleusercontent.com",
 *         hostedDomain = "company.com", roles = {"user"})
 * public class MailIntegration { … }
 * </pre>
 */
@Documented
@Inherited
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
@A2Sso(provider = SsoProvider.GOOGLE)
public @interface A2GoogleSso {

    /** Google OAuth2 client id. */
    String clientId() default "";

    /** Optional client secret. */
    String clientSecret() default "";

    /**
     * Google Workspace hosted domain ({@code hd} claim).
     * When set, only accounts from this domain are accepted.
     */
    String hostedDomain() default "";

    String[] roles() default {};

    String[] permissions() default {};

    String[] scopes() default {"openid", "profile", "email"};

    String configKey() default "a2.sso.google";

    boolean forceReauth() default false;
}

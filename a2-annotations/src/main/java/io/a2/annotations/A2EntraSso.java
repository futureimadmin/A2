package io.a2.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * SSO via Microsoft Entra ID (formerly Azure Active Directory).
 * Issuer preset: {@code https://login.microsoftonline.com/{tenantId}/v2.0}.
 *
 * <pre>
 * {@literal @}A2EntraSso(tenantId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
 *         clientId = "app-registration-id", roles = {"Employee"})
 * public class CorporateApi { … }
 * </pre>
 */
@Documented
@Inherited
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
@A2Sso(provider = SsoProvider.ENTRA)
public @interface A2EntraSso {

    /**
     * Entra tenant id (GUID), domain name, or {@code common} / {@code organizations} / {@code consumers}.
     */
    String tenantId() default "common";

    /** App registration (application) client id. */
    String clientId() default "";

    String clientSecret() default "";

    /**
     * Expected audience / app id URI. Empty = accept tokens for {@link #clientId()}.
     */
    String audience() default "";

    String[] roles() default {};

    String[] permissions() default {};

    /** Default includes Microsoft Graph user.read when integrating with Graph. */
    String[] scopes() default {"openid", "profile", "email"};

    String configKey() default "a2.sso.entra";

    boolean forceReauth() default false;
}

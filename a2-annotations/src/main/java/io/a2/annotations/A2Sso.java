package io.a2.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Generic SSO requirement. Prefer brand-specific annotations
 * ({@link A2OktaSso}, {@link A2GoogleSso}, {@link A2EntraSso}, …) when possible.
 *
 * <pre>
 * {@literal @}A2Sso(provider = SsoProvider.OKTA, issuer = "https://myorg.okta.com",
 *         clientId = "0oa…", roles = {"employee"})
 * public class EmployeePortal { … }
 * </pre>
 */
@Documented
@Inherited
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
@A2Protected(protocols = {Protocol.SSO, Protocol.OIDC})
public @interface A2Sso {

    /** Which SSO IdP to use. */
    SsoProvider provider();

    /**
     * Issuer or discovery base URL.
     * For Okta: {@code https://{domain}.okta.com};
     * for Entra: {@code https://login.microsoftonline.com/{tenant}/v2.0};
     * for Google usually left empty (preset applied).
     */
    String issuer() default "";

    /** OAuth2 / OIDC client id registered at the IdP. */
    String clientId() default "";

    /** Optional client secret (prefer external config / env in production). */
    String clientSecret() default "";

    /** Tenant id (Entra) or org domain (Okta / Auth0 / Google Workspace). */
    String tenant() default "";

    /** Required roles after successful SSO. */
    String[] roles() default {};

    /** Required permissions after successful SSO. */
    String[] permissions() default {};

    /** OIDC scopes requested at login (default openid profile email). */
    String[] scopes() default {"openid", "profile", "email"};

    /** Optional config key looked up in a2.yml / application properties. */
    String configKey() default "";

    /** Force re-authentication at the IdP. */
    boolean forceReauth() default false;
}

package io.a2.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * SSO against on-premises Active Directory (or AD FS).
 *
 * Modes:
 * <ul>
 *   <li>{@link AdMode#KERBEROS} — SPNEGO / GSS (uses {@code a2-provider-kerberos})</li>
 *   <li>{@link AdMode#SAML} — AD FS SAML 2.0 assertions</li>
 *   <li>{@link AdMode#OIDC} — AD FS / Entra hybrid OIDC endpoint</li>
 *   <li>{@link AdMode#LDAP} — simple bind (service / legacy apps only)</li>
 * </ul>
 *
 * <pre>
 * {@literal @}A2ActiveDirectorySso(mode = AdMode.KERBEROS,
 *         realm = "CORP.EXAMPLE.COM", roles = {"DOMAIN USER"})
 * public class IntranetApp { … }
 * </pre>
 */
@Documented
@Inherited
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
@A2Sso(provider = SsoProvider.ACTIVE_DIRECTORY)
public @interface A2ActiveDirectorySso {

    /** How to talk to AD / AD FS. */
    AdMode mode() default AdMode.KERBEROS;

    /** Kerberos realm / AD domain, e.g. {@code CORP.EXAMPLE.COM}. */
    String realm() default "";

    /** SPN for the service, e.g. {@code HTTP/app.corp.example.com}. */
    String servicePrincipal() default "";

    /** Path to keytab (Kerberos mode). */
    String keytabPath() default "";

    /** AD FS / IdP metadata URL (SAML mode). */
    String metadataUrl() default "";

    /** OIDC issuer when mode is OIDC (AD FS or Entra hybrid). */
    String issuer() default "";

    String clientId() default "";

    String clientSecret() default "";

    String[] roles() default {};

    String[] permissions() default {};

    String configKey() default "a2.sso.ad";

    boolean forceReauth() default false;

    /** Active Directory integration mode. */
    enum AdMode {
        KERBEROS,
        SAML,
        OIDC,
        LDAP
    }
}

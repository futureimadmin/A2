package io.a2.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * SSO via Ping Identity / PingFederate / PingOne.
 *
 * <pre>
 * {@literal @}A2PingSso(issuer = "https://auth.pingone.com/{envId}/as",
 *         clientId = "…", roles = {"user"})
 * public class PingProtectedApi { … }
 * </pre>
 */
@Documented
@Inherited
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
@A2Sso(provider = SsoProvider.PING)
public @interface A2PingSso {

    /**
     * OIDC issuer (PingOne environment or PingFederate base).
     * Example: {@code https://auth.pingone.com/{env}/as}
     */
    String issuer() default "";

    String clientId() default "";

    String clientSecret() default "";

    /** Ping environment / region id when using PingOne presets. */
    String environmentId() default "";

    String[] roles() default {};

    String[] permissions() default {};

    String[] scopes() default {"openid", "profile", "email"};

    String configKey() default "a2.sso.ping";

    boolean forceReauth() default false;
}

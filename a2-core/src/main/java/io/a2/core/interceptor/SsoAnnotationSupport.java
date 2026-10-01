package io.a2.core.interceptor;

import io.a2.annotations.A2ActiveDirectorySso;
import io.a2.annotations.A2Auth0Sso;
import io.a2.annotations.A2EntraSso;
import io.a2.annotations.A2GoogleSso;
import io.a2.annotations.A2OktaSso;
import io.a2.annotations.A2PingSso;
import io.a2.annotations.A2Sso;
import io.a2.annotations.Protocol;
import io.a2.annotations.SsoProvider;
import io.a2.spi.SecurityContext;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Optional;

/**
 * Resolves brand-specific SSO annotations and validates protocol / roles.
 */
public final class SsoAnnotationSupport {

    private SsoAnnotationSupport() {}

    public record SsoRequirement(
            SsoProvider provider,
            String[] roles,
            String[] permissions,
            String configKey
    ) {}

    public static Optional<SsoRequirement> find(Method method, Class<?> type) {
        A2OktaSso okta = first(method, type, A2OktaSso.class);
        if (okta != null) {
            return Optional.of(new SsoRequirement(SsoProvider.OKTA, okta.roles(), okta.permissions(), okta.configKey()));
        }
        A2GoogleSso google = first(method, type, A2GoogleSso.class);
        if (google != null) {
            return Optional.of(new SsoRequirement(SsoProvider.GOOGLE, google.roles(), google.permissions(), google.configKey()));
        }
        A2EntraSso entra = first(method, type, A2EntraSso.class);
        if (entra != null) {
            return Optional.of(new SsoRequirement(SsoProvider.ENTRA, entra.roles(), entra.permissions(), entra.configKey()));
        }
        A2PingSso ping = first(method, type, A2PingSso.class);
        if (ping != null) {
            return Optional.of(new SsoRequirement(SsoProvider.PING, ping.roles(), ping.permissions(), ping.configKey()));
        }
        A2Auth0Sso auth0 = first(method, type, A2Auth0Sso.class);
        if (auth0 != null) {
            return Optional.of(new SsoRequirement(SsoProvider.AUTH0, auth0.roles(), auth0.permissions(), auth0.configKey()));
        }
        A2ActiveDirectorySso ad = first(method, type, A2ActiveDirectorySso.class);
        if (ad != null) {
            return Optional.of(new SsoRequirement(SsoProvider.ACTIVE_DIRECTORY, ad.roles(), ad.permissions(), ad.configKey()));
        }
        A2Sso sso = first(method, type, A2Sso.class);
        if (sso != null) {
            return Optional.of(new SsoRequirement(sso.provider(), sso.roles(), sso.permissions(), sso.configKey()));
        }
        return Optional.empty();
    }

    public static void enforce(SecurityContext ctx, SsoRequirement req) {
        if (!ctx.isAuthenticated()) {
            throw new SecurityException("SSO authentication required (" + req.provider() + ")");
        }
        Protocol p = ctx.protocol();
        if (p != Protocol.SSO && p != Protocol.OIDC && p != Protocol.SAML && p != Protocol.KERBEROS) {
            throw new SecurityException("Protocol " + p + " not allowed for SSO endpoint (" + req.provider() + ")");
        }
        Object claimProvider = ctx.claims().get("a2.sso.provider");
        if (claimProvider != null
                && !req.provider().name().equalsIgnoreCase(String.valueOf(claimProvider))) {
            throw new SecurityException("SSO provider mismatch: expected " + req.provider()
                    + " got " + claimProvider);
        }
        if (req.roles().length > 0) {
            boolean ok = Arrays.stream(req.roles()).anyMatch(ctx::hasRole);
            if (!ok) {
                throw new SecurityException("Missing required SSO roles: " + Arrays.toString(req.roles()));
            }
        }
        if (req.permissions().length > 0) {
            boolean ok = Arrays.stream(req.permissions()).anyMatch(ctx::hasPermission);
            if (!ok) {
                throw new SecurityException("Missing required SSO permissions: " + Arrays.toString(req.permissions()));
            }
        }
    }

    private static <A extends java.lang.annotation.Annotation> A first(
            Method method, Class<?> type, Class<A> ann) {
        A m = method.getAnnotation(ann);
        if (m != null) return m;
        return type.getAnnotation(ann);
    }
}

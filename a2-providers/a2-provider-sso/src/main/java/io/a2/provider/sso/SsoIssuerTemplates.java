package io.a2.provider.sso;

import io.a2.annotations.SsoProvider;

/**
 * Well-known OIDC issuer / discovery bases for major SSO brands.
 */
public final class SsoIssuerTemplates {

    private SsoIssuerTemplates() {}

    public static final String GOOGLE = "https://accounts.google.com";
    public static final String ENTRA_COMMON = "https://login.microsoftonline.com/common/v2.0";
    public static final String ENTRA_ORGANIZATIONS = "https://login.microsoftonline.com/organizations/v2.0";
    public static final String ENTRA_CONSUMERS = "https://login.microsoftonline.com/consumers/v2.0";

    public static String entra(String tenantId) {
        String t = (tenantId == null || tenantId.isBlank()) ? "common" : tenantId.trim();
        return "https://login.microsoftonline.com/" + t + "/v2.0";
    }

    public static String okta(String domain) {
        if (domain == null || domain.isBlank()) {
            throw new IllegalArgumentException("Okta domain is required (e.g. mycompany.okta.com)");
        }
        String d = domain.trim();
        if (d.startsWith("https://")) {
            return d.endsWith("/") ? d.substring(0, d.length() - 1) : d;
        }
        return "https://" + d;
    }

    public static String oktaAuthServer(String domain, String authorizationServerId) {
        String base = okta(domain);
        String as = (authorizationServerId == null || authorizationServerId.isBlank())
                ? "default" : authorizationServerId.trim();
        if ("default".equals(as) && !base.contains("/oauth2/")) {
            return base + "/oauth2/default";
        }
        if (base.contains("/oauth2/")) {
            return base;
        }
        return base + "/oauth2/" + as;
    }

    public static String auth0(String domain) {
        if (domain == null || domain.isBlank()) {
            throw new IllegalArgumentException("Auth0 domain is required (e.g. myapp.us.auth0.com)");
        }
        String d = domain.trim();
        if (d.startsWith("https://")) {
            return d.endsWith("/") ? d.substring(0, d.length() - 1) : d;
        }
        return "https://" + d;
    }

    public static String pingOne(String environmentId, String region) {
        if (environmentId == null || environmentId.isBlank()) {
            throw new IllegalArgumentException("PingOne environmentId is required");
        }
        String r = (region == null || region.isBlank()) ? "auth" : region.trim();
        return "https://" + r + ".pingone.com/" + environmentId.trim() + "/as";
    }

    public static String resolve(SsoProvider provider, String issuerOrDomain, String tenantOrEnv) {
        return switch (provider) {
            case GOOGLE -> GOOGLE;
            case ENTRA -> (issuerOrDomain != null && !issuerOrDomain.isBlank())
                    ? issuerOrDomain
                    : entra(tenantOrEnv);
            case OKTA -> {
                if (issuerOrDomain != null && issuerOrDomain.contains("://")) {
                    yield issuerOrDomain;
                }
                yield okta(issuerOrDomain != null && !issuerOrDomain.isBlank()
                        ? issuerOrDomain : tenantOrEnv);
            }
            case AUTH0 -> auth0(issuerOrDomain != null && !issuerOrDomain.isBlank()
                    ? issuerOrDomain : tenantOrEnv);
            case PING -> {
                if (issuerOrDomain != null && !issuerOrDomain.isBlank()) {
                    yield issuerOrDomain;
                }
                yield pingOne(tenantOrEnv, "auth");
            }
            case KEYCLOAK -> {
                if (issuerOrDomain == null || issuerOrDomain.isBlank()) {
                    throw new IllegalArgumentException("Keycloak issuer URL is required");
                }
                yield issuerOrDomain;
            }
            case ACTIVE_DIRECTORY, CUSTOM -> {
                if (issuerOrDomain == null || issuerOrDomain.isBlank()) {
                    throw new IllegalArgumentException(
                            provider + " requires an explicit issuer / discovery URI");
                }
                yield issuerOrDomain;
            }
        };
    }
}

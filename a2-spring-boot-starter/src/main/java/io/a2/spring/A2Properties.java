package io.a2.spring;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties(prefix = "a2")
public class A2Properties {

    private Providers providers = new Providers();
    private Oidc oidc = new Oidc();
    private Saml saml = new Saml();
    private Kerberos kerberos = new Kerberos();
    private Cors cors = new Cors();
    private Auth auth = new Auth();

    public Providers getProviders() { return providers; }
    public void setProviders(Providers providers) { this.providers = providers; }
    public Oidc getOidc() { return oidc; }
    public void setOidc(Oidc oidc) { this.oidc = oidc; }
    public Saml getSaml() { return saml; }
    public void setSaml(Saml saml) { this.saml = saml; }
    public Kerberos getKerberos() { return kerberos; }
    public void setKerberos(Kerberos kerberos) { this.kerberos = kerberos; }
    public Cors getCors() { return cors; }
    public void setCors(Cors cors) { this.cors = cors; }
    public Auth getAuth() { return auth; }
    public void setAuth(Auth auth) { this.auth = auth; }

    public static class Auth {
        /** Register the servlet AuthN filter. */
        private boolean filterEnabled = true;
        /** Reject request immediately when credentials are present but invalid. */
        private boolean failOnInvalidCredentials = true;

        public boolean isFilterEnabled() { return filterEnabled; }
        public void setFilterEnabled(boolean filterEnabled) { this.filterEnabled = filterEnabled; }
        public boolean isFailOnInvalidCredentials() { return failOnInvalidCredentials; }
        public void setFailOnInvalidCredentials(boolean failOnInvalidCredentials) {
            this.failOnInvalidCredentials = failOnInvalidCredentials;
        }
    }

    public static class Cors {
        private boolean enabled = true;
        private boolean allowCredentials = true;
        private List<String> allowedOrigins = new ArrayList<>(List.of("*"));
        private List<String> allowedMethods = new ArrayList<>(
                List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"));
        private List<String> allowedHeaders = new ArrayList<>(List.of("*"));
        private String pathPattern = "/**";
        private long maxAgeSeconds = 3600;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public boolean isAllowCredentials() { return allowCredentials; }
        public void setAllowCredentials(boolean allowCredentials) { this.allowCredentials = allowCredentials; }
        public List<String> getAllowedOrigins() { return allowedOrigins; }
        public void setAllowedOrigins(List<String> allowedOrigins) { this.allowedOrigins = allowedOrigins; }
        public List<String> getAllowedMethods() { return allowedMethods; }
        public void setAllowedMethods(List<String> allowedMethods) { this.allowedMethods = allowedMethods; }
        public List<String> getAllowedHeaders() { return allowedHeaders; }
        public void setAllowedHeaders(List<String> allowedHeaders) { this.allowedHeaders = allowedHeaders; }
        public String getPathPattern() { return pathPattern; }
        public void setPathPattern(String pathPattern) { this.pathPattern = pathPattern; }
        public long getMaxAgeSeconds() { return maxAgeSeconds; }
        public void setMaxAgeSeconds(long maxAgeSeconds) { this.maxAgeSeconds = maxAgeSeconds; }
    }

    public static class Providers {
        private boolean jwt = true;
        private boolean apikey = true;
        private boolean oidc = false;
        private boolean saml = false;
        private boolean kerberos = false;

        public boolean isJwt() { return jwt; }
        public void setJwt(boolean jwt) { this.jwt = jwt; }
        public boolean isApikey() { return apikey; }
        public void setApikey(boolean apikey) { this.apikey = apikey; }
        public boolean isOidc() { return oidc; }
        public void setOidc(boolean oidc) { this.oidc = oidc; }
        public boolean isSaml() { return saml; }
        public void setSaml(boolean saml) { this.saml = saml; }
        public boolean isKerberos() { return kerberos; }
        public void setKerberos(boolean kerberos) { this.kerberos = kerberos; }
    }

    public static class Oidc {
        private String issuer = "https://localhost/auth/realms/master";
        private String clientId = "a2-client";
        private String clientSecret = "";
        private String discoveryUri = "";

        public String getIssuer() { return issuer; }
        public void setIssuer(String issuer) { this.issuer = issuer; }
        public String getClientId() { return clientId; }
        public void setClientId(String clientId) { this.clientId = clientId; }
        public String getClientSecret() { return clientSecret; }
        public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }
        public String getDiscoveryUri() { return discoveryUri; }
        public void setDiscoveryUri(String discoveryUri) { this.discoveryUri = discoveryUri; }
    }

    public static class Saml {
        private String entityId = "https://sp.example.com";
        private String idpSsoUrl = "https://idp.example.com/sso";
        private String acsUrl = "https://sp.example.com/acs";

        public String getEntityId() { return entityId; }
        public void setEntityId(String entityId) { this.entityId = entityId; }
        public String getIdpSsoUrl() { return idpSsoUrl; }
        public void setIdpSsoUrl(String idpSsoUrl) { this.idpSsoUrl = idpSsoUrl; }
        public String getAcsUrl() { return acsUrl; }
        public void setAcsUrl(String acsUrl) { this.acsUrl = acsUrl; }
    }

    public static class Kerberos {
        private String servicePrincipal = "HTTP/server.example.com";
        private String realm = "EXAMPLE.COM";

        public String getServicePrincipal() { return servicePrincipal; }
        public void setServicePrincipal(String servicePrincipal) { this.servicePrincipal = servicePrincipal; }
        public String getRealm() { return realm; }
        public void setRealm(String realm) { this.realm = realm; }
    }
}

package io.a2.spring;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "a2")
public class A2Properties {

    private Providers providers = new Providers();
    private Oidc oidc = new Oidc();
    private Saml saml = new Saml();
    private Kerberos kerberos = new Kerberos();

    public Providers getProviders() { return providers; }
    public void setProviders(Providers providers) { this.providers = providers; }
    public Oidc getOidc() { return oidc; }
    public void setOidc(Oidc oidc) { this.oidc = oidc; }
    public Saml getSaml() { return saml; }
    public void setSaml(Saml saml) { this.saml = saml; }
    public Kerberos getKerberos() { return kerberos; }
    public void setKerberos(Kerberos kerberos) { this.kerberos = kerberos; }

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

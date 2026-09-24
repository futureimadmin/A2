package io.a2.quarkus;

import io.quarkus.runtime.annotations.ConfigItem;
import io.quarkus.runtime.annotations.ConfigRoot;

@ConfigRoot(name = "a2")
public class A2QuarkusConfig {

    /** Enable OIDC provider. */
    @ConfigItem(defaultValue = "false")
    public boolean oidcEnabled;

    @ConfigItem(defaultValue = "https://localhost/auth/realms/master")
    public String oidcIssuer;

    @ConfigItem(defaultValue = "a2-client")
    public String oidcClientId;

    @ConfigItem(defaultValue = "")
    public String oidcClientSecret;

    @ConfigItem(defaultValue = "")
    public String oidcDiscoveryUri;
}

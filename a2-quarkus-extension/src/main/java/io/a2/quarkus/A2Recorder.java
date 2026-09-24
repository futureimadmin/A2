package io.a2.quarkus;

import io.a2.core.A2Runtime;
import io.a2.core.DefaultTokenService;
import io.a2.provider.jwt.JwtProtocolProvider;
import io.a2.provider.oidc.OidcProtocolProvider;
import io.quarkus.runtime.annotations.Recorder;

@Recorder
public class A2Recorder {

    public void init(A2QuarkusConfig config) {
        A2Runtime runtime = A2Runtime.get();
        runtime.register(new JwtProtocolProvider());
        if (config.oidcEnabled) {
            runtime.register(new OidcProtocolProvider(
                    config.oidcIssuer,
                    config.oidcClientId,
                    config.oidcClientSecret,
                    config.oidcDiscoveryUri
            ));
        }
        try {
            runtime.tokenService();
        } catch (IllegalStateException e) {
            runtime.setTokenService(new DefaultTokenService());
        }
    }
}

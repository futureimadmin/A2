package io.a2.spring;

import io.a2.core.A2Runtime;
import io.a2.core.DefaultTokenService;
import io.a2.core.interceptor.A2Interceptor;
import io.a2.provider.apikey.ApiKeyProtocolProvider;
import io.a2.provider.jwt.JwtProtocolProvider;
import io.a2.provider.kerberos.KerberosProtocolProvider;
import io.a2.provider.oidc.OidcProtocolProvider;
import io.a2.provider.saml.SamlProtocolProvider;
import io.a2.spi.TokenService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.EnableAspectJAutoProxy;

@AutoConfiguration
@EnableAspectJAutoProxy
@EnableConfigurationProperties(A2Properties.class)
public class A2AutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public A2Runtime a2Runtime(A2Properties props) {
        A2Runtime runtime = A2Runtime.get();

        if (props.getProviders().isJwt()) {
            runtime.register(new JwtProtocolProvider());
        }
        if (props.getProviders().isApikey()) {
            runtime.register(new ApiKeyProtocolProvider());
        }
        if (props.getProviders().isOidc()) {
            runtime.register(new OidcProtocolProvider(
                    props.getOidc().getIssuer(),
                    props.getOidc().getClientId(),
                    props.getOidc().getClientSecret(),
                    props.getOidc().getDiscoveryUri()
            ));
        }
        if (props.getProviders().isSaml()) {
            runtime.register(new SamlProtocolProvider(
                    props.getSaml().getEntityId(),
                    props.getSaml().getIdpSsoUrl(),
                    props.getSaml().getAcsUrl()
            ));
        }
        if (props.getProviders().isKerberos()) {
            runtime.register(new KerberosProtocolProvider(
                    props.getKerberos().getServicePrincipal(),
                    props.getKerberos().getRealm()
            ));
        }

        if (runtime.tokenService() == null) {
            try {
                runtime.setTokenService(new DefaultTokenService());
            } catch (Exception ignored) {
                // already set
            }
        }
        return runtime;
    }

    @Bean
    @ConditionalOnMissingBean
    public TokenService a2TokenService(A2Runtime runtime) {
        try {
            return runtime.tokenService();
        } catch (IllegalStateException e) {
            DefaultTokenService ts = new DefaultTokenService();
            runtime.setTokenService(ts);
            return ts;
        }
    }

    @Bean
    @ConditionalOnMissingBean
    public A2Interceptor a2Interceptor() {
        return new A2Interceptor();
    }

    @Bean
    public A2SecurityAspect a2SecurityAspect(A2Interceptor interceptor) {
        return new A2SecurityAspect(interceptor);
    }
}

package io.a2.spring;

import io.a2.core.A2Runtime;
import io.a2.core.DefaultTokenService;
import io.a2.core.auth.RequestAuthenticator;
import io.a2.core.interceptor.A2Interceptor;
import io.a2.provider.apikey.ApiKeyProtocolProvider;
import io.a2.provider.jwt.JwtProtocolProvider;
import io.a2.provider.kerberos.KerberosProtocolProvider;
import io.a2.provider.oidc.OidcProtocolProvider;
import io.a2.provider.saml.SamlProtocolProvider;
import io.a2.spi.TokenService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;

@AutoConfiguration
@EnableAspectJAutoProxy
@EnableConfigurationProperties(A2Properties.class)
@Import({A2CorsConfiguration.class, A2ExceptionHandler.class})
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
        try {
            runtime.tokenService();
        } catch (IllegalStateException e) {
            runtime.setTokenService(new DefaultTokenService());
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
    @ConditionalOnMissingBean
    public RequestAuthenticator a2RequestAuthenticator(A2Runtime runtime) {
        return new RequestAuthenticator(runtime);
    }

    @Bean
    public A2SecurityAspect a2SecurityAspect(A2Interceptor interceptor) {
        return new A2SecurityAspect(interceptor);
    }

    @Bean
    @ConditionalOnWebApplication
    @ConditionalOnProperty(prefix = "a2.auth", name = "filter-enabled", havingValue = "true", matchIfMissing = true)
    public FilterRegistrationBean<A2AuthenticationFilter> a2AuthenticationFilter(
            RequestAuthenticator authenticator, A2Properties props) {
        A2AuthenticationFilter filter = new A2AuthenticationFilter(
                authenticator, props.getAuth().isFailOnInvalidCredentials());
        FilterRegistrationBean<A2AuthenticationFilter> bean = new FilterRegistrationBean<>(filter);
        bean.setOrder(Ordered.HIGHEST_PRECEDENCE + 20);
        bean.setName("a2AuthenticationFilter");
        bean.addUrlPatterns("/*");
        return bean;
    }
}

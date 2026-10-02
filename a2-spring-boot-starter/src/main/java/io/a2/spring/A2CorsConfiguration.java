package io.a2.spring;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.Arrays;
import java.util.List;

@ConditionalOnWebApplication
@ConditionalOnProperty(prefix = "a2.cors", name = "enabled", havingValue = "true", matchIfMissing = true)
public class A2CorsConfiguration {

    private final A2Properties properties;

    public A2CorsConfiguration(A2Properties properties) {
        this.properties = properties;
    }

    @Bean
    public FilterRegistrationBean<CorsFilter> a2CorsFilter() {
        A2Properties.Cors cors = properties.getCors();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(cors.isAllowCredentials());
        List<String> origins = cors.getAllowedOrigins();
        if (origins == null || origins.isEmpty() || origins.contains("*")) {
            config.addAllowedOriginPattern("*");
        } else {
            origins.forEach(config::addAllowedOriginPattern);
        }
        List<String> methods = cors.getAllowedMethods();
        if (methods == null || methods.isEmpty()) {
            config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"));
        } else {
            config.setAllowedMethods(methods);
        }
        List<String> headers = cors.getAllowedHeaders();
        if (headers == null || headers.isEmpty()) {
            config.addAllowedHeader("*");
        } else {
            headers.forEach(config::addAllowedHeader);
        }
        config.setExposedHeaders(Arrays.asList("Authorization", "WWW-Authenticate", "X-A2-SSO-Provider"));
        config.setMaxAge(cors.getMaxAgeSeconds());

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration(cors.getPathPattern(), config);

        FilterRegistrationBean<CorsFilter> bean = new FilterRegistrationBean<>(new CorsFilter(source));
        bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
        bean.setName("a2CorsFilter");
        return bean;
    }
}

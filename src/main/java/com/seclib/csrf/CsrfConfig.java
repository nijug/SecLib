package com.seclib.csrf;

import com.seclib.config.csrf.CsrfFilter;
import com.seclib.config.csrf.CsrfFilterProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;


@Configuration
@EnableConfigurationProperties(CsrfFilterProperties.class)
public class CsrfConfig {

    private final CsrfFilterProperties csrfFilterProperties;

    public CsrfConfig(CsrfFilterProperties csrfFilterProperties) {
        this.csrfFilterProperties = csrfFilterProperties;
    }

    @Bean
    @ConditionalOnProperty(prefix = "csrf", name = "enabled", havingValue = "true")
    public CsrfService csrfService() {
        return new CsrfService();
    }

    @Bean
    @ConditionalOnProperty(prefix = "csrf", name = "enabled", havingValue = "true")
    public FilterRegistrationBean<CsrfFilter> csrfFilter(CsrfService csrfService, RequestMappingHandlerMapping handlerMapping) {
        FilterRegistrationBean<CsrfFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(new CsrfFilter(csrfFilterProperties, csrfService, handlerMapping));
        registrationBean.addUrlPatterns("/*");
        registrationBean.setOrder(Ordered.LOWEST_PRECEDENCE);
        return registrationBean;
    }
}

package com.seclib.csrf;

import com.seclib.config.csrf.CsrfFilter;
import com.seclib.config.csrf.CsrfFilterProperties;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Optional;

@Configuration
@EnableConfigurationProperties(CsrfFilterProperties.class)
public class CsrfConfig {

    private final CsrfFilterProperties csrfFilterProperties;

    public CsrfConfig(CsrfFilterProperties csrfFilterProperties) {
        this.csrfFilterProperties = csrfFilterProperties;
    }

    @Bean
    @ConditionalOnProperty(prefix = "csrf", name = "enabled", havingValue = "true", matchIfMissing = true)
    public CsrfService csrfService(@Value("${app.secret}") String formSecret) {
        return new CsrfService(formSecret);
    }

    @Bean
    @ConditionalOnProperty(prefix = "csrf", name = "enabled", havingValue = "true", matchIfMissing = true)
    public FilterRegistrationBean<CsrfFilter> csrfFilter(CsrfService csrfService) {
        FilterRegistrationBean<CsrfFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(new CsrfFilter(csrfFilterProperties, csrfService));
        registrationBean.addUrlPatterns("/*");
        registrationBean.setOrder(2);
        return registrationBean;
    }
}

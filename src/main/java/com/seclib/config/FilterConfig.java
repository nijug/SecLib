package com.seclib.config;

import com.seclib.config.session.SessionFilter;
import com.seclib.config.session.SessionFilterProperties;
import com.seclib.userRoles.service.BaseRoleService;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FilterConfig {

    private final SessionFilterProperties properties;
    private final BaseRoleService<?, ?> roleService;

    public FilterConfig(SessionFilterProperties properties, BaseRoleService<?, ?> roleService) {
        this.properties = properties;
        this.roleService = roleService;
    }

    @Bean
    public FilterRegistrationBean<SessionFilter> sessionFilter() {
        FilterRegistrationBean<SessionFilter> registrationBean = new FilterRegistrationBean<>();

        registrationBean.setFilter(new SessionFilter(properties, roleService));
        registrationBean.addUrlPatterns("/*");
        registrationBean.setOrder(1);

        return registrationBean;
    }
}
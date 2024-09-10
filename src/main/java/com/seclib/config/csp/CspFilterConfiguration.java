package com.seclib.config.csp;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.jetbrains.annotations.NotNull;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Configuration
@EnableConfigurationProperties(CspFilterProperties.class)
@RequiredArgsConstructor
public class CspFilterConfiguration {

    private final CspFilterProperties properties;

    @Bean("cspFilter")
    public FilterRegistrationBean<OncePerRequestFilter> cspFilter() {
        OncePerRequestFilter cspFilter = new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(@NotNull HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
                    throws ServletException, IOException {
                response.setHeader("Content-Security-Policy", buildCspDirectiveString());
                filterChain.doFilter(request, response);
            }
        };

        FilterRegistrationBean<OncePerRequestFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(cspFilter);
        registrationBean.addUrlPatterns("/*");
        return registrationBean;
    }

    private String buildCspDirectiveString() {
        return StringUtils.collectionToDelimitedString(properties.getDirectives(), "; ");
    }
}

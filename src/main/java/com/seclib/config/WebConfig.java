package com.seclib.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import com.seclib.ipBlocking.IpBlockService;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    private final IpBlockService ipBlockService;

    public WebConfig(IpBlockService ipBlockService) {
        this.ipBlockService = ipBlockService;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        if (ipBlockService instanceof HandlerInterceptor) {
            registry.addInterceptor((HandlerInterceptor) ipBlockService);
        }
    }
}
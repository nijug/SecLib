package com.seclib.config;

import com.seclib.honeypot.FakeCookieHoneypot;
import com.seclib.honeypot.HoneypotService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import com.seclib.ipBlocking.IpBlockService;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    private final IpBlockService ipBlockService;
    private final HoneypotService honeypotService;

    @Autowired
    public WebConfig(IpBlockService ipBlockService, HoneypotService honeypotService) {
        this.ipBlockService = ipBlockService;
        this.honeypotService = honeypotService;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        if (ipBlockService instanceof HandlerInterceptor) {
            registry.addInterceptor((HandlerInterceptor) ipBlockService);
        }
        honeypotService.getActiveHoneypots().stream()
                .filter(honeypot -> honeypot instanceof HandlerInterceptor)
                .forEach(honeypot -> registry.addInterceptor((HandlerInterceptor) honeypot));
    }
}
package com.seclib.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "cors")
public class CorsProperties {

    private String[] allowedOrigins = new String[] {};
    private String[] allowedMethods = new String[] {};
    private String[] allowedHeaders = new String[] {};
    private boolean allowCredentials;

    String[] getAllowedOrigins() {
        return allowedOrigins;
    }

    String[] getAllowedMethods() {
        return allowedMethods;
    }

    String[] getAllowedHeaders() {
        return allowedHeaders;
    }

    boolean isAllowCredentials() {
        return allowCredentials;
    }
}
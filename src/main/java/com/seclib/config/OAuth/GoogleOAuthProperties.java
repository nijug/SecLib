package com.seclib.config.OAuth;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

@Setter
@Getter
@Configuration
@Validated
@ConfigurationProperties(prefix = "google-oauth")
public class GoogleOAuthProperties extends BaseOAuthProperties {
    private String authorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth";
    private String tokenEndpoint = "https://oauth2.googleapis.com/token";
    private String userInfoEndpoint = "https://openidconnect.googleapis.com/v1/userinfo";
    private String jwksUrl = "https://www.googleapis.com/oauth2/v3/certs";
}
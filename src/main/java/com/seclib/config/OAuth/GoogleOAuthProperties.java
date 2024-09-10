package com.seclib.config.OAuth;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.EqualsAndHashCode;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Data
@EqualsAndHashCode(callSuper = false)
@Validated
@ConfigurationProperties(prefix = "google-oauth")
public class GoogleOAuthProperties extends BaseOAuthProperties {
    @NotBlank
    private String authorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth";
    @NotBlank
    private String tokenEndpoint = "https://oauth2.googleapis.com/token";
    @NotBlank
    private String userInfoEndpoint = "https://openidconnect.googleapis.com/v1/userinfo";
    @NotBlank
    private String jwksUrl = "https://www.googleapis.com/oauth2/v3/certs";
}
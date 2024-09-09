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
@ConfigurationProperties(prefix = "github-oauth")
public class GitHubOAuthProperties extends BaseOAuthProperties {
    private String authorizationEndpoint = "https://github.com/login/oauth/authorize";
    private String tokenEndpoint = "https://github.com/login/oauth/access_token";
    private String userInfoEndpoint = "https://api.github.com/user";
}
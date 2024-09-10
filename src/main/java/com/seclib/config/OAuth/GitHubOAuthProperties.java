package com.seclib.config.OAuth;


import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

@Data
@EqualsAndHashCode(callSuper = false)
@Validated
@ConfigurationProperties(prefix = "github-oauth")
public class GitHubOAuthProperties extends BaseOAuthProperties {
    @NotBlank
    private String authorizationEndpoint = "https://github.com/login/oauth/authorize";
    @NotBlank
    private String tokenEndpoint = "https://github.com/login/oauth/access_token";
    @NotBlank
    private String userInfoEndpoint = "https://api.github.com/user";
}
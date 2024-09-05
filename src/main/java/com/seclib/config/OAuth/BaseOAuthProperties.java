package com.seclib.config.OAuth;


import lombok.Data;

import java.util.List;

@Data
public abstract class BaseOAuthProperties {
    private String clientId;
    private String clientSecret;
    private String redirectUri;
    private List<String> scopes;
    private String state;
    private String authorizationEndpoint;
}

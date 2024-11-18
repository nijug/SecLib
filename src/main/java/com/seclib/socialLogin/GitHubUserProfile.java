package com.seclib.socialLogin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(callSuper = true)
@JsonIgnoreProperties(ignoreUnknown = true)
public class GitHubUserProfile extends BaseUserProfile {
    private String id;
    private String login;

    @Override
    public String getProvider() {
        return "github";
    }

    @Override
    public String getProviderId() {
        return id;
    }

    @Override
    public String getUsername() {
        return login;
    }
}
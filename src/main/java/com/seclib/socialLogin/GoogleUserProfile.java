package com.seclib.socialLogin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(callSuper = true)
@JsonIgnoreProperties(ignoreUnknown = true)
public class GoogleUserProfile extends BaseUserProfile {
    private String sub;
    private String name;

    @Override
    public String getProvider() {
        return "google";
    }

    @Override
    public String getProviderId() {
        return sub;
    }

    @Override
    public String getUsername() {
        return name;
    }
}
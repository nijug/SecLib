package com.seclib.socialLogin;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public abstract class BaseUserProfile {
    @JsonProperty("email")
    private String email;

    public abstract String getProvider();
    public abstract String getProviderId();
    public abstract String getUsername();
}
package com.seclib.config;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

@Data
@ConfigurationProperties(prefix = "security")
public class AuthorizationProperties {

    private Map<String, RoleProperties> roles;
    private boolean roleBasedAuthorizationEnabled = true;

    @Data
    public static class RoleProperties {
        private List<String> permissions;
    }
}
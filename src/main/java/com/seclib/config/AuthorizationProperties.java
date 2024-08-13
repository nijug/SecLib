package com.seclib.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "security")
public class AuthorizationProperties {

    @Setter
    private Map<String, RoleProperties> roles;
    private boolean roleBasedAuthorizationEnabled = true;

    @Getter
    @Setter
    public static class RoleProperties {
        private List<String> permissions;
        private String parent;

    }
}
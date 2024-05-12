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

    private Map<String, RoleProperties> roles;
    private boolean roleBasedAuthorizationEnabled = true;

    public void setRoles(Map<String, RoleProperties> roles) {
        this.roles = roles;
    }

    @Getter
    @Setter
    public static class RoleProperties {
        private List<String> permissions;
        private String parent;

    }
}
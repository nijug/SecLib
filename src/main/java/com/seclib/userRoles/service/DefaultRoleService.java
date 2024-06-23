package com.seclib.userRoles.service;

import com.seclib.config.AuthorizationProperties;
import com.seclib.user.model.DefaultUser;
import com.seclib.user.service.DefaultUserService;
import com.seclib.userRoles.model.DefaultRole;
import org.springframework.stereotype.Service;


@Service
public class DefaultRoleService extends BaseRoleService<DefaultRole, DefaultUserService> {

    public DefaultRoleService(AuthorizationProperties authorizationProperties, DefaultUserService userService) {
        super(authorizationProperties, userService);
    }

    public String getUserRole(String username) {
        DefaultUser user = userService.findByUsername(username);
        return user != null ? user.getRole() : null;
    }
    public boolean userHasRole(String username, String role) {
        String userRole = getUserRole(username);
        return userRole != null && userRole.equals(role);
    }
}
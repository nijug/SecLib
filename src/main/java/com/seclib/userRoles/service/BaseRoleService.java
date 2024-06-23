package com.seclib.userRoles.service;

import com.seclib.config.AuthorizationProperties;
import com.seclib.user.model.BaseUser;
import com.seclib.user.repository.BaseUserRepository;
import com.seclib.user.service.BaseUserService;
import com.seclib.userRoles.model.BaseRole;


public abstract class BaseRoleService<T extends BaseRole, U extends BaseUserService<? extends BaseUser, ? extends BaseUserRepository<?, Long>>> {

    private final AuthorizationProperties authorizationProperties;
    protected final U userService;

    public BaseRoleService(AuthorizationProperties authorizationProperties, U userService) {
        this.authorizationProperties = authorizationProperties;
        this.userService = userService;
    }

    public boolean isRoleBasedAuthorizationEnabled() {
        return authorizationProperties.isRoleBasedAuthorizationEnabled();
    }



}
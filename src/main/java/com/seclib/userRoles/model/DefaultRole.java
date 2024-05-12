package com.seclib.userRoles.model;

import com.seclib.userRoles.permissions.Permission;

import java.util.Set;

public class DefaultRole extends BaseRole {

    public DefaultRole(String name, Set<Permission> permissions) {
        this.setName(name);
        this.setPermissions(permissions);
    }
}
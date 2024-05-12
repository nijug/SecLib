package com.seclib.userRoles.service;

import com.seclib.userRoles.model.BaseRole;
import com.seclib.userRoles.permissions.Permission;

import java.util.HashMap;
import java.util.Map;

public abstract class BaseRoleService<T extends BaseRole> {

    protected Map<Long, T> roleMap = new HashMap<>();

    public boolean hasPermission(T role, Permission permission) {
        return role.getPermissions().contains(permission);
    }

    public T getRoleById(Long id) {
        return roleMap.get(id);
    }
}
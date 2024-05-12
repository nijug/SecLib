package com.seclib.userRoles.model;

import com.seclib.userRoles.permissions.Permission;
import lombok.Getter;
import lombok.Setter;

import java.util.HashSet;
import java.util.Set;

public abstract class BaseRole {

    @Setter
    private String name;
    private BaseRole parentRole;

    @Setter
    @Getter
    private Set<Permission> permissions = new HashSet<>();


}

package com.seclib.userRoles.model;

import com.seclib.userRoles.permissions.Permission;
import lombok.Getter;
import lombok.Setter;

import java.util.HashSet;
import java.util.Set;

@Setter
@Getter
public abstract class BaseRole {

    private String name;

    private Set<Permission> permissions = new HashSet<>();


}

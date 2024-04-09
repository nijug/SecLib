package com.seclib.user.model;


import jakarta.persistence.Entity;

@Entity
public class DefaultUser extends BaseUser {

    protected DefaultUser() {
    }
    public DefaultUser(Long id, String password) {
        super(id, password);
    }
}
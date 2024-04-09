package com.seclib.loginAttempt.model;

import jakarta.persistence.Entity;

@Entity
public class DefaultLoginAttempt extends BaseLoginAttempt {

    public DefaultLoginAttempt(String ipAddress) {
        super(ipAddress);
    }

    public DefaultLoginAttempt(String ipAddress, int failedAttempts, long lockTime) { // constructor for testing
        super(ipAddress, failedAttempts, lockTime);
    }

    protected DefaultLoginAttempt() {
    }
}
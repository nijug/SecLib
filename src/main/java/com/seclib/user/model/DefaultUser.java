package com.seclib.user.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import lombok.Getter;
import lombok.Setter;


@Getter
@Setter
@Entity
public class DefaultUser extends BaseUser {

    @Column(name = "failed_attempts")
    private int failedAttempts = 0;

    @Column(name = "lock_time")
    private long lockTime = 0;

    @Column(name = "totp_secret")
    private String totpSecret;

    private String role;

    protected DefaultUser() {
    }

    public DefaultUser(Long id, String password) {
        super(id, password);
    }

    public void resetFailedAttempts() {
        this.failedAttempts = 0;
    }

    public void incrementFailedAttempts() {
        this.failedAttempts++;
    }
}
package com.seclib.user.model;


import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import lombok.Getter;
import lombok.Setter;

@Entity
public class DefaultUser extends BaseUser {

    @Getter
    @Setter // for testing purposes
    @Column(name = "failed_attempts")
    private int failedAttempts = 0;

    @Getter
    @Setter
    @Column(name = "lock_time")
    private long lockTime = 0;

    @Getter
    @Setter
    private String totpSecret;

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
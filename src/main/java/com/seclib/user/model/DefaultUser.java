package com.seclib.user.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import lombok.*;

@Data
@EqualsAndHashCode(callSuper = true)
@NoArgsConstructor
@Entity
public class DefaultUser extends BaseUser {

    @Column(name = "failed_attempts")
    private int failedAttempts = 0;

    @Column(name = "lock_time")
    private long lockTime = 0;

    @Column(name = "totp_secret")
    private String totpSecret;

    @Column(name = "role")
    private String role;

    @Column(name = "email")
    private String email;

    public DefaultUser(String username, String password) {
        super(username, password);
    }

    public void resetFailedAttempts() {
        this.failedAttempts = 0;
    }

    public void incrementFailedAttempts(int maxAttempts) {
        this.failedAttempts++;
        if (this.failedAttempts >= maxAttempts) {
            this.lockTime = System.currentTimeMillis();
        }
    }
}
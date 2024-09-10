package com.seclib.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;


@Data
@ConfigurationProperties(prefix = "user")
public class UserProperties {

    private final PasswordPolicy passwordPolicy = new PasswordPolicy();
    private boolean twoFactorAuthEnabled = true;
    private boolean ipLockingEnabled = true;
    private boolean userLockingEnabled = true;
    private boolean passwordPolicyEnabled = true;
    private boolean passwordResetEnabled = true;

    private int ipMaxAttempts = 2;
    private long ipLockTime = 1 * 60 * 1000; // 1 minute
    private int userMaxAttempts = 2;
    private long userLockTime = 1 * 60 * 1000; // 1 minute

    @Data
    public static class PasswordPolicy {
        private String pattern = "(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?]).{8,}";
        private int entropy = 60;
    }

}

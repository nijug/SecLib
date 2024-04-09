package com.seclib.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Setter // for configuration properties
@Getter // for baseUser class
@Component
@ConfigurationProperties(prefix = "user")
public class UserProperties {
    private PasswordPolicy passwordPolicy = new PasswordPolicy();
    //defining default values
    private boolean twoFactorAuthEnabled = true;
    private boolean ipLockingEnabled = true; // new property
    private int maxAttempts = 2;  // Maximum number of failed attempts
    private long lockTime = 1 * 60 * 1000; // 1 minute

    public UserProperties() {
        passwordPolicy.setPattern("(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?]).{8,}");// default value
        // pierwszy nawais sprawdza przynajmniej jedna cyfre, drugi przynajmniej jedna mala litere, trzeci duza, czwarty znak specjalny, w klamrach calkowita minimalna dlugosc to 8

        passwordPolicy.setEntropy(60);
    }

}
package com.seclib.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Setter // for configuration properties
@Getter // for baseUser class
@Component
@ConfigurationProperties(prefix = "user")
public class UserProperties {

    @Autowired
    private PasswordPolicy passwordPolicy = new PasswordPolicy();
    //defining default values
    private boolean twoFactorAuthEnabled = true;
    private boolean ipLockingEnabled = true;
    private boolean userLockingEnabled = true;
    private boolean passwordPolicyEnabled = true;
    private boolean passwordResetEnabled = true;

    private int ipMaxAttempts = 2;
    private long ipLockTime = 1 * 60 * 1000; //1 minute
    private int userMaxAttempts = 2;
    private long userLockTime = 1 * 60 * 1000;


    public UserProperties() {
        passwordPolicy.setPattern("(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?]).{8,}");// default value
        // pierwszy nawias sprawdza przynajmniej jedna cyfre, drugi przynajmniej jedna mala litere, trzeci duza, czwarty znak specjalny, w klamrach calkowita minimalna dlugosc to 8

        passwordPolicy.setEntropy(60);
    }

}
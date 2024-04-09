package com.seclib.loginAttempt.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@MappedSuperclass
public abstract class BaseLoginAttempt {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @Getter
    @Setter
    @Column(name = "ip_address")
    private String ipAddress;

    @Getter
    @Setter
    @Column(name = "failed_attempts")
    private int failedAttempts = 0;

    @Getter
    @Setter
    @Column(name = "lock_time")
    private long lockTime = 0;

    public BaseLoginAttempt(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public BaseLoginAttempt(String ipAddress, int failedAttempts, long lockTime) { // constructor for testing
        this.ipAddress = ipAddress;
        this.failedAttempts = failedAttempts;
        this.lockTime = lockTime;
    }

    protected BaseLoginAttempt() {
    }


}
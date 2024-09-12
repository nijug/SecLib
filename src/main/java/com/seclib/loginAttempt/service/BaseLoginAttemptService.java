package com.seclib.loginAttempt.service;

import com.seclib.loginAttempt.model.BaseLoginAttempt;
import com.seclib.loginAttempt.repository.BaseLoginAttemptRepository;

import java.util.Optional;

public abstract class BaseLoginAttemptService<T extends BaseLoginAttempt, R extends BaseLoginAttemptRepository<T, Long>> {

    protected final R loginAttemptRepository;

    protected BaseLoginAttemptService(R loginAttemptRepository) {
        this.loginAttemptRepository = loginAttemptRepository;
    }

    public Optional<T> getLoginAttempt(String ipAddress) {
        return loginAttemptRepository.findByIpAddress(ipAddress);
    }

    public void saveLoginAttempt(T loginAttempt) {
        loginAttemptRepository.save(loginAttempt);
    }

    public void resetFailedAttempts(T loginAttempt) {
        loginAttempt.resetFailedAttempts();
        loginAttemptRepository.save(loginAttempt);
    }

    public abstract T createInstance(String ipAddress);
}

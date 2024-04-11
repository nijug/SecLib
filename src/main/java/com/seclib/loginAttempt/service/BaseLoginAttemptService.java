package com.seclib.loginAttempt.service;

import com.seclib.loginAttempt.model.BaseLoginAttempt;
import com.seclib.loginAttempt.repository.BaseLoginAttemptRepository;

public abstract class BaseLoginAttemptService<T extends BaseLoginAttempt, R extends BaseLoginAttemptRepository<T, Long>> {


    protected R loginAttemptRepository;

    BaseLoginAttemptService(R loginAttemptRepository) {
        this.loginAttemptRepository = loginAttemptRepository;
    }

    public T getLoginAttempt(String ipAddress) {
        return loginAttemptRepository.findByIpAddress(ipAddress).orElse(null);
    }

    public void saveLoginAttempt(T loginAttempt) {
        loginAttemptRepository.save(loginAttempt);
    }

    public void resetFailedAttempts(T loginAttempt) {
        loginAttempt.setFailedAttempts(0);
        loginAttemptRepository.save(loginAttempt);
    }

    public abstract T createInstance(String ipAddress);


}
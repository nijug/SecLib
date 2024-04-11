package com.seclib.loginAttempt.service;

import com.seclib.loginAttempt.model.DefaultLoginAttempt;
import com.seclib.loginAttempt.repository.DefaultLoginAttemptRepository;
import org.springframework.stereotype.Service;

@Service
public class DefaultLoginAttemptService extends BaseLoginAttemptService<DefaultLoginAttempt, DefaultLoginAttemptRepository> {
    DefaultLoginAttemptService(DefaultLoginAttemptRepository loginAttemptRepository) {
        super(loginAttemptRepository);
    }

    @Override
    public DefaultLoginAttempt createInstance(String ipAddress) {
          return new DefaultLoginAttempt(ipAddress);
    }

}
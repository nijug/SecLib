package com.seclib.user.service;

import com.seclib.config.UserProperties;
import com.seclib.loginAttempt.model.DefaultLoginAttempt;
import com.seclib.loginAttempt.repository.DefaultLoginAttemptRepository;
import com.seclib.loginAttempt.service.DefaultLoginAttemptService;
import com.seclib.user.model.DefaultUser;
import com.seclib.user.repository.DefaultUserRepository;
import jakarta.validation.Validator;
import org.springframework.stereotype.Service;
@Service
public class DefaultUserService extends BaseUserService<DefaultUser, DefaultUserRepository, DefaultLoginAttempt, DefaultLoginAttemptRepository, DefaultLoginAttemptService> {

    public DefaultUserService(UserProperties userProperties, DefaultUserRepository userRepository, Validator validator, DefaultLoginAttemptService loginAttemptService) {
        super(userProperties, userRepository, validator, loginAttemptService);
    }

    @Override
    protected DefaultUser createInstance(Long id, String password) {
        return new DefaultUser(id, password);
    }
}
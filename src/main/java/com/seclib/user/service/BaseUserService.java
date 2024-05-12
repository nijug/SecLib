package com.seclib.user.service;

import com.seclib.config.UserProperties;
import com.seclib.exception.ApiException;
import com.seclib.exception.PasswordValidationException;
import com.seclib.exception.UserException;
import com.seclib.user.model.BaseUser;
import com.seclib.user.repository.BaseUserRepository;
import jakarta.validation.ConstraintViolation;
import lombok.Setter;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import jakarta.validation.ConstraintViolationException;
import jakarta.validation.Validator;

import java.util.Set;

public abstract class BaseUserService<T extends BaseUser, R extends BaseUserRepository<T, Long>> {

    protected final UserProperties userProperties;
    protected R userRepository;
    protected final Argon2PasswordEncoder passwordEncoder;

    @Setter // for testing purposes
    protected Validator validator;

    public BaseUserService(UserProperties userProperties, R userRepository, Validator validator) {
        this.userProperties = userProperties;
        this.userRepository = userRepository;
        this.passwordEncoder = new Argon2PasswordEncoder(16, 32, 1, 7168, 5);
        this.validator = validator;
    }

    public T createUser(Long id, String password) {
        T user = createInstance(id, password);
        userRepository.save(user);
        return user;
    }

    public T login(T userFromRequest) throws ApiException, InterruptedException {
        Thread.sleep(500);
        T userInDB = userRepository.findById(userFromRequest.getId()).orElse(null);
        if (userInDB == null) {
            throw new UserException(401, "User not found");
        }

        if (!passwordEncoder.matches(userFromRequest.getPassword(), userInDB.getPassword())) {
            throw new UserException(401, "Invalid password");
        }

        return userInDB;
    }

    public void register(T user) throws ApiException, InterruptedException {
        Thread.sleep(500);
        Set<ConstraintViolation<T>> violations = validator.validate(user);
        if (!violations.isEmpty()) {
            throw new ConstraintViolationException(violations);
        }

        T existingUser = userRepository.findById(user.getId()).orElse(null);
        if (existingUser != null) {
            throw new UserException(400, "User with this ID already exists");
        }
        if (userProperties.isPasswordPolicyEnabled()) {
            validatePassword(user.getPassword());
        }
        String encodedPassword = passwordEncoder.encode(user.getPassword());
        user.setPassword(encodedPassword);
        System.out.println("User password: " + user.getPassword());

        userRepository.save(user);
    }


    public void validatePassword(String password) throws ApiException {
        String pattern = userProperties.getPasswordPolicy().getPattern();
        if (!password.matches(pattern)) {
            throw new PasswordValidationException(400, "Password does not match the pattern");
        }

        int N = 95;
        int L = password.length();
        double entropy = Math.log(Math.pow(N, L)) / Math.log(2);

        System.out.println("Entropy: " + entropy);
        if (entropy < userProperties.getPasswordPolicy().getEntropy()) {
            throw new PasswordValidationException(400, "Weak password");
        }
        System.out.println("Password is valid");
    }

    public T findById(Long id) {
        return userRepository.findById(id).orElse(null);
    }

    protected abstract T createInstance(Long id, String password);
}
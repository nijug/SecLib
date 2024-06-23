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

    public T login(String username, String password) throws ApiException, InterruptedException {
        Thread.sleep(500);
        T userInDB = userRepository.findByUsername(username).orElse(null);
        System.out.println("User from request: " + username);
        if (userInDB == null) {
            throw new UserException(401, "User not found");
        }

        if (!passwordEncoder.matches(password, userInDB.getPassword())) {
            throw new UserException(401, "Invalid password");
        }

        return userInDB;
    }

    public T register(String usernameFromRequest, String passwordFromRequest) throws ApiException, InterruptedException {
        Thread.sleep(500);
        T user = createNewUser(usernameFromRequest, passwordFromRequest);
        Set<ConstraintViolation<T>> violations = validator.validate(user);
        if (!violations.isEmpty()) {
            throw new ConstraintViolationException(violations);
        }


        T existingUser = userRepository.findByUsername(usernameFromRequest).orElse(null);
        if (existingUser != null) {
            throw new UserException(400, "User with this username already exists");
        }

        if (userProperties.isPasswordPolicyEnabled()) {
            validatePassword(passwordFromRequest);
        }
        String encodedPassword = passwordEncoder.encode(passwordFromRequest);
        user.setPassword(encodedPassword);
        System.out.println("User password: " + user.getPassword());
        System.out.println("User username: " + user.getUsername());

        userRepository.save(user);
        return user;
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

    public T findByUsername(String username) {
        return userRepository.findByUsername(username).orElse(null);
    }

    protected abstract T createNewUser(String username, String password);


}
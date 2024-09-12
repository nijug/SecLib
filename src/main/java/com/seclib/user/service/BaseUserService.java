package com.seclib.user.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import com.seclib.config.UserProperties;
import com.seclib.exception.ApiException;
import com.seclib.exception.PasswordValidationException;
import com.seclib.exception.UserException;
import com.seclib.user.dto.BaseUserDTO;
import com.seclib.user.model.BaseUser;
import com.seclib.user.repository.BaseUserRepository;

import java.util.Optional;

@Slf4j
public abstract class BaseUserService<T extends BaseUser, R extends BaseUserRepository<T, Long>, D extends BaseUserDTO> {

    protected final UserProperties userProperties;
    protected final R userRepository;
    protected final Argon2PasswordEncoder passwordEncoder;

    private static final int CHARACTER_SPACE = 95;

    public BaseUserService(UserProperties userProperties, R userRepository, Argon2PasswordEncoder passwordEncoder) {
        this.userProperties = userProperties;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    protected T login(D userToLogin) throws ApiException {
        Optional<T> userInDB = userRepository.findByUsername(userToLogin.getUsername());
        if (userInDB.isEmpty()) {
            log.info("User not found: {}", userToLogin.getUsername());
            throw new UserException(401, "User not found");
        }

        T user = userInDB.get();
        if (!passwordEncoder.matches(userToLogin.getPassword(), user.getPassword())) {
            log.info("Invalid password attempt for user: {}", userToLogin.getUsername());
            throw new UserException(401, "Invalid password");
        }

        return user;
    }

    protected T register(D userToRegister) throws ApiException {
        Optional<T> existingUser = userRepository.findByUsername(userToRegister.getUsername());
        if (existingUser.isPresent()) {
            log.info("Attempt to register with existing username: {}", userToRegister.getUsername());
            throw new UserException(400, "User with this username already exists");
        }

        if (userProperties.isPasswordPolicyEnabled()) {
            validatePassword(userToRegister.getPassword());
        }

        T user = createNewUser(userToRegister.getUsername(), userToRegister.getPassword());
        String encodedPassword = passwordEncoder.encode(userToRegister.getPassword());
        user.setPassword(encodedPassword);

        userRepository.save(user);
        return user;
    }

    protected void validatePassword(String password) throws ApiException {
        String pattern = userProperties.getPasswordPolicy().getPattern();
        if (!password.matches(pattern)) {
            throw new PasswordValidationException(400, "Password does not match the pattern");
        }

        int L = password.length();
        double entropy = Math.log(Math.pow(CHARACTER_SPACE, L)) / Math.log(2);

        if (entropy < userProperties.getPasswordPolicy().getEntropy()) {
            throw new PasswordValidationException(400, "Weak password");
        }
    }

    public Optional<T> findById(Long id) {
        return userRepository.findById(id);
    }

    public Optional<T> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    protected abstract T createNewUser(String username, String password);
}

package com.seclib.user.service;

import com.seclib.user.model.BaseUser;
import com.seclib.config.UserProperties;
import com.seclib.user.repository.BaseUserRepository;
import com.seclib.loginAttempt.service.BaseLoginAttemptService;
import com.seclib.loginAttempt.model.BaseLoginAttempt;
import com.seclib.loginAttempt.repository.BaseLoginAttemptRepository;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import jakarta.validation.Validator;
import jakarta.servlet.http.HttpSession;
import lombok.Setter;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import java.util.Set;
import jakarta.servlet.http.HttpServletRequest;


public abstract class BaseUserService<T extends BaseUser, R extends BaseUserRepository<T, Long>, S extends BaseLoginAttempt, U extends BaseLoginAttemptRepository<S, Long>, V extends BaseLoginAttemptService<S, U>> {

    private final UserProperties userProperties;
    private final Argon2PasswordEncoder passwordEncoder;
    private final V loginAttemptService;

    @Setter
    private Validator validator;

    protected R userRepository;

    public BaseUserService(UserProperties userProperties, R userRepository, Validator validator, V loginAttemptService) {
        this.userProperties = userProperties;
        this.userRepository = userRepository;
        this.passwordEncoder = new Argon2PasswordEncoder(16, 32, 1, 7168, 5);
        this.validator = validator;
        this.loginAttemptService = loginAttemptService;
    }

    public T createUser(Long id, String password) {
        T user = createInstance(id, password);
        userRepository.save(user);
        return user;
    }

    public void register(T user) throws InterruptedException {
        Thread.sleep(500);
        Set<ConstraintViolation<T>> violations = validator.validate(user);
        if (!violations.isEmpty()) {
            throw new ConstraintViolationException(violations);
        }

        T existingUser = userRepository.findById(user.getId()).orElse(null);
        if (existingUser != null) {
            throw new IllegalArgumentException("User with this ID already exists");
        }

        try {
            validatePassword(user.getPassword());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(e.getMessage());
        }

        String encodedPassword = passwordEncoder.encode(user.getPassword());
        user.setPassword(encodedPassword);
        System.out.println("User password: " + user.getPassword());
        //String secretKey = totpService.generateSecretKey();
       // user.setTotpSecret(secretKey);

        //List<String> recoveryKeys = generateRecoveryKeys();
        //storeRecoveryKeys(user, recoveryKeys);
        userRepository.save(user);
    }

    public void validatePassword(String password) {
        String pattern = userProperties.getPasswordPolicy().getPattern();
        if (!password.matches(pattern)) {
            throw new IllegalArgumentException("Invalid password");
        }

        int N = 95;
        int L = password.length();
        double entropy = Math.log(Math.pow(N, L)) / Math.log(2);

        System.out.println("Entropy: " + entropy);
        if (entropy < userProperties.getPasswordPolicy().getEntropy()) {
            throw new IllegalArgumentException("Weak password");
        }
    }

    public T login(T userFromRequest, String totpOrRecoveryKey, HttpSession session, HttpServletRequest request) throws InterruptedException {
        T userInDB = userRepository.findById(userFromRequest.getId()).orElse(null);
        if (userInDB == null) {
            throw new IllegalArgumentException("Invalid username/password");
        }

        S loginAttempt = null;
        if (userProperties.isIpLockingEnabled()) {
            String ipAddress = request.getRemoteAddr(); // Get IP address of the client
            loginAttempt = loginAttemptService.getLoginAttempt(ipAddress);
            if (loginAttempt == null) {
                loginAttempt = loginAttemptService.createInstance(ipAddress);
            }

            if (loginAttempt.getFailedAttempts() >= userProperties.getMaxAttempts() &&
                    System.currentTimeMillis() - loginAttempt.getLockTime() < userProperties.getLockTime()) {
                throw new IllegalArgumentException("Logging from this ip has been locked, try again later");
            }
        }

        if (!passwordEncoder.matches(userFromRequest.getPassword(), userInDB.getPassword())) {
            if (loginAttempt != null) {
                incrementFailedAttempts(loginAttempt);
            }
            throw new IllegalArgumentException("Invalid username/password");
        }

        if (loginAttempt != null) {
            loginAttemptService.resetFailedAttempts(loginAttempt);
        }

        return userInDB;
    }
    //todo:consider exceptions handling

    private void incrementFailedAttempts(S loginAttempt) {
        loginAttempt.setFailedAttempts(loginAttempt.getFailedAttempts() + 1);
        if (loginAttempt.getFailedAttempts() >= userProperties.getMaxAttempts()) {
            loginAttempt.setLockTime(System.currentTimeMillis());
        }
        loginAttemptService.saveLoginAttempt(loginAttempt);
    }

    protected abstract T createInstance(Long id, String password);

    public String getTwoFactorAuthCode(T user) { // temporary implementation for testing
        if (userProperties.isTwoFactorAuthEnabled()) {
            return "123456";
        } else {
        return null;
        }
    }


}
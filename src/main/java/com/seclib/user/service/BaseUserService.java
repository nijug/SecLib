package com.seclib.user.service;

import com.seclib.exception.ApiException;
import com.seclib.exception.LoginAttemptException;
import com.seclib.exception.PasswordValidationException;
import com.seclib.exception.UserException;
import com.seclib.Totp.service.BaseTotpService;
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


public abstract class BaseUserService<T extends BaseUser, R extends BaseUserRepository<T, Long>, S extends BaseLoginAttempt, U extends BaseLoginAttemptRepository<S, Long>, V extends BaseLoginAttemptService<S, U>, W extends BaseTotpService> {

    private final UserProperties userProperties;
    private final Argon2PasswordEncoder passwordEncoder;
    private final V loginAttemptService;
    private final W totpService;

    @Setter
    private Validator validator;

    protected R userRepository;

    public BaseUserService(UserProperties userProperties, R userRepository, Validator validator, V loginAttemptService, W totpService) {
        this.userProperties = userProperties;
        this.userRepository = userRepository;
        this.passwordEncoder = new Argon2PasswordEncoder(16, 32, 1, 7168, 5);
        this.validator = validator;
        this.loginAttemptService = loginAttemptService;
        this.totpService = totpService;
    }

    public T createUser(Long id, String password) {
        T user = createInstance(id, password);
        userRepository.save(user);
        return user;
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

        validatePassword(user.getPassword());

        String encodedPassword = passwordEncoder.encode(user.getPassword());
        user.setPassword(encodedPassword);
        System.out.println("User password: " + user.getPassword());

        if (userProperties.isTwoFactorAuthEnabled()) {
            setTwoFactorAuthKey(user);
        }
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
    }

    public T login(T userFromRequest, String totpOrRecoveryKey, HttpSession session, HttpServletRequest request) throws ApiException {
        T userInDB = userRepository.findById(userFromRequest.getId()).orElse(null);
        if (userInDB == null) {
            throw new UserException(401, "User not found");
        }

        S loginAttempt = null;
        if (userProperties.isIpLockingEnabled()) {
            String ipAddress = request.getRemoteAddr();
            loginAttempt = loginAttemptService.getLoginAttempt(ipAddress);
            if (loginAttempt == null) {
                loginAttempt = loginAttemptService.createInstance(ipAddress);
            }

            System.out.println("Failed attempts: " + loginAttempt.getFailedAttempts() + " Locked till: " + (loginAttempt.getLockTime()+userProperties.getIpLockTime())  + " Current time: " + System.currentTimeMillis() + " Difference: " + (System.currentTimeMillis() - loginAttempt.getLockTime()+userProperties.getIpLockTime() ));
            System.out.println((loginAttempt.getFailedAttempts() >= userProperties.getIpMaxAttempts()) + " " + (
                    System.currentTimeMillis() < userProperties.getIpLockTime() + loginAttempt.getLockTime()));
            if (loginAttempt.getFailedAttempts() >= userProperties.getIpMaxAttempts() &&
                    System.currentTimeMillis() < userProperties.getIpLockTime() + loginAttempt.getLockTime()) {
                throw new LoginAttemptException(403, "Logging from this ip has been locked, try again later");
            }
        }

        if (!passwordEncoder.matches(userFromRequest.getPassword(), userInDB.getPassword())) {
            if (loginAttempt != null) {
                incrementFailedAttempts(loginAttempt);
            }
            if (userProperties.isUserLockingEnabled()) {
                incrementFailedAttempts(userInDB);
            }
            throw new UserException(401, "Invalid password");
        }

        if (loginAttempt != null) {
            loginAttemptService.resetFailedAttempts(loginAttempt);
        }

        if (userProperties.isUserLockingEnabled() && userInDB.getFailedAttempts() >= userProperties.getUserMaxAttempts() &&
                System.currentTimeMillis() - userInDB.getLockTime() < userProperties.getUserLockTime()) {
            throw new UserException(403, "This user has been locked, try again later");
        }
        userInDB.resetFailedAttempts();
        userInDB.setLockTime(0);
        userRepository.save(userInDB);

        return userInDB;
    }

    private void incrementFailedAttempts(S loginAttempt) {
        loginAttempt.setFailedAttempts(loginAttempt.getFailedAttempts() + 1);
        if (loginAttempt.getFailedAttempts() >= userProperties.getIpMaxAttempts()) {
            loginAttempt.setLockTime(System.currentTimeMillis());
        }
        loginAttemptService.saveLoginAttempt(loginAttempt);
    }

    private void incrementFailedAttempts(T user) {
        user.incrementFailedAttempts();
        if (user.getFailedAttempts() >= userProperties.getUserMaxAttempts()) {
            user.setLockTime(System.currentTimeMillis());
        }
        userRepository.save(user);
    }

    public void setTwoFactorAuthKey(T user) {
        String secretKey = totpService.generateSecretKey();
        user.setTotpSecret(secretKey);
        userRepository.save(user);

    }

    public boolean verifyTwoFactorAuth(T user, String totp, HttpSession session) {
        return totpService.validateTotp(user.getTotpSecret(), totp, session);
    }

    protected abstract T createInstance(Long id, String password);




}
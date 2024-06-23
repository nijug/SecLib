package com.seclib.user.service;

import com.seclib.config.UserProperties;
import com.seclib.exception.*;
import com.seclib.loginAttempt.model.DefaultLoginAttempt;
import com.seclib.loginAttempt.service.DefaultLoginAttemptService;
import com.seclib.Totp.service.DefaultTotpService;
import com.seclib.passwordResetToken.model.DefaultPasswordResetToken;
import com.seclib.passwordResetToken.service.DefaultPasswordResetTokenService;
import com.seclib.user.model.DefaultUser;
import com.seclib.user.repository.DefaultUserRepository;
import jakarta.validation.Validator;
import org.springframework.stereotype.Service;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpServletRequest;
@Service
public class DefaultUserService extends BaseUserService<DefaultUser, DefaultUserRepository> {

    private final DefaultLoginAttemptService loginAttemptService;
    private final DefaultTotpService totpService;
    private final DefaultPasswordResetTokenService passwordResetTokenService;

    public DefaultUserService(UserProperties userProperties, DefaultUserRepository userRepository, Validator validator, DefaultLoginAttemptService loginAttemptService, DefaultTotpService totpService, DefaultPasswordResetTokenService passwordResetTokenService) {
        super(userProperties, userRepository, validator);
        this.loginAttemptService = loginAttemptService;
        this.totpService = totpService;
        this.passwordResetTokenService = passwordResetTokenService;
    }


    public DefaultUser register(String usernameFromRequest, String passwordFromRequest) throws ApiException, InterruptedException {
        return registerUser(usernameFromRequest, passwordFromRequest, null);
    }

    public DefaultUser register(String usernameFromRequest, String passwordFromRequest, String role) throws ApiException, InterruptedException {
        return registerUser(usernameFromRequest, passwordFromRequest, role);
    }

    private DefaultUser registerUser(String usernameFromRequest, String passwordFromRequest, String role) throws ApiException, InterruptedException {
        DefaultUser registeredUser = super.register(usernameFromRequest, passwordFromRequest);
        if (role != null) {
            registeredUser.setRole(role);
        }
        if (userProperties.isTwoFactorAuthEnabled()) {
            setTwoFactorAuthKey(registeredUser);
        }
        return registeredUser;
    }

    public DefaultUser login(String usernameFromRequest, String passwordFromRequest, String Totp, HttpSession session, HttpServletRequest request) throws ApiException, InterruptedException {

        DefaultLoginAttempt loginAttempt = null;
        if (userProperties.isIpLockingEnabled()) {
            String ipAddress = request.getRemoteAddr();
            loginAttempt = loginAttemptService.getLoginAttempt(ipAddress);
            if (loginAttempt == null) {
                loginAttempt = loginAttemptService.createInstance(ipAddress);
            }

            if (loginAttempt.getFailedAttempts() >= userProperties.getIpMaxAttempts() &&
                    System.currentTimeMillis() < userProperties.getIpLockTime() + loginAttempt.getLockTime()) {
                throw new LoginAttemptException(403, "Logging from this ip has been locked, try again later");
            }
        }

        DefaultUser userInDB = super.login(usernameFromRequest,passwordFromRequest );

        if (!passwordEncoder.matches(passwordFromRequest, userInDB.getPassword())) {
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

        if (userInDB.getTotpSecret() != null) {
            if (!totpService.validateTotp(userInDB.getTotpSecret(), Totp, session)) {
                throw new TotpException(401, "Invalid TOTP");
            }
        }

        userInDB.resetFailedAttempts();
        userInDB.setLockTime(0);
        userRepository.save(userInDB);

        return userInDB;
    }

    private void incrementFailedAttempts(DefaultUser user) {
        user.incrementFailedAttempts();
        if (user.getFailedAttempts() >= userProperties.getUserMaxAttempts()) {
            user.setLockTime(System.currentTimeMillis());
        }
        userRepository.save(user);
    }

    private void incrementFailedAttempts(DefaultLoginAttempt loginAttempt) {
        loginAttempt.setFailedAttempts(loginAttempt.getFailedAttempts() + 1);
        if (loginAttempt.getFailedAttempts() >= userProperties.getIpMaxAttempts()) {
            loginAttempt.setLockTime(System.currentTimeMillis());
        }
        loginAttemptService.saveLoginAttempt(loginAttempt);
    }

    private void setTwoFactorAuthKey(DefaultUser user) {
        String secretKey = totpService.generateSecretKey();
        user.setTotpSecret(secretKey);
        userRepository.save(user);
    }

    public String forgotPassword(String usernameFromRequest) throws PasswordResetException, InterruptedException{
        Thread.sleep(500);
        if (!userProperties.isPasswordResetEnabled()) {
            throw new PasswordResetException(403, "Password reset is disabled");
        }
        DefaultUser userInDB = userRepository.findByUsername(usernameFromRequest).orElse(null);
        if (userInDB == null) {
            throw new UserException(401, "User not found");
        }
        DefaultPasswordResetToken token = passwordResetTokenService.createPasswordResetToken(userInDB);
        return token.getToken();
    }

    public void resetPassword(String token, String newPassword) throws InterruptedException {
        Thread.sleep(500);
        DefaultPasswordResetToken resetToken = passwordResetTokenService.getPasswordResetToken(token);
        if (resetToken == null) {
            throw new PasswordResetException(403, "Invalid password reset token");
        }
        DefaultUser user = resetToken.getUser();


        validatePassword(newPassword);
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        passwordResetTokenService.deletePasswordResetToken(resetToken);
    }

    @Override
    protected DefaultUser createNewUser(String username, String password) {
        return new DefaultUser(username, password);
    }


}
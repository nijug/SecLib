package com.seclib.user.service;

import com.seclib.config.UserProperties;
import com.seclib.csrf.CsrfService;
import com.seclib.exception.*;
import com.seclib.loginAttempt.model.DefaultLoginAttempt;
import com.seclib.loginAttempt.service.DefaultLoginAttemptService;
import com.seclib.passwordResetToken.model.DefaultPasswordResetToken;
import com.seclib.passwordResetToken.service.DefaultPasswordResetTokenService;
import com.seclib.totp.DefaultTotpService;
import com.seclib.user.dto.DefaultUserDTO;
import com.seclib.user.mapper.DefaultUserMapper;
import com.seclib.user.model.DefaultUser;
import com.seclib.user.repository.DefaultUserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@Slf4j
public class DefaultUserService extends BaseUserService<DefaultUser, DefaultUserRepository, DefaultUserDTO> {

    private final DefaultLoginAttemptService loginAttemptService;
    private final DefaultTotpService totpService;
    private final DefaultPasswordResetTokenService passwordResetTokenService;
    private final CsrfService csrfService;
    @Setter
    private DefaultUserMapper userMapper;

    public DefaultUserService(UserProperties userProperties, DefaultUserRepository userRepository, Argon2PasswordEncoder passwordEncoder,
                              DefaultLoginAttemptService loginAttemptService,
                              DefaultTotpService totpService, DefaultPasswordResetTokenService passwordResetTokenService,
                              @Autowired(required = false) CsrfService csrfService, DefaultUserMapper userMapper) {
        super(userProperties, userRepository, passwordEncoder);
        this.loginAttemptService = loginAttemptService;
        this.totpService = totpService;
        this.passwordResetTokenService = passwordResetTokenService;
        this.csrfService = csrfService;
        this.userMapper = userMapper;
    }

    public DefaultUserDTO register(DefaultUserDTO userToRegister, Optional<String> role) throws ApiException, InterruptedException {
        DefaultUser registeredUser = super.register(userToRegister);
        role.ifPresent(registeredUser::setRole);
        registeredUser.setEmail(userToRegister.getEmail());
        if (userProperties.isTwoFactorAuthEnabled()) {
            setTwoFactorAuthKey(registeredUser);
        }
        userRepository.save(registeredUser);
        return userMapper.toDefaultUserDTO(registeredUser);
    }

    public DefaultUserDTO login(DefaultUserDTO userToLogin, HttpServletRequest request) throws ApiException {
        DefaultLoginAttempt loginAttempt = checkIpLocking(request);

        DefaultUser userInDB = authenticateUser(userToLogin, loginAttempt);
        checkUserLocking(userInDB);
        handleTwoFactorAuthentication(userInDB, userToLogin, request, loginAttempt);
        resetFailedAttempts(userInDB, loginAttempt);

        HttpSession newSession = createNewSessionWithAttributes(request, userInDB);
        return createUserDTOWithCsrfToken(userInDB, newSession);
    }

    private void resetFailedAttempts(DefaultUser user, DefaultLoginAttempt loginAttempt) {
        user.resetFailedAttempts();
        userRepository.save(user);

        if (loginAttempt != null) {
            loginAttempt.resetFailedAttempts();
            loginAttemptService.saveLoginAttempt(loginAttempt);
        }
    }


    private DefaultUser authenticateUser(DefaultUserDTO userToLogin, DefaultLoginAttempt loginAttempt) throws UserException {
        try {
            return super.login(userToLogin);
        } catch (UserException e) {
            handleFailedLoginAttempt(userToLogin.getUsername(), loginAttempt);
            throw e;
        }
    }

    private void handleFailedLoginAttempt(String username, DefaultLoginAttempt loginAttempt) {
        Optional<DefaultUser> userOpt = userRepository.findByUsername(username);
        userOpt.ifPresent(user -> {
            incrementFailedAttempts(user);
            userRepository.save(user);
        });

        if (loginAttempt != null) {
            incrementFailedAttempts(loginAttempt);
            loginAttemptService.saveLoginAttempt(loginAttempt);
        }
    }

    private DefaultLoginAttempt checkIpLocking(HttpServletRequest request) throws LoginAttemptException {
        if (!userProperties.isIpLockingEnabled()) return null;

        String ipAddress = request.getRemoteAddr();
        DefaultLoginAttempt loginAttempt = loginAttemptService.getLoginAttempt(ipAddress)
                .orElseGet(() -> loginAttemptService.createInstance(ipAddress));

        System.out.println("LOGIN ATTEMPTS FROM IP " + loginAttempt.getFailedAttempts());
        if (isIpLocked(loginAttempt)) {
            throw new LoginAttemptException(403, "Logging from this IP has been locked, try again later");
        }
        return loginAttempt;
    }

    private boolean isIpLocked(DefaultLoginAttempt loginAttempt) {
        long lockTimeElapsed = System.currentTimeMillis() - loginAttempt.getLockTime();
        return loginAttempt.getFailedAttempts() >= userProperties.getIpMaxAttempts() &&
                lockTimeElapsed < userProperties.getIpLockTime();
    }

    private void checkUserLocking(DefaultUser userInDB) throws UserException {
        if (!userProperties.isUserLockingEnabled()) return;

        System.out.println("LOGIN ATTEMPTS FROM USER " + userInDB.getFailedAttempts());

        long lockTimeElapsed = System.currentTimeMillis() - userInDB.getLockTime();
        if (userInDB.getFailedAttempts() >= userProperties.getUserMaxAttempts() &&
                lockTimeElapsed < userProperties.getUserLockTime()) {
            throw new UserException(403, "This user has been locked, try again later");
        }
    }

    private void handleTwoFactorAuthentication(DefaultUser userInDB, DefaultUserDTO userToLogin, HttpServletRequest request, DefaultLoginAttempt loginAttempt) throws TotpException {
        if (!userProperties.isTwoFactorAuthEnabled() || userInDB.getTotpSecret() == null) return;

        HttpSession oldSession = request.getSession(false);
        if (!totpService.validateTotp(userInDB.getTotpSecret(), userToLogin.getTotpSecret(), oldSession)) {
            handleFailedLoginAttempt(userToLogin.getUsername(), loginAttempt);
            throw new TotpException(401, "Invalid TOTP");
        }
    }

    private HttpSession createNewSessionWithAttributes(HttpServletRequest request, DefaultUser user) {
        HttpSession oldSession = request.getSession(false);
        if (oldSession != null) {
            oldSession.invalidate();
        }
        HttpSession newSession = request.getSession(true);
        newSession.setAttribute("userId", user.getId());
        return newSession;
    }

    private DefaultUserDTO createUserDTOWithCsrfToken(DefaultUser user, HttpSession session) {
        DefaultUserDTO userDTO = userMapper.toDefaultUserDTO(user);
        if (csrfService != null) {
            String csrfToken = csrfService.generateToken();
            csrfService.storeToken(session, csrfToken);
            userDTO.setCsrfToken(csrfToken);
        }
        userDTO.setSessionId(session.getId());
        return userDTO;
    }

    private void incrementFailedAttempts(DefaultUser user) {
        int maxAttempts = userProperties.getUserMaxAttempts();
        System.out.println("INCREMENTING USER FAILED ATTEMPTS");
        user.incrementFailedAttempts(maxAttempts);
        userRepository.save(user);
    }

    private void incrementFailedAttempts(DefaultLoginAttempt loginAttempt) {
        int maxAttempts = userProperties.getIpMaxAttempts();
        System.out.println("INCREMENTING LOGIN FAILED ATTEMPTS");
        loginAttempt.incrementFailedAttempts(maxAttempts);
        loginAttemptService.saveLoginAttempt(loginAttempt);
    }

    private void setTwoFactorAuthKey(DefaultUser user) {
        String secretKey = totpService.generateSecretKey();
        user.setTotpSecret(secretKey);
        userRepository.save(user);
    }

    public String forgotPassword(String usernameFromRequest) throws PasswordResetException {
        if (!userProperties.isPasswordResetEnabled()) {
            throw new PasswordResetException(403, "Password reset is disabled");
        }
        DefaultUser userInDB = userRepository.findByUsername(usernameFromRequest)
                .orElseThrow(() -> new ApiException(401, "User not found"));
        DefaultPasswordResetToken token = passwordResetTokenService.createPasswordResetToken(userInDB);
        return token.getToken();
    }

    public void resetPassword(String token, String newPassword) throws ApiException {
        DefaultPasswordResetToken resetToken = passwordResetTokenService.getPasswordResetToken(token)
                .orElseThrow(() -> new TwoFAuthException(403, "Invalid password reset token"));
        DefaultUser user = resetToken.getUser();
        validatePassword(newPassword);
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        passwordResetTokenService.deletePasswordResetToken(resetToken);
    }

    public void logout(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }

    }

    @Override
    protected DefaultUser createNewUser(String username, String password) {
        return new DefaultUser(username, password);
    }

}
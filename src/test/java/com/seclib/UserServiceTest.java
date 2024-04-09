package com.seclib;

import com.seclib.config.PasswordPolicy;
import com.seclib.config.UserProperties;
import com.seclib.loginAttempt.model.DefaultLoginAttempt;
import com.seclib.loginAttempt.service.DefaultLoginAttemptService;
import com.seclib.user.model.DefaultUser;
import com.seclib.user.repository.DefaultUserRepository;
import com.seclib.user.service.DefaultUserService;
import jakarta.validation.Validator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

public class UserServiceTest {

    @Mock
    private UserProperties userProperties;

    @Mock
    private DefaultUserRepository defaultUserRepository;

    @Mock
    private Validator validator;

    @InjectMocks
    private DefaultUserService userService;

    private DefaultUser testUser;

    @Mock
    private PasswordPolicy passwordPolicy;

    @Mock
    private DefaultLoginAttemptService loginAttemptService;

    private MockHttpServletRequest request;

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        userService.setValidator(validator);
        testUser = new DefaultUser(1L, "Password123!");

        when(userProperties.getPasswordPolicy()).thenReturn(passwordPolicy);
        when(passwordPolicy.getPattern()).thenReturn(".*[A-Z].*");
        when(loginAttemptService.getLoginAttempt(anyString())).thenReturn(null);
        when(loginAttemptService.createInstance(anyString())).thenReturn(new DefaultLoginAttempt("127.0.0.1"));

        request = new MockHttpServletRequest();
        request.setRemoteAddr("127.0.0.1");

        try {
            userService.register(testUser);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    @Test
    public void testLoginWithAccountLockingDisabledAndExistingUser() throws InterruptedException {
        when(userProperties.isIpLockingEnabled()).thenReturn(false);
        when(defaultUserRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));
        DefaultUser userForLogin = new DefaultUser(testUser.getId(), "Password123!");
        DefaultUser loggedInUser = userService.login(userForLogin, "totpOrRecoveryKey", new MockHttpSession(), request);
        assertEquals(testUser.getId(), loggedInUser.getId());
    }

    @Test
    public void testLoginWithAccountLockingDisabledAndNonExistingUser() throws InterruptedException {
        when(userProperties.isIpLockingEnabled()).thenReturn(false);
        when(defaultUserRepository.findById(2L)).thenReturn(Optional.empty());
        DefaultUser userForLogin = new DefaultUser(2L, "Password123!");
        assertThrows(IllegalArgumentException.class, () -> userService.login(userForLogin, "totpOrRecoveryKey", new MockHttpSession(), request));
    }
    @Test
    public void testLoginWithAccountLockingDisabledAndExistingUserWithWrongPassword() throws InterruptedException {
        when(userProperties.isIpLockingEnabled()).thenReturn(false);
        when(defaultUserRepository.findById(anyLong())).thenReturn(Optional.of(testUser));
        DefaultUser userForLogin = new DefaultUser(testUser.getId(), "WrongPassword!");
        assertThrows(IllegalArgumentException.class, () -> userService.login(userForLogin, "totpOrRecoveryKey", new MockHttpSession(), request));
    }

    @Test
    public void testLoginWithIpLockingEnabledAndCorrectPassword() throws InterruptedException {
        when(userProperties.isIpLockingEnabled()).thenReturn(true);
        when(defaultUserRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));
        DefaultUser userForLogin = new DefaultUser(testUser.getId(), "Password123!");
        DefaultUser loggedInUser = userService.login(userForLogin, "totpOrRecoveryKey", new MockHttpSession(), request);
        assertEquals(testUser.getId(), loggedInUser.getId());
    }

    @Test
    public void testLoginWithIpLockingEnabledAndIncorrectPassword() throws InterruptedException {
        when(userProperties.isIpLockingEnabled()).thenReturn(true);
        when(defaultUserRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));
        DefaultUser userForLogin = new DefaultUser(testUser.getId(), "WrongPassword!");
        assertThrows(IllegalArgumentException.class, () -> userService.login(userForLogin, "totpOrRecoveryKey", new MockHttpSession(), request));
    }

    @Test
    public void testLoginWithIpLockingEnabledAndCorrectPasswordButBlockedIp() throws InterruptedException {
        when(userProperties.isIpLockingEnabled()).thenReturn(true);
        when(defaultUserRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));
        when(userProperties.getLockTime()).thenReturn(6000L); // Set lockTime to 5 seconds
        when(userProperties.getMaxAttempts()).thenReturn(3);
        when(loginAttemptService.getLoginAttempt("127.0.0.1")).thenReturn(new DefaultLoginAttempt("127.0.0.1", 3, System.currentTimeMillis() - 3000 ));
        DefaultUser userForLogin = new DefaultUser(testUser.getId(), "Password123!");
        assertThrows(IllegalArgumentException.class, () -> userService.login(userForLogin, "totpOrRecoveryKey", new MockHttpSession(), request));
    }
    @Test
    public void testLoginWithIpLockingEnabledAndIncorrectPasswordAndBlockedIp() throws InterruptedException {
        when(userProperties.isIpLockingEnabled()).thenReturn(true);
        when(defaultUserRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));
        when(loginAttemptService.getLoginAttempt("127.0.0.1")).thenReturn(new DefaultLoginAttempt("127.0.0.1", 3, System.currentTimeMillis() - 3000 ));
        DefaultUser userForLogin = new DefaultUser(testUser.getId(), "WrongPassword!");
        assertThrows(IllegalArgumentException.class, () -> userService.login(userForLogin, "totpOrRecoveryKey", new MockHttpSession(), request));
    }

    @Test
    public void testLoginWithIpLockingEnabledAndExceedingMaxAttempts() throws InterruptedException {
        when(userProperties.isIpLockingEnabled()).thenReturn(true);
        when(userProperties.getMaxAttempts()).thenReturn(2);
        when(defaultUserRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));
        DefaultUser userForLogin = new DefaultUser(testUser.getId(), "WrongPassword!");

        assertThrows(IllegalArgumentException.class, () -> userService.login(userForLogin, "totpOrRecoveryKey", new MockHttpSession(), request));

        assertThrows(IllegalArgumentException.class, () -> userService.login(userForLogin, "totpOrRecoveryKey", new MockHttpSession(), request));

        assertThrows(IllegalArgumentException.class, () -> userService.login(userForLogin, "totpOrRecoveryKey", new MockHttpSession(), request));
    }

    @Test
    public void testLoginWithIpLockingEnabledAndNonExistingUser() throws InterruptedException {
        when(userProperties.isIpLockingEnabled()).thenReturn(true);
        when(defaultUserRepository.findById(2L)).thenReturn(Optional.empty());
        DefaultUser userForLogin = new DefaultUser(2L, "Password123!");
        assertThrows(IllegalArgumentException.class, () -> userService.login(userForLogin, "totpOrRecoveryKey", new MockHttpSession(), request));
    }

    @Test
    public void testLoginWithIpLockingDisabledAndBlockedIp() throws InterruptedException {
        when(userProperties.isIpLockingEnabled()).thenReturn(false);
        when(defaultUserRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));
        when(loginAttemptService.getLoginAttempt("127.0.0.1")).thenReturn(new DefaultLoginAttempt("127.0.0.1", 3, System.currentTimeMillis() - 3000 ));
        DefaultUser userForLogin = new DefaultUser(testUser.getId(), "Password123!");
        DefaultUser loggedInUser = userService.login(userForLogin, "totpOrRecoveryKey", new MockHttpSession(), request);
        assertEquals(testUser.getId(), loggedInUser.getId());
    }

    @Test
    public void testLoginWithIpLockingEnabledCorrectPasswordExceedingMaxAttempts() throws InterruptedException {
        when(userProperties.isIpLockingEnabled()).thenReturn(true);
        when(defaultUserRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));
        when(userProperties.getLockTime()).thenReturn(5000L);
        when(userProperties.getMaxAttempts()).thenReturn(3);
        when(loginAttemptService.getLoginAttempt("127.0.0.1")).thenReturn(new DefaultLoginAttempt("127.0.0.1", 5, System.currentTimeMillis() - 3000));
        DefaultUser userForLogin = new DefaultUser(testUser.getId(), "Password123!");
        assertThrows(IllegalArgumentException.class, () -> userService.login(userForLogin, "totpOrRecoveryKey", new MockHttpSession(), request));
    }

    @Test
    public void testLoginWithIpLockingEnabledIncorrectPasswordExceedingMaxAttempts() throws InterruptedException {
        when(userProperties.isIpLockingEnabled()).thenReturn(true);
        when(defaultUserRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));
        when(userProperties.getMaxAttempts()).thenReturn(3);
        when(loginAttemptService.getLoginAttempt("127.0.0.1")).thenReturn(new DefaultLoginAttempt("127.0.0.1", 5, System.currentTimeMillis() - 3000));
        DefaultUser userForLogin = new DefaultUser(testUser.getId(), "WrongPassword!");
        assertThrows(IllegalArgumentException.class, () -> userService.login(userForLogin, "totpOrRecoveryKey", new MockHttpSession(), request));
    }

    @Test
    public void testLoginWithIpLockingEnabledCorrectPasswordJustBlocked() throws InterruptedException {
        when(userProperties.isIpLockingEnabled()).thenReturn(true);
        when(defaultUserRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));
        when(userProperties.getLockTime()).thenReturn(5000L); // Set lockTime to 5 seconds
        when(userProperties.getMaxAttempts()).thenReturn(3);
        when(loginAttemptService.getLoginAttempt("127.0.0.1")).thenReturn(new DefaultLoginAttempt("127.0.0.1", 3, System.currentTimeMillis()));
        DefaultUser userForLogin = new DefaultUser(testUser.getId(), "Password123!");
        assertThrows(IllegalArgumentException.class, () -> userService.login(userForLogin, "totpOrRecoveryKey", new MockHttpSession(), request));
    }

    @Test
    public void testLoginWithIpLockingEnabledIncorrectPasswordJustBlocked() throws InterruptedException {
        when(userProperties.isIpLockingEnabled()).thenReturn(true);
        when(defaultUserRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));
        when(userProperties.getMaxAttempts()).thenReturn(3);
        when(loginAttemptService.getLoginAttempt("127.0.0.1")).thenReturn(new DefaultLoginAttempt("127.0.0.1", 3, System.currentTimeMillis()));
        DefaultUser userForLogin = new DefaultUser(testUser.getId(), "WrongPassword!");
        assertThrows(IllegalArgumentException.class, () -> userService.login(userForLogin, "totpOrRecoveryKey", new MockHttpSession(), request));
    }
}